// Command hook-vault collects provider webhooks, seals them with a key it does
// not hold, and serves them back as an encrypted, cursor-paginated log.
package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/atelie-dev/hook-vault/internal/config"
	"github.com/atelie-dev/hook-vault/internal/httpapi"
	"github.com/atelie-dev/hook-vault/internal/retention"
	"github.com/atelie-dev/hook-vault/internal/store"
	"github.com/atelie-dev/hook-vault/internal/vault"
)

// version is overridden at build time with -ldflags "-X main.version=…".
var version = "0.5.0-dev"

const usage = `hook-vault — encrypted webhook inbox

Usage:
  hook-vault serve      run the ingest and control-plane listeners
  hook-vault migrate    apply schema migrations and exit
  hook-vault keygen     create a recipient key pair and its API token
  hook-vault fetch      read events (decrypting them when given the key)
  hook-vault open       decrypt a payload with its secret key
  hook-vault version    print the version
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "serve":
		err = runServe(os.Args[2:])
	case "migrate":
		err = runMigrate(os.Args[2:])
	case "keygen":
		err = runKeygen(os.Args[2:])
	case "fetch":
		err = runFetch(os.Args[2:])
	case "open":
		err = runOpen(os.Args[2:])
	case "version":
		fmt.Println(version)
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "hook-vault: %v\n", err)
		os.Exit(1)
	}
}

func runServe(args []string) error {
	cfg, err := config.Load(args)
	if err != nil {
		return err
	}

	logger := newLogger(cfg.LogLevel)
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer st.Close()

	if err := st.RequirePostgres18(ctx); err != nil {
		return err
	}
	if err := st.Migrate(ctx); err != nil {
		return err
	}

	api := httpapi.New(httpapi.Options{
		Store:        st,
		PublicURL:    cfg.PublicURL,
		MaxBodyBytes: cfg.MaxBodyBytes,
		ReadLag:      cfg.ReadLag,
		AdminToken:   cfg.AdminToken,
		Logger:       logger,
		Version:      version,
	})

	sweeper := retention.New(st, logger)
	go sweeper.Run(ctx, cfg.ReaperInterval)

	dataPlane := newHTTPServer(cfg.IngestAddr, api.DataPlane(), logger)
	controlPlane := newHTTPServer(cfg.AdminAddr, api.ControlPlane(), logger)

	logger.Info("hook-vault starting",
		"version", version,
		"ingest_addr", cfg.IngestAddr,
		"admin_addr", cfg.AdminAddr,
		"public_url", cfg.PublicURL,
		"read_lag", cfg.ReadLag.String(),
		"max_body_bytes", cfg.MaxBodyBytes,
	)

	errs := make(chan error, 2)

	go func() { errs <- serve(dataPlane, "ingest", logger) }()
	go func() { errs <- serve(controlPlane, "control-plane", logger) }()

	select {
	case <-ctx.Done():
		logger.Info("shutdown requested")
	case err := <-errs:
		if err != nil {
			stop()
			_ = shutdown(dataPlane, cfg.ShutdownTimeout, logger)
			_ = shutdown(controlPlane, cfg.ShutdownTimeout, logger)
			return err
		}
	}

	shutdownErr := shutdown(dataPlane, cfg.ShutdownTimeout, logger)
	if err := shutdown(controlPlane, cfg.ShutdownTimeout, logger); err != nil {
		shutdownErr = err
	}
	return shutdownErr
}

func newHTTPServer(addr string, handler http.Handler, logger *slog.Logger) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
}

func serve(srv *http.Server, name string, logger *slog.Logger) error {
	listener, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return fmt.Errorf("%s listener: %w", name, err)
	}
	logger.Info("listening", "listener", name, "addr", listener.Addr().String())

	if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("%s listener: %w", name, err)
	}
	return nil
}

func shutdown(srv *http.Server, timeout time.Duration, logger *slog.Logger) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("shutdown", "addr", srv.Addr, "error", err)
		return err
	}
	return nil
}

func runMigrate(args []string) error {
	cfg, err := config.Load(args)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	st, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer st.Close()

	if err := st.RequirePostgres18(ctx); err != nil {
		return err
	}
	if err := st.Migrate(ctx); err != nil {
		return err
	}
	fmt.Println("migrations applied")
	return nil
}

func runKeygen(args []string) error {
	fs := flag.NewFlagSet("hook-vault keygen", flag.ContinueOnError)
	secretFlag := fs.String("secret", "", "derive from an existing secret key (base64) instead of generating one")
	asJSON := fs.Bool("json", false, "print machine-readable JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var key *vault.Key
	var err error
	if *secretFlag != "" {
		raw, decodeErr := decodeSecret(*secretFlag)
		if decodeErr != nil {
			return decodeErr
		}
		key, err = vault.FromSecret(raw)
	} else {
		key, err = vault.Generate()
	}
	if err != nil {
		return err
	}

	tokenHash := vault.HashToken(key.Token)

	if *asJSON {
		out := map[string]string{
			"secret_key":   vault.EncodeSecret(key.Secret[:]),
			"public_key":   vault.EncodePublic(key.Public[:]),
			"kid":          key.KID,
			"token":        key.Token,
			"token_sha256": hex.EncodeToString(tokenHash),
		}
		encoded, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(encoded))
		return nil
	}

	fmt.Printf("secret_key:   %s\n", vault.EncodeSecret(key.Secret[:]))
	fmt.Printf("public_key:   %s\n", vault.EncodePublic(key.Public[:]))
	fmt.Printf("kid:          %s\n", key.KID)
	fmt.Printf("token:        %s\n", key.Token)
	fmt.Printf("token_sha256: %s\n", hex.EncodeToString(tokenHash))
	fmt.Print(`
Keep secret_key offline, together with the archive you may need to read: it is
the only thing that can open stored payloads, and it cannot be recovered.
Registration needs public_key and token_sha256 only — neither reveals the key.
The token is derived from the secret, so it can be recomputed with:
  hook-vault keygen --secret <secret_key>
`)
	return nil
}

func runOpen(args []string) error {
	fs := flag.NewFlagSet("hook-vault open", flag.ContinueOnError)
	secretFlag := fs.String("secret", "", "secret key (base64); taken from HOOK_VAULT_SECRET when empty")
	cipherFlag := fs.String("ct", "", "ciphertext as base64url, as returned by the API")
	inputFlag := fs.String("in", "", "file with raw ciphertext; reads stdin when empty")
	if err := fs.Parse(args); err != nil {
		return err
	}

	rawSecret := *secretFlag
	if rawSecret == "" {
		rawSecret = os.Getenv("HOOK_VAULT_SECRET")
	}
	if rawSecret == "" {
		return errors.New("a secret key is required: pass -secret or set HOOK_VAULT_SECRET")
	}
	secret, err := decodeSecret(rawSecret)
	if err != nil {
		return err
	}
	key, err := vault.FromSecret(secret)
	if err != nil {
		return err
	}

	var ciphertext []byte
	switch {
	case *cipherFlag != "":
		ciphertext, err = decodeCiphertext(*cipherFlag)
		if err != nil {
			return err
		}
	case *inputFlag != "":
		raw, err := os.ReadFile(*inputFlag)
		if err != nil {
			return fmt.Errorf("read %s: %w", *inputFlag, err)
		}
		ciphertext, err = readCiphertext(raw)
		if err != nil {
			return err
		}
	default:
		raw, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("read stdin: %w", err)
		}
		ciphertext, err = readCiphertext(raw)
		if err != nil {
			return err
		}
	}
	if len(ciphertext) == 0 {
		return errors.New("no ciphertext given: pass -ct, -in or pipe it on stdin")
	}

	plaintext, err := vault.Open(ciphertext, &key.Public, &key.Secret)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(plaintext)
	return err
}

func decodeSecret(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding,
	} {
		if raw, err := enc.DecodeString(value); err == nil && len(raw) == vault.SecretKeySize {
			return raw, nil
		}
	}
	return nil, fmt.Errorf("secret key must be %d bytes encoded as base64", vault.SecretKeySize)
}

func decodeCiphertext(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding,
	} {
		if raw, err := enc.DecodeString(value); err == nil && len(raw) > vault.AnonymousOverhead {
			return raw, nil
		}
	}
	return nil, errors.New("ciphertext must be base64 and longer than a sealed box header")
}

// readCiphertext accepts either raw bytes or the base64 text the API returns.
//
// Piping base64 into a decoder is what everyone tries first, and line-wrapped
// base64 (from the base64 command) is the second thing they try, so both work.
func readCiphertext(raw []byte) ([]byte, error) {
	if decoded, ok := base64Text(raw); ok {
		return decoded, nil
	}
	if len(raw) > vault.AnonymousOverhead {
		return raw, nil
	}
	return nil, errors.New("ciphertext is too short to be a sealed box")
}

func base64Text(raw []byte) ([]byte, bool) {
	clean := make([]byte, 0, len(raw))
	for _, b := range raw {
		switch b {
		case ' ', '\t', '\r', '\n':
			continue
		default:
			clean = append(clean, b)
		}
	}
	if len(clean) == 0 {
		return nil, false
	}
	for _, b := range clean {
		if b < 0x20 || b > 0x7e {
			return nil, false // binary, not encoded text
		}
	}
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding,
	} {
		if decoded, err := enc.DecodeString(string(clean)); err == nil && len(decoded) > vault.AnonymousOverhead {
			return decoded, true
		}
	}
	return nil, false
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))
}
