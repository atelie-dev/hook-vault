package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/atelie-dev/hook-vault/internal/vault"
)

// fetch pulls events from the read API and, given the secret key, decrypts
// them on the way out. It is the CLI shape of the whole contract:
//
//	token  → authenticates the read (derived from the key when omitted)
//	key    → opens the sealed box (the server never has it)
//
// Nothing here is privileged: the same two credentials a consumer needs.
type fetchOptions struct {
	baseURL         string
	token           string
	key             *vault.Key
	cursor          string
	cursorFile      string
	limit           int
	includeRejected bool
	asJSON          bool
	out             io.Writer
	errOut          io.Writer
}

type remoteEvent struct {
	ID         string          `json:"id"`
	ReceivedAt time.Time       `json:"received_at"`
	KID        string          `json:"kid"`
	Alg        string          `json:"alg"`
	CT         string          `json:"ct"`
	Size       int             `json:"size"`
	Status     string          `json:"status"`
	Meta       json.RawMessage `json:"meta"`
}

type remotePage struct {
	Events       []remoteEvent `json:"events"`
	NextCursor   *string       `json:"next_cursor"`
	HasMore      bool          `json:"has_more"`
	OldestCursor *string       `json:"oldest_cursor"`
	LagSeconds   float64       `json:"lag_seconds"`
}

func runFetch(args []string) error {
	fs := flag.NewFlagSet("hook-vault fetch", flag.ContinueOnError)
	var (
		baseURL       = fs.String("url", envOr("HOOKVAULT_URL", ""), "base URL of the ingest listener (env HOOKVAULT_URL)")
		tokenFile     = fs.String("token-file", envOr("HOOKVAULT_TOKEN_FILE", ""), "file with the read API bearer token")
		tokenInline   = fs.String("token", "", "read API bearer token inline (prefer --token-file)")
		keyFile       = fs.String("key-file", envOr("HOOKVAULT_KEY_FILE", ""), "file with the 32-byte secret key (base64)")
		keyInline     = fs.String("key", "", "secret key inline (prefer --key-file)")
		cursor        = fs.String("cursor", "", "start after this event id")
		cursorFile    = fs.String("cursor-file", "", "read and update a cursor file, so repeated runs resume")
		limit         = fs.Int("limit", 100, "page size (1–1000)")
		includeReject = fs.Bool("include-rejected", false, "also return events that failed signature verification")
		asJSON        = fs.Bool("json", false, "one JSON object per line")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}

	opts := &fetchOptions{
		baseURL:         strings.TrimRight(*baseURL, "/"),
		cursor:          *cursor,
		cursorFile:      *cursorFile,
		limit:           *limit,
		includeRejected: *includeReject,
		asJSON:          *asJSON,
		out:             os.Stdout,
		errOut:          os.Stderr,
	}

	if opts.baseURL == "" {
		return errors.New("--url is required (or HOOKVAULT_URL)")
	}
	if *cursor != "" && *cursorFile != "" {
		return errors.New("--cursor and --cursor-file are mutually exclusive")
	}

	switch {
	case *keyFile != "":
		raw, err := os.ReadFile(*keyFile)
		if err != nil {
			return fmt.Errorf("read key file: %w", err)
		}
		secret, err := decodeSecret(string(raw))
		if err != nil {
			return err
		}
		if opts.key, err = vault.FromSecret(secret); err != nil {
			return err
		}
	case *keyInline != "":
		secret, err := decodeSecret(*keyInline)
		if err != nil {
			return err
		}
		if opts.key, err = vault.FromSecret(secret); err != nil {
			return err
		}
	}

	switch {
	case *tokenFile != "":
		raw, err := os.ReadFile(*tokenFile)
		if err != nil {
			return fmt.Errorf("read token file: %w", err)
		}
		opts.token = strings.TrimSpace(string(raw))
	case *tokenInline != "":
		opts.token = strings.TrimSpace(*tokenInline)
	}

	// The token derives from the key: one file is enough to authenticate and
	// decrypt.
	if opts.token == "" {
		if opts.key == nil {
			return errors.New("a credential is required: --key-file (derives the token) or --token-file")
		}
		opts.token = opts.key.Token
	}

	if opts.cursorFile != "" {
		raw, err := os.ReadFile(opts.cursorFile)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("read cursor file: %w", err)
		}
		opts.cursor = strings.TrimSpace(string(raw))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	page, err := fetchPage(ctx, http.DefaultClient, opts)
	if err != nil {
		return err
	}

	emitted := 0
	for _, event := range page.Events {
		if err := emit(opts, event); err != nil {
			return err
		}
		emitted++
	}

	if emitted > 0 && page.NextCursor != nil && opts.cursorFile != "" {
		if err := os.WriteFile(opts.cursorFile, []byte(*page.NextCursor+"\n"), 0o600); err != nil {
			return fmt.Errorf("write cursor file: %w", err)
		}
	}

	// Machine-readable summary on stderr keeps stdout clean for payloads.
	if page.NextCursor != nil {
		fmt.Fprintf(opts.errOut, "next_cursor=%s has_more=%t events=%d\n", *page.NextCursor, page.HasMore, emitted)
	} else {
		fmt.Fprintf(opts.errOut, "events=%d\n", emitted)
	}
	if page.OldestCursor != nil && emitted == 0 {
		fmt.Fprintf(opts.errOut, "oldest_cursor=%s (nothing newer is stored)\n", *page.OldestCursor)
	}
	return nil
}

func fetchPage(ctx context.Context, client *http.Client, opts *fetchOptions) (*remotePage, error) {
	query := url.Values{}
	query.Set("limit", fmt.Sprint(opts.limit))
	if opts.cursor != "" {
		query.Set("cursor", opts.cursor)
	}
	if opts.includeRejected {
		query.Set("include_rejected", "true")
	}

	endpoint := opts.baseURL + "/v1/events?" + query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+opts.token)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch events: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, errors.New("the read API rejected the token (401): pass the token that belongs to this endpoint, or the secret key that derives it")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("read API returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var page remotePage
	if err := json.Unmarshal(body, &page); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &page, nil
}

// emit writes one event: decrypted when the key matches the event's kid,
// otherwise the ciphertext with a note (a key from another rotation).
func emit(opts *fetchOptions, event remoteEvent) error {
	payload, decrypted, reason := decodeEvent(opts.key, event)

	if opts.asJSON {
		out := map[string]any{
			"id":          event.ID,
			"received_at": event.ReceivedAt,
			"kid":         event.KID,
			"status":      event.Status,
			"meta":        event.Meta,
		}
		if decrypted {
			out["payload"] = string(payload)
		} else {
			out["ct"] = event.CT
			out["decrypted"] = false
			out["reason"] = reason
		}
		encoded, err := json.Marshal(out)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(opts.out, string(encoded))
		return err
	}

	w := bufio.NewWriter(opts.out)
	fmt.Fprintf(w, "--- %s  %s  kid=%s  status=%s\n", event.ID, event.ReceivedAt.UTC().Format(time.RFC3339), event.KID, event.Status)
	if len(event.Meta) > 2 {
		fmt.Fprintf(w, "    meta: %s\n", strings.ReplaceAll(string(event.Meta), "\n", " "))
	}
	if decrypted {
		w.Write(payload)
		if !strings.HasSuffix(string(payload), "\n") {
			w.WriteString("\n")
		}
	} else {
		fmt.Fprintf(w, "    [not decrypted: %s]\n    ct: %s\n", reason, event.CT)
	}
	return w.Flush()
}

// decodeEvent opens the sealed box when the key is the one that sealed it.
func decodeEvent(key *vault.Key, event remoteEvent) (payload []byte, ok bool, reason string) {
	if key == nil {
		return nil, false, "no --key-file given; the payload stays sealed"
	}
	if event.KID != "" && event.KID != key.KID {
		return nil, false, fmt.Sprintf("event was sealed for kid %s, this key is %s", event.KID, key.KID)
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(event.CT)
	if err != nil {
		return nil, false, "ciphertext is not base64url: " + err.Error()
	}
	plaintext, err := vault.Open(ciphertext, &key.Public, &key.Secret)
	if err != nil {
		return nil, false, "cannot open: " + err.Error()
	}
	return plaintext, true, ""
}

func envOr(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok && value != "" {
		return value
	}
	return fallback
}
