package main

import (
	"bufio"
	"bytes"
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
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/atelie-dev/hook-vault/internal/vault"
)

// fetch pulls events from the read API and, given the secret key, decrypts
// them on the way out. It is the CLI shape of the whole contract:
//
//	token  → authenticates the read (derived from the key when omitted)
//	key    → opens the sealed box (the server never has it)
//
// Output is either for a person (--format human: colours, aligned, payload
// pretty-printed) or for a pipeline (--format jsonl: one stable object per
// line). --watch keeps paging and emits as events arrive.
type fetchOptions struct {
	baseURL         string
	token           string
	key             *vault.Key
	cursor          string
	cursorFile      string
	limit           int
	includeRejected bool
	watch           bool
	interval        time.Duration
	rawPayload      bool
	format          string // human | jsonl
	color           bool
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

// jsonEvent is the jsonl schema. It is stable on purpose: `decrypted` is always
// present, and payload is a string (the consumer parses it however it wants).
type jsonEvent struct {
	ID         string          `json:"id"`
	ReceivedAt time.Time       `json:"received_at"`
	KID        string          `json:"kid,omitempty"`
	Status     string          `json:"status"`
	Meta       json.RawMessage `json:"meta,omitempty"`
	Decrypted  bool            `json:"decrypted"`
	// Payload is embedded as JSON when the content-type says so and the body
	// parses; otherwise it is a JSON string. --raw-payload forces the string.
	Payload    json.RawMessage `json:"payload,omitempty"`
	Ciphertext *string         `json:"ct,omitempty"`
	Reason     *string         `json:"reason,omitempty"`
}

var errUnauthorized = errors.New("the read API rejected the token (401): pass the token that belongs to this endpoint, or the secret key that derives it")

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
		format        = fs.String("format", "auto", "output: auto (human on a terminal, jsonl otherwise), human, jsonl")
		watch         = fs.Bool("watch", false, "keep paging and emit events as they arrive")
		interval      = fs.Duration("interval", 5*time.Second, "poll interval when --watch has nothing new")
		rawPayload    = fs.Bool("raw-payload", false, "never interpret the payload, even when the content-type is JSON")
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
		watch:           *watch,
		interval:        *interval,
		rawPayload:      *rawPayload,
		out:             os.Stdout,
		errOut:          os.Stderr,
	}

	if opts.baseURL == "" {
		return errors.New("--url is required (or HOOKVAULT_URL)")
	}
	if *cursor != "" && *cursorFile != "" {
		return errors.New("--cursor and --cursor-file are mutually exclusive")
	}
	if opts.limit < 1 || opts.limit > 1000 {
		return errors.New("--limit must be between 1 and 1000")
	}
	if opts.interval <= 0 {
		return errors.New("--interval must be positive")
	}

	// Output format: a person at a terminal gets colours, a pipe gets jsonl.
	isTTY := stdoutIsTerminal()
	switch *format {
	case "auto":
		if isTTY {
			opts.format = "human"
		} else {
			opts.format = "jsonl"
		}
	case "human", "jsonl":
		opts.format = *format
	default:
		return fmt.Errorf("--format must be auto, human or jsonl (got %q)", *format)
	}
	opts.color = opts.format == "human" && isTTY && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb"

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
		warnLoosePermissions(*keyFile, opts.errOut)
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	client := &http.Client{Timeout: 60 * time.Second}

	if !opts.watch {
		return runOnce(ctx, client, opts)
	}

	// Watching without a starting point should attach at the tail, not replay
	// the whole retention window.
	if opts.cursor == "" {
		if newest, err := fetchNewest(ctx, client, opts); err == nil && newest != nil {
			opts.cursor = *newest
		}
	}
	return watchLoop(ctx, client, opts)
}

func runOnce(ctx context.Context, client *http.Client, opts *fetchOptions) error {
	page, err := fetchPage(ctx, client, opts)
	if err != nil {
		return err
	}
	count, err := emitAll(opts, page)
	if err != nil {
		return err
	}
	if err := persistCursor(opts, page); err != nil {
		return err
	}
	if page.NextCursor != nil {
		fmt.Fprintf(opts.errOut, "next_cursor=%s has_more=%t events=%d\n", *page.NextCursor, page.HasMore, count)
	} else {
		fmt.Fprintf(opts.errOut, "events=%d\n", count)
	}
	if page.OldestCursor != nil && count == 0 {
		fmt.Fprintf(opts.errOut, "oldest_cursor=%s (nothing newer is stored)\n", *page.OldestCursor)
	}
	return nil
}

// watchLoop pages forever, sleeping only when there is nothing new. A broken
// credential ends it; a network blip does not.
func watchLoop(ctx context.Context, client *http.Client, opts *fetchOptions) error {
	for ctx.Err() == nil {
		page, err := fetchPage(ctx, client, opts)
		if err != nil {
			if errors.Is(err, errUnauthorized) || ctx.Err() != nil {
				return err
			}
			fmt.Fprintf(opts.errOut, "error: %v (retrying in %s)\n", err, opts.interval)
			if !sleepContext(ctx, opts.interval) {
				return nil
			}
			continue
		}

		if _, err := emitAll(opts, page); err != nil {
			return err
		}
		if err := persistCursor(opts, page); err != nil {
			return err
		}

		if !page.HasMore && !sleepContext(ctx, opts.interval) {
			return nil
		}
	}
	return nil
}

func emitAll(opts *fetchOptions, page *remotePage) (int, error) {
	count := 0
	for _, event := range page.Events {
		if err := emit(opts, event); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

// persistCursor always advances the in-memory cursor (otherwise --watch would
// re-emit the same page forever) and mirrors it to the file when asked.
func persistCursor(opts *fetchOptions, page *remotePage) error {
	if page.NextCursor == nil || len(page.Events) == 0 {
		return nil
	}
	opts.cursor = *page.NextCursor
	if opts.cursorFile == "" {
		return nil
	}
	if err := os.WriteFile(opts.cursorFile, []byte(*page.NextCursor+"\n"), 0o600); err != nil {
		return fmt.Errorf("write cursor file: %w", err)
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

	var page remotePage
	if err := getJSON(ctx, client, opts, "/v1/events?"+query.Encode(), &page); err != nil {
		return nil, err
	}
	return &page, nil
}

// fetchNewest asks the API for the tail of the log.
func fetchNewest(ctx context.Context, client *http.Client, opts *fetchOptions) (*string, error) {
	var me struct {
		Cursor struct {
			Newest *string `json:"newest"`
		} `json:"cursor"`
	}
	if err := getJSON(ctx, client, opts, "/v1/me", &me); err != nil {
		return nil, err
	}
	return me.Cursor.Newest, nil
}

func getJSON(ctx context.Context, client *http.Client, opts *fetchOptions, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, opts.baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+opts.token)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request %s: %w", path, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return errUnauthorized
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("read API returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

// emit writes one event in the selected format.
func emit(opts *fetchOptions, event remoteEvent) error {
	payload, decrypted, reason := decodeEvent(opts.key, event)

	if opts.format == "jsonl" {
		line := jsonEvent{
			ID:         event.ID,
			ReceivedAt: event.ReceivedAt,
			KID:        event.KID,
			Status:     event.Status,
			Meta:       event.Meta,
			Decrypted:  decrypted,
		}
		if decrypted {
			line.Payload = payloadForJSON(opts, event, payload)
		} else {
			line.Ciphertext = &event.CT
			line.Reason = &reason
		}
		encoded, err := json.Marshal(line)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(opts.out, string(encoded))
		return err
	}

	return emitHuman(opts, event, payload, decrypted, reason)
}

func emitHuman(opts *fetchOptions, event remoteEvent, payload []byte, decrypted bool, reason string) error {
	w := bufio.NewWriter(opts.out)

	statusColor := "\x1b[32m" // green
	if event.Status != "stored" {
		statusColor = "\x1b[31m" // red
	}
	fmt.Fprintf(w, "%s%s  %s  %s\n",
		paint(opts, "\x1b[36m", "▌"),
		paint(opts, "\x1b[1m", event.ID),
		paint(opts, "\x1b[2m", event.ReceivedAt.Local().Format("2006-01-02 15:04:05")),
		paint(opts, statusColor, event.Status),
	)
	if len(event.Meta) > 2 && string(event.Meta) != "{}" {
		fmt.Fprintf(w, "  %s %s\n", paint(opts, "\x1b[2m", "meta"), string(event.Meta))
	}
	if event.KID != "" {
		fmt.Fprintf(w, "  %s  %s\n", paint(opts, "\x1b[2m", "kid "), paint(opts, "\x1b[36m", event.KID))
	}

	switch {
	case decrypted && interpretPayload(opts, event, payload):
		pretty := &bytes.Buffer{}
		if err := json.Indent(pretty, payload, "  ", "  "); err == nil {
			// json.Indent only prefixes continuation lines; align the opening
			// brace with the closing one.
			w.WriteString("  ")
			w.Write(pretty.Bytes())
			w.WriteString("\n")
		} else {
			writeIndented(w, payload)
		}
	case decrypted:
		writeIndented(w, payload)
	default:
		fmt.Fprintf(w, "  %s\n", paint(opts, "\x1b[33m", "sealed: "+reason))
		fmt.Fprintf(w, "  %s %s\n", paint(opts, "\x1b[2m", "ct "), event.CT)
	}
	w.WriteString("\n")
	return w.Flush()
}

func writeIndented(w io.Writer, payload []byte) {
	for _, line := range strings.Split(strings.TrimRight(string(payload), "\n"), "\n") {
		fmt.Fprintf(w, "  %s\n", line)
	}
}

func paint(opts *fetchOptions, code, text string) string {
	if !opts.color {
		return text
	}
	return code + text + "\x1b[0m"
}

// interpretPayload decides whether the body is treated as data or as text: only
// when the producer declared JSON, the body parses, and --raw-payload is off.
func interpretPayload(opts *fetchOptions, event remoteEvent, payload []byte) bool {
	if opts.rawPayload || !jsonContentType(event.Meta) {
		return false
	}
	return json.Valid(payload)
}

func jsonContentType(meta json.RawMessage) bool {
	var probe struct {
		ContentType string `json:"content_type"`
	}
	if err := json.Unmarshal(meta, &probe); err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(probe.ContentType), "json")
}

// payloadForJSON embeds the payload as JSON, compacted so the jsonl invariant
// (one line per event) holds even when the producer sent pretty-printed JSON.
// Anything else is written as a JSON string.
func payloadForJSON(opts *fetchOptions, event remoteEvent, payload []byte) json.RawMessage {
	if interpretPayload(opts, event, payload) {
		compact := &bytes.Buffer{}
		if err := json.Compact(compact, payload); err == nil {
			return json.RawMessage(compact.Bytes())
		}
	}
	encoded, _ := json.Marshal(string(payload))
	return encoded
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

func stdoutIsTerminal() bool {
	info, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func sleepContext(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// warnLoosePermissions nudges when the key file is readable by others.
func warnLoosePermissions(path string, errOut io.Writer) {
	info, err := os.Stat(path)
	if err != nil {
		return
	}
	if info.Mode().Perm()&0o077 != 0 {
		fmt.Fprintf(errOut, "warning: %s is readable beyond its owner (mode %04o); chmod 600 it\n",
			path, info.Mode().Perm())
	}
}

func envOr(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok && value != "" {
		return value
	}
	return fallback
}
