package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/atelie-dev/hook-vault/internal/vault"
)

func sealFor(t *testing.T, key *vault.Key, payload string) string {
	t.Helper()
	sealed, err := vault.SealTo([]byte(payload), &key.Public)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(sealed)
}

func pageWith(t *testing.T, key *vault.Key, id, payload string, more bool) string {
	t.Helper()
	next := ""
	if more {
		next = `,"has_more":true`
	} else {
		next = `,"has_more":false`
	}
	return `{"events":[{"id":"` + id + `","received_at":"2026-11-21T07:49:27Z","kid":"` + key.KID +
		`","alg":"x25519-xsalsa20poly1305-sealed","ct":"` + sealFor(t, key, payload) +
		`","size":60,"status":"stored","meta":{"source":"meta"}}],"next_cursor":"` + id + `"` + next +
		`,"oldest_cursor":"` + id + `","lag_seconds":2}`
}

func TestFetchPageAndDecrypt(t *testing.T) {
	key, err := vault.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if r.URL.Query().Get("limit") != "100" {
			t.Errorf("limit = %q, want 100", r.URL.Query().Get("limit"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(pageWith(t, key, "019a0000-0000-7000-8000-000000000001", `{"hello":"world"}`, false)))
	}))
	defer server.Close()

	opts := &fetchOptions{baseURL: server.URL, token: key.Token, limit: 100, key: key}
	page, err := fetchPage(context.Background(), server.Client(), opts)
	if err != nil {
		t.Fatalf("fetchPage: %v", err)
	}
	if gotAuth != "Bearer "+key.Token {
		t.Fatalf("Authorization = %q", gotAuth)
	}
	if len(page.Events) != 1 || page.NextCursor == nil || *page.NextCursor != page.Events[0].ID {
		t.Fatalf("unexpected page: %+v", page)
	}

	payload, ok, reason := decodeEvent(opts.key, page.Events[0])
	if !ok {
		t.Fatalf("decrypt failed: %s", reason)
	}
	if string(payload) != `{"hello":"world"}` {
		t.Fatalf("payload = %q", payload)
	}

	other, err := vault.Generate()
	if err != nil {
		t.Fatalf("generate other: %v", err)
	}
	if _, ok, reason := decodeEvent(other, page.Events[0]); ok || !strings.Contains(reason, "sealed for kid") {
		t.Fatalf("wrong key: ok=%v reason=%q", ok, reason)
	}
	if _, ok, reason := decodeEvent(nil, page.Events[0]); ok || !strings.Contains(reason, "no --key-file") {
		t.Fatalf("no key: ok=%v reason=%q", ok, reason)
	}
}

func TestFetchPageRejectsBadToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"code":"unauthorized"}`))
	}))
	defer server.Close()

	opts := &fetchOptions{baseURL: server.URL, token: "hv1_nope", limit: 10}
	if _, err := fetchPage(context.Background(), server.Client(), opts); err == nil {
		t.Fatal("a 401 must be an error")
	} else if err != errUnauthorized {
		t.Fatalf("error = %v, want errUnauthorized", err)
	}
}

func TestEmitJSONLHasStableSchema(t *testing.T) {
	key, err := vault.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	event := remoteEvent{
		ID:     "019a0000-0000-7000-8000-000000000001",
		KID:    key.KID,
		CT:     sealFor(t, key, "raw body, not json"),
		Status: "stored",
		Meta:   json.RawMessage(`{"source":"meta"}`),
	}

	var buf bytes.Buffer
	opts := &fetchOptions{key: key, format: "jsonl", out: &buf, errOut: &buf}
	if err := emit(opts, event); err != nil {
		t.Fatalf("emit: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("jsonl must be one line per event, got %d", len(lines))
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &decoded); err != nil {
		t.Fatalf("not json: %v", err)
	}
	// No content-type in meta: the payload stays a string.
	if decoded["decrypted"] != true || decoded["payload"] != "raw body, not json" {
		t.Fatalf("schema = %v", decoded)
	}

	buf.Reset()
	opts.key = nil
	if err := emit(opts, event); err != nil {
		t.Fatalf("emit sealed: %v", err)
	}
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("not json: %v", err)
	}
	if decoded["decrypted"] != false || decoded["ct"] == "" || decoded["reason"] == "" {
		t.Fatalf("sealed schema = %v", decoded)
	}
}

// A JSON content-type means the payload is data, not a string — unless
// --raw-payload says otherwise. One line per event still holds.
func TestEmitJSONLInterpretsJSONPayload(t *testing.T) {
	key, err := vault.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	event := remoteEvent{
		ID:     "019a0000-0000-7000-8000-000000000002",
		KID:    key.KID,
		CT:     sealFor(t, key, "{\n  \"entry\": [{\"id\": \"1\"}],\n  \"object\": \"whatsapp\"\n}"),
		Status: "stored",
		Meta:   json.RawMessage(`{"source":"meta","content_type":"application/json; charset=utf-8"}`),
	}

	var buf bytes.Buffer
	opts := &fetchOptions{key: key, format: "jsonl", out: &buf, errOut: &buf}
	if err := emit(opts, event); err != nil {
		t.Fatalf("emit: %v", err)
	}
	if lines := strings.Split(strings.TrimSpace(buf.String()), "\n"); len(lines) != 1 {
		t.Fatalf("embedded payload broke the one-line invariant: %d lines", len(lines))
	}

	var decoded struct {
		Payload map[string]any `json:"payload"`
	}
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("not json: %v", err)
	}
	if decoded.Payload["object"] != "whatsapp" {
		t.Fatalf("payload not embedded: %s", buf.String())
	}

	// --raw-payload turns it back into a string.
	buf.Reset()
	opts.rawPayload = true
	if err := emit(opts, event); err != nil {
		t.Fatalf("emit raw: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("not json: %v", err)
	}
	if _, isString := raw["payload"].(string); !isString {
		t.Fatalf("--raw-payload must keep the payload a string: %v", raw["payload"])
	}
}

func TestEmitHumanPrettyPrintsJSON(t *testing.T) {
	key, err := vault.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	event := remoteEvent{
		ID:     "019a0000-0000-7000-8000-000000000003",
		KID:    key.KID,
		CT:     sealFor(t, key, `{"a":1,"b":[2,3]}`),
		Status: "stored",
		Meta:   json.RawMessage(`{"source":"meta","content_type":"application/json"}`),
	}

	var buf bytes.Buffer
	opts := &fetchOptions{key: key, format: "human", out: &buf, errOut: &buf}
	if err := emit(opts, event); err != nil {
		t.Fatalf("emit: %v", err)
	}
	out := buf.String()
	for _, want := range []string{event.ID, "stored", "kid", `"a": 1`, "\n"} {
		if !strings.Contains(out, want) {
			t.Fatalf("human output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b[") {
		t.Fatal("colour codes leaked into a non-tty buffer")
	}

	// --raw-payload shows the bytes as they arrived.
	buf.Reset()
	opts.rawPayload = true
	if err := emit(opts, event); err != nil {
		t.Fatalf("emit raw: %v", err)
	}
	if !strings.Contains(buf.String(), `{"a":1,"b":[2,3]}`) {
		t.Fatalf("--raw-payload must not reformat:\n%s", buf.String())
	}
}

// lockedBuf is a goroutine-safe sink for the watch loop.
type lockedBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestWatchLoopPagesAndPersistsCursor(t *testing.T) {
	key, err := vault.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	var mu sync.Mutex
	requests := 0
	var cursors []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests++
		cursors = append(cursors, r.URL.Query().Get("cursor"))
		first := requests == 1
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		switch {
		case first:
			_, _ = w.Write([]byte(pageWith(t, key, "019a0000-0000-7000-8000-000000000001", `{"n":1}`, false)))
		default:
			_, _ = w.Write([]byte(`{"events":[],"next_cursor":null,"has_more":false,"oldest_cursor":null,"lag_seconds":2}`))
		}
	}))
	defer server.Close()

	cursorFile := filepath.Join(t.TempDir(), "cursor")
	out := &lockedBuf{}
	opts := &fetchOptions{
		baseURL:    server.URL,
		token:      key.Token,
		key:        key,
		limit:      100,
		format:     "jsonl",
		watch:      true,
		interval:   20 * time.Millisecond,
		cursorFile: cursorFile,
		out:        out,
		errOut:     &lockedBuf{},
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- watchLoop(ctx, server.Client(), opts) }()

	deadline := time.After(2 * time.Second)
	for {
		mu.Lock()
		done := requests >= 2
		mu.Unlock()
		if done {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("watch did not poll again; requests=%d", requests)
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	if err := <-done; err != nil && ctx.Err() == nil {
		t.Fatalf("watchLoop: %v", err)
	}

	mu.Lock()
	gotRequests, gotCursors := requests, append([]string(nil), cursors...)
	mu.Unlock()
	if gotRequests < 2 {
		t.Fatalf("watch made %d requests, want at least 2", gotRequests)
	}
	if gotCursors[1] != "019a0000-0000-7000-8000-000000000001" {
		t.Fatalf("second page cursor = %q, want the last emitted id", gotCursors[1])
	}

	raw, err := os.ReadFile(cursorFile)
	if err != nil {
		t.Fatalf("cursor file: %v", err)
	}
	if strings.TrimSpace(string(raw)) != "019a0000-0000-7000-8000-000000000001" {
		t.Fatalf("cursor file = %q", raw)
	}
}

// Without --cursor-file the cursor still has to move, or the loop re-emits the
// same page forever.
func TestWatchLoopAdvancesCursorWithoutFile(t *testing.T) {
	key, err := vault.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	var mu sync.Mutex
	var cursors []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		cursors = append(cursors, r.URL.Query().Get("cursor"))
		first := len(cursors) == 1
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		if first {
			_, _ = w.Write([]byte(pageWith(t, key, "019a0000-0000-7000-8000-000000000002", `{"n":1}`, false)))
			return
		}
		_, _ = w.Write([]byte(`{"events":[],"next_cursor":null,"has_more":false}`))
	}))
	defer server.Close()

	out := &lockedBuf{}
	opts := &fetchOptions{
		baseURL:  server.URL,
		token:    key.Token,
		key:      key,
		limit:    100,
		format:   "jsonl",
		watch:    true,
		interval: 20 * time.Millisecond,
		out:      out,
		errOut:   &lockedBuf{},
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- watchLoop(ctx, server.Client(), opts) }()

	deadline := time.After(2 * time.Second)
	for {
		mu.Lock()
		n := len(cursors)
		mu.Unlock()
		if n >= 3 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("watch did not keep polling; requests=%d", n)
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	<-done

	mu.Lock()
	second := cursors[1]
	mu.Unlock()
	if second != "019a0000-0000-7000-8000-000000000002" {
		t.Fatalf("second poll cursor = %q, want the emitted id", second)
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("event emitted %d times, want 1:\n%s", len(lines), out.String())
	}
}

// A server that ignores the unknown `since` parameter must not change the
// result: the client-side cutoff keeps the window exact.
func TestEmitAllAppliesLocalSinceCutoff(t *testing.T) {
	key, err := vault.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	cutoff := time.Date(2026, 11, 21, 11, 0, 0, 0, time.UTC)
	page := &remotePage{Events: []remoteEvent{
		{
			ID:         "019a0000-0000-7000-8000-000000000001",
			ReceivedAt: cutoff.Add(-time.Minute), // outside
			KID:        key.KID,
			CT:         sealFor(t, key, "old"),
			Status:     "stored",
		},
		{
			ID:         "019a0000-0000-7000-8000-000000000002",
			ReceivedAt: cutoff.Add(time.Minute), // inside
			KID:        key.KID,
			CT:         sealFor(t, key, "new"),
			Status:     "stored",
		},
	}}

	out := &lockedBuf{}
	opts := &fetchOptions{key: key, format: "jsonl", sinceCutoff: &cutoff, out: out, errOut: out}
	count, err := emitAll(opts, page)
	if err != nil {
		t.Fatalf("emitAll: %v", err)
	}
	if count != 1 {
		t.Fatalf("emitted %d events, want 1", count)
	}
	if !strings.Contains(out.String(), `"new"`) || strings.Contains(out.String(), `"old"`) {
		t.Fatalf("wrong event survived the cutoff:\n%s", out.String())
	}
}

func TestPickCredential(t *testing.T) {
	cases := []struct {
		name                   string
		flagValue, flagPath    string
		envValueName, envValue string
		envPathName, envPath   string
		wantValue, wantPath    string
		errSub                 string
	}{
		{name: "flag value", flagValue: "v", wantValue: "v"},
		{name: "flag path", flagPath: "/k", wantPath: "/k"},
		{name: "both flags", flagValue: "v", flagPath: "/k", errSub: "not both"},
		{name: "env value", envValueName: "HOOKVAULT_KEY_VALUE", envValue: "v", wantValue: "v"},
		{name: "env path", envPathName: "HOOKVAULT_KEY_FILE", envPath: "/k", wantPath: "/k"},
		{
			name:         "both envs",
			envValueName: "HOOKVAULT_KEY_VALUE", envValue: "v",
			envPathName: "HOOKVAULT_KEY_FILE", envPath: "/k",
			errSub: "both set",
		},
		{
			name:         "flag beats env",
			flagValue:    "from-flag",
			envValueName: "HOOKVAULT_KEY_VALUE", envValue: "from-env",
			wantValue: "from-flag",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			value, path, err := pickCredential("key", tc.flagValue, tc.flagPath,
				tc.envValueName, tc.envValue, tc.envPathName, tc.envPath)
			if tc.errSub != "" {
				if err == nil || !strings.Contains(err.Error(), tc.errSub) {
					t.Fatalf("err = %v, want containing %q", err, tc.errSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if value != tc.wantValue || path != tc.wantPath {
				t.Fatalf("value=%q path=%q, want value=%q path=%q", value, path, tc.wantValue, tc.wantPath)
			}
		})
	}
}

// The 1Password pattern: op run injects the value, no file on disk.
func TestFetchEnvOnlyCredentials(t *testing.T) {
	key, err := vault.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+key.Token {
			t.Errorf("Authorization = %q, want the token derived from the key", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(pageWith(t, key, "019a0000-0000-7000-8000-000000000009", `{"n":1}`, false)))
	}))
	defer server.Close()

	t.Setenv("HOOKVAULT_URL", server.URL)
	t.Setenv("HOOKVAULT_KEY_VALUE", vault.EncodeSecret(key.Secret[:]))
	t.Setenv("HOOKVAULT_KEY_FILE", "")
	t.Setenv("HOOKVAULT_TOKEN_VALUE", "")
	t.Setenv("HOOKVAULT_TOKEN_FILE", "")

	if err := runFetch([]string{"--format", "jsonl"}); err != nil {
		t.Fatalf("runFetch with env only: %v", err)
	}
}

func TestFetchRejectsAmbiguousEnv(t *testing.T) {
	t.Setenv("HOOKVAULT_URL", "http://127.0.0.1:1")
	t.Setenv("HOOKVAULT_KEY_VALUE", "x")
	t.Setenv("HOOKVAULT_KEY_FILE", "/nowhere")
	if err := runFetch([]string{"--format", "jsonl"}); err == nil || !strings.Contains(err.Error(), "both set") {
		t.Fatalf("err = %v, want the ambiguity error", err)
	}
}
