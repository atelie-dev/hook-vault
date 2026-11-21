package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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

func TestFetchPageAndDecrypt(t *testing.T) {
	key, err := vault.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	body := `{"events":[{"id":"019a0000-0000-7000-8000-000000000001","received_at":"2026-11-21T07:49:27Z","kid":"` +
		key.KID + `","alg":"x25519-xsalsa20poly1305-sealed","ct":"` + sealFor(t, key, `{"hello":"world"}`) +
		`","size":60,"status":"stored","meta":{"source":"meta"}}],"next_cursor":"019a0000-0000-7000-8000-000000000001","has_more":false,"oldest_cursor":"019a0000-0000-7000-8000-000000000001","lag_seconds":2}`

	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if r.URL.Query().Get("limit") != "100" {
			t.Errorf("limit = %q, want 100", r.URL.Query().Get("limit"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
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

	// A key from another rotation must not be silently wrong.
	other, err := vault.Generate()
	if err != nil {
		t.Fatalf("generate other: %v", err)
	}
	if _, ok, reason := decodeEvent(other, page.Events[0]); ok || !strings.Contains(reason, "sealed for kid") {
		t.Fatalf("wrong key: ok=%v reason=%q", ok, reason)
	}

	// Without a key the event still lists, ciphertext and all.
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
	} else if !strings.Contains(err.Error(), "rejected the token") {
		t.Fatalf("error = %v", err)
	}
}

func TestEmitJSONCarriesPayload(t *testing.T) {
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
	opts := &fetchOptions{key: key, asJSON: true, out: &buf, errOut: &buf}
	if err := emit(opts, event); err != nil {
		t.Fatalf("emit: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("not json: %v (%s)", err, buf.String())
	}
	if decoded["payload"] != "raw body, not json" {
		t.Fatalf("payload = %v", decoded["payload"])
	}
	if decoded["id"] != event.ID {
		t.Fatalf("id = %v", decoded["id"])
	}
}
