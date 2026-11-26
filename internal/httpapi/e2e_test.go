package httpapi_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/atelie-dev/hook-vault/internal/httpapi"
	"github.com/atelie-dev/hook-vault/internal/retention"
	"github.com/atelie-dev/hook-vault/internal/store"
	"github.com/atelie-dev/hook-vault/internal/vault"
)

// The suite needs a disposable database:
//
//	HOOKVAULT_TEST_DATABASE_URL='host=/tmp port=5432 user=postgres dbname=hookvault_test' go test ./...
//
// It drops and recreates the public schema, so never point it at anything you
// care about.
func newHarness(t *testing.T) (*httptest.Server, *httptest.Server, *store.Store) {
	t.Helper()
	return newHarnessWith(t, httpapi.Options{})
}

// newHarnessWith lets a test inject the seams the server does not default in
// production: today the SNS certificate fetcher and subscription confirmer.
func newHarnessWith(t *testing.T, options httpapi.Options) (*httptest.Server, *httptest.Server, *store.Store) {
	t.Helper()

	dsn := os.Getenv("HOOKVAULT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("HOOKVAULT_TEST_DATABASE_URL is not set")
	}

	ctx := context.Background()
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if _, err := st.Pool().Exec(ctx, `drop schema public cascade; create schema public`); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
	if err := st.RequirePostgres18(ctx); err != nil {
		t.Fatalf("postgres version: %v", err)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	logOut := io.Discard
	if os.Getenv("HOOKVAULT_TEST_VERBOSE") != "" {
		logOut = os.Stderr
	}
	logger := slog.New(slog.NewTextHandler(logOut, nil))

	options.Store = st
	options.MaxBodyBytes = 1 << 20
	options.Logger = logger
	api := httpapi.New(options)

	dataPlane := httptest.NewServer(api.DataPlane())
	controlPlane := httptest.NewServer(api.ControlPlane())
	t.Cleanup(func() {
		dataPlane.Close()
		controlPlane.Close()
		st.Close()
	})
	return dataPlane, controlPlane, st
}

type endpointView struct {
	Endpoint struct {
		ID             string   `json:"id"`
		Slug           string   `json:"slug"`
		Name           string   `json:"name"`
		IngestURL      string   `json:"ingest_url"`
		RetentionDays  *int     `json:"retention_days"`
		MaxBytes       *int64   `json:"max_bytes"`
		BytesUsed      int64    `json:"bytes_used"`
		EventsUsed     int64    `json:"events_used"`
		EvictedEvents  int64    `json:"evicted_events"`
		Verify         string   `json:"verify"`
		SNSAutoConfirm bool     `json:"sns_auto_confirm"`
		SNSTopics      []string `json:"sns_topics"`
		ActiveKID      *string  `json:"active_kid"`
	} `json:"endpoint"`
	Key struct {
		KID       string `json:"kid"`
		PublicKey string `json:"public_key"`
	} `json:"key"`
}

type pageView struct {
	Events []struct {
		ID         string         `json:"id"`
		ReceivedAt time.Time      `json:"received_at"`
		KID        string         `json:"kid"`
		Alg        string         `json:"alg"`
		CT         string         `json:"ct"`
		Size       int            `json:"size"`
		Status     string         `json:"status"`
		Meta       map[string]any `json:"meta"`
	} `json:"events"`
	NextCursor   *string `json:"next_cursor"`
	HasMore      bool    `json:"has_more"`
	OldestCursor *string `json:"oldest_cursor"`
	LagSeconds   float64 `json:"lag_seconds"`
}

func do(t *testing.T, method, url string, body []byte, headers map[string]string) (int, []byte, http.Header) {
	t.Helper()

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request %s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, payload, resp.Header
}

func createEndpoint(t *testing.T, adminURL string, key *vault.Key, extra map[string]any) endpointView {
	t.Helper()

	payload := map[string]any{
		"name":         "github prod",
		"public_key":   vault.EncodePublic(key.Public[:]),
		"token_sha256": hex.EncodeToString(vault.HashToken(key.Token)),
	}
	for k, v := range extra {
		payload[k] = v
	}
	body, _ := json.Marshal(payload)

	status, respBody, _ := do(t, http.MethodPost, adminURL+"/v1/endpoints", body,
		map[string]string{"Content-Type": "application/json"})
	if status != http.StatusCreated {
		t.Fatalf("create endpoint: status %d, body %s", status, respBody)
	}

	var view endpointView
	if err := json.Unmarshal(respBody, &view); err != nil {
		t.Fatalf("decode endpoint: %v", err)
	}
	return view
}

func sign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestIngestSealReadAndDecrypt(t *testing.T) {
	dataPlane, controlPlane, _ := newHarness(t)

	key, err := vault.Generate()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	created := createEndpoint(t, controlPlane.URL, key, map[string]any{
		"retention_days": 30,
		"max_bytes":      1 << 20,
		"verify":         "github",
		"verify_secret":  "s3cr3t",
	})
	if created.Key.KID != key.KID {
		t.Fatalf("registered kid %q, want %q", created.Key.KID, key.KID)
	}
	if created.Endpoint.ActiveKID == nil || *created.Endpoint.ActiveKID != key.KID {
		t.Fatal("endpoint does not report the active key")
	}

	payload := []byte(`{"action":"opened","number":42}`)
	status, body, header := do(t, http.MethodPost,
		dataPlane.URL+"/in/"+created.Endpoint.Slug, payload,
		map[string]string{
			"Content-Type":        "application/json",
			"X-GitHub-Event":      "issues",
			"X-GitHub-Delivery":   "delivery-1",
			"X-Hub-Signature-256": sign("s3cr3t", payload),
		},
	)
	if status != http.StatusOK {
		t.Fatalf("ingest: status %d, body %s", status, body)
	}
	eventID := header.Get("X-HookVault-Event-Id")
	if eventID == "" {
		t.Fatal("ingest did not return an event id")
	}

	status, body, _ = do(t, http.MethodGet, dataPlane.URL+"/v1/events", nil,
		map[string]string{"Authorization": "Bearer " + key.Token})
	if status != http.StatusOK {
		t.Fatalf("read: status %d, body %s", status, body)
	}

	var page pageView
	if err := json.Unmarshal(body, &page); err != nil {
		t.Fatalf("decode page: %v", err)
	}
	if len(page.Events) != 1 {
		t.Fatalf("got %d events, want 1", len(page.Events))
	}

	event := page.Events[0]
	if event.ID != eventID {
		t.Fatalf("event id %q, want %q", event.ID, eventID)
	}
	if event.KID != key.KID {
		t.Fatalf("event kid %q, want %q", event.KID, key.KID)
	}
	if event.Status != "stored" {
		t.Fatalf("event status %q, want stored", event.Status)
	}
	if got := event.Meta["event"]; got != "issues" {
		t.Fatalf("meta event %v, want issues", got)
	}
	if event.Meta["delivery"] != "delivery-1" {
		t.Fatalf("meta delivery %v, want delivery-1", event.Meta["delivery"])
	}
	if strings.Contains(string(body), "opened") {
		t.Fatal("payload content leaked into the API response")
	}

	sealed, err := base64.RawURLEncoding.DecodeString(event.CT)
	if err != nil {
		t.Fatalf("decode ciphertext: %v", err)
	}
	if bytes.Contains(sealed, []byte("opened")) {
		t.Fatal("ciphertext contains plaintext")
	}
	plaintext, err := vault.Open(sealed, &key.Public, &key.Secret)
	if err != nil {
		t.Fatalf("open ciphertext: %v", err)
	}
	if !bytes.Equal(plaintext, payload) {
		t.Fatalf("plaintext %q, want %q", plaintext, payload)
	}
	if event.Size != len(sealed) {
		t.Fatalf("size %d, want %d", event.Size, len(sealed))
	}

	// The control plane must never expose the provider secret.
	status, body, _ = do(t, http.MethodGet, controlPlane.URL+"/v1/endpoints/"+created.Endpoint.ID, nil, nil)
	if status != http.StatusOK {
		t.Fatalf("get endpoint: status %d", status)
	}
	if strings.Contains(string(body), "s3cr3t") {
		t.Fatal("the provider secret was returned by the control plane")
	}
}

// TestIngestProbeAnswersProviderURLCheck covers the HEAD a provider makes before
// it accepts a webhook URL (Receita Federal's async APIs reject the solicitation
// when it fails). net/http matches a GET pattern against HEAD, so a missing HEAD
// route here silently answers the Meta handshake's 400 instead.
func TestIngestProbeAnswersProviderURLCheck(t *testing.T) {
	dataPlane, controlPlane, _ := newHarness(t)

	key, err := vault.Generate()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	created := createEndpoint(t, controlPlane.URL, key, map[string]any{"verify": "none"})
	ingestURL := dataPlane.URL + "/in/" + created.Endpoint.Slug

	status, body, header := do(t, http.MethodHead, ingestURL, nil, nil)
	if status != http.StatusOK {
		t.Fatalf("probe: status %d, want 200", status)
	}
	if len(body) != 0 {
		t.Fatalf("probe body %q, want empty", body)
	}
	if got := header.Get("Content-Type"); strings.Contains(got, "json") {
		t.Fatalf("probe answered %q; that is the handshake, not the probe", got)
	}

	// The probe is unauthenticated and runs once per solicitation: it must leave
	// no trace in the log.
	status, body, _ = do(t, http.MethodGet, dataPlane.URL+"/v1/events", nil,
		map[string]string{"Authorization": "Bearer " + key.Token})
	if status != http.StatusOK {
		t.Fatalf("read: status %d, body %s", status, body)
	}
	var page pageView
	if err := json.Unmarshal(body, &page); err != nil {
		t.Fatalf("decode page: %v", err)
	}
	if len(page.Events) != 0 {
		t.Fatalf("the probe stored %d events, want 0", len(page.Events))
	}

	// A wrong URL has to fail now, while the subscription is being opened.
	status, _, _ = do(t, http.MethodHead, dataPlane.URL+"/in/does-not-exist", nil, nil)
	if status != http.StatusNotFound {
		t.Fatalf("probe on unknown slug: status %d, want 404", status)
	}

	// The handshake keeps its own 400 for a bare GET.
	status, _, _ = do(t, http.MethodGet, ingestURL, nil, nil)
	if status != http.StatusBadRequest {
		t.Fatalf("bare GET: status %d, want 400", status)
	}

	patch, _ := json.Marshal(map[string]any{"disabled": true})
	status, body, _ = do(t, http.MethodPatch, controlPlane.URL+"/v1/endpoints/"+created.Endpoint.ID,
		patch, map[string]string{"Content-Type": "application/json"})
	if status != http.StatusOK {
		t.Fatalf("disable endpoint: status %d, body %s", status, body)
	}
	status, _, _ = do(t, http.MethodHead, ingestURL, nil, nil)
	if status != http.StatusGone {
		t.Fatalf("probe on disabled endpoint: status %d, want 410", status)
	}
}

func TestCursorPaginationWalksEveryEventOnce(t *testing.T) {
	dataPlane, controlPlane, _ := newHarness(t)

	key, err := vault.Generate()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	created := createEndpoint(t, controlPlane.URL, key, map[string]any{"verify": "none"})

	const total = 5
	for i := 0; i < total; i++ {
		payload := []byte(fmt.Sprintf(`{"n":%d}`, i))
		status, body, _ := do(t, http.MethodPost, dataPlane.URL+"/in/"+created.Endpoint.Slug, payload, nil)
		if status != http.StatusOK {
			t.Fatalf("ingest %d: status %d, body %s", i, status, body)
		}
	}

	seen := make([]string, 0, total)
	var cursor *string
	for page := 0; ; page++ {
		url := dataPlane.URL + "/v1/events?limit=2"
		if cursor != nil {
			url += "&cursor=" + *cursor
		}
		status, body, _ := do(t, http.MethodGet, url, nil,
			map[string]string{"Authorization": "Bearer " + key.Token})
		if status != http.StatusOK {
			t.Fatalf("page %d: status %d, body %s", page, status, body)
		}

		var view pageView
		if err := json.Unmarshal(body, &view); err != nil {
			t.Fatalf("decode page %d: %v", page, err)
		}
		for _, event := range view.Events {
			seen = append(seen, event.ID)
		}
		if !view.HasMore {
			break
		}
		if view.NextCursor == nil {
			t.Fatal("has_more is true but next_cursor is null")
		}
		cursor = view.NextCursor
		if page > total {
			t.Fatal("pagination did not terminate")
		}
	}

	if len(seen) != total {
		t.Fatalf("walked %d events, want %d", len(seen), total)
	}
	for i := 1; i < len(seen); i++ {
		if seen[i-1] >= seen[i] {
			t.Fatalf("cursor order is not increasing: %q then %q", seen[i-1], seen[i])
		}
	}

	// A cursor from the middle must resume exactly after itself.
	status, body, _ := do(t, http.MethodGet,
		dataPlane.URL+"/v1/events?limit=10&cursor="+seen[2], nil,
		map[string]string{"Authorization": "Bearer " + key.Token})
	if status != http.StatusOK {
		t.Fatalf("resume: status %d, body %s", status, body)
	}
	var resume pageView
	if err := json.Unmarshal(body, &resume); err != nil {
		t.Fatalf("decode resume: %v", err)
	}
	if len(resume.Events) != total-3 {
		t.Fatalf("resume returned %d events, want %d", len(resume.Events), total-3)
	}
	if resume.Events[0].ID != seen[3] {
		t.Fatalf("resume started at %q, want %q", resume.Events[0].ID, seen[3])
	}

	// /v1/me exposes both ends of the log. A consumer joining an existing
	// endpoint starts at cursor.newest: everything before it was sealed for
	// another key and it could not decrypt it anyway.
	status, body, _ = do(t, http.MethodGet, dataPlane.URL+"/v1/me", nil,
		map[string]string{"Authorization": "Bearer " + key.Token})
	if status != http.StatusOK {
		t.Fatalf("me: status %d, body %s", status, body)
	}
	var me struct {
		Cursor struct {
			Oldest *string `json:"oldest"`
			Newest *string `json:"newest"`
		} `json:"cursor"`
	}
	if err := json.Unmarshal(body, &me); err != nil {
		t.Fatalf("decode me: %v", err)
	}
	if me.Cursor.Newest == nil || *me.Cursor.Newest != seen[total-1] {
		t.Fatalf("cursor.newest = %v, want %q", me.Cursor.Newest, seen[total-1])
	}
	if me.Cursor.Oldest == nil || *me.Cursor.Oldest != seen[0] {
		t.Fatalf("cursor.oldest = %v, want %q", me.Cursor.Oldest, seen[0])
	}
}

func TestInvalidSignatureIsStoredAsEvidence(t *testing.T) {
	dataPlane, controlPlane, _ := newHarness(t)

	key, err := vault.Generate()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	created := createEndpoint(t, controlPlane.URL, key, map[string]any{
		"verify":        "github",
		"verify_secret": "right-secret",
	})

	payload := []byte(`{"spoofed":true}`)
	status, body, _ := do(t, http.MethodPost, dataPlane.URL+"/in/"+created.Endpoint.Slug, payload,
		map[string]string{"X-Hub-Signature-256": sign("wrong-secret", payload)})
	if status != http.StatusUnauthorized {
		t.Fatalf("spoofed ingest: status %d, want 401 (body %s)", status, body)
	}

	auth := map[string]string{"Authorization": "Bearer " + key.Token}
	status, body, _ = do(t, http.MethodGet, dataPlane.URL+"/v1/events", nil, auth)
	if status != http.StatusOK {
		t.Fatalf("read: status %d", status)
	}
	var page pageView
	if err := json.Unmarshal(body, &page); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(page.Events) != 0 {
		t.Fatal("a rejected event appeared in the default read")
	}

	status, body, _ = do(t, http.MethodGet, dataPlane.URL+"/v1/events?include_rejected=true", nil, auth)
	if status != http.StatusOK {
		t.Fatalf("read rejected: status %d", status)
	}
	if err := json.Unmarshal(body, &page); err != nil {
		t.Fatalf("decode rejected: %v", err)
	}
	if len(page.Events) != 1 || page.Events[0].Status != "rejected" {
		t.Fatalf("expected one rejected event, got %+v", page.Events)
	}

	// The evidence is still sealed, so the operator can decrypt what arrived.
	sealed, err := base64.RawURLEncoding.DecodeString(page.Events[0].CT)
	if err != nil {
		t.Fatalf("decode ciphertext: %v", err)
	}
	plaintext, err := vault.Open(sealed, &key.Public, &key.Secret)
	if err != nil {
		t.Fatalf("open rejected event: %v", err)
	}
	if !bytes.Equal(plaintext, payload) {
		t.Fatalf("plaintext %q, want %q", plaintext, payload)
	}
}

func TestAuthenticationRequired(t *testing.T) {
	dataPlane, controlPlane, _ := newHarness(t)

	key, err := vault.Generate()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	created := createEndpoint(t, controlPlane.URL, key, nil)

	for name, headers := range map[string]map[string]string{
		"none":        nil,
		"garbage":     {"Authorization": "Bearer hv1_not-a-token"},
		"wrong-shape": {"Authorization": "Basic abc"},
	} {
		status, _, _ := do(t, http.MethodGet, dataPlane.URL+"/v1/events", nil, headers)
		if status != http.StatusUnauthorized {
			t.Fatalf("%s: status %d, want 401", name, status)
		}
	}

	// Revoking the key must kill the token on the next request.
	status, body, _ := do(t, http.MethodDelete,
		controlPlane.URL+"/v1/endpoints/"+created.Endpoint.ID+"/keys/"+key.KID, nil, nil)
	if status != http.StatusNoContent {
		t.Fatalf("revoke: status %d, body %s", status, body)
	}
	status, _, _ = do(t, http.MethodGet, dataPlane.URL+"/v1/events", nil,
		map[string]string{"Authorization": "Bearer " + key.Token})
	if status != http.StatusUnauthorized {
		t.Fatalf("revoked token: status %d, want 401", status)
	}
}

func TestRetentionEnforcesAgeAndSize(t *testing.T) {
	_, controlPlane, st := newHarness(t)

	key, err := vault.Generate()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	maxBytes := int64(4096)
	retentionDays := 1
	created := createEndpoint(t, controlPlane.URL, key, map[string]any{
		"retention_days": retentionDays,
		"max_bytes":      maxBytes,
	})

	ctx := context.Background()
	body := bytes.Repeat([]byte("x"), 900)
	for i := 0; i < 10; i++ {
		sealed, err := vault.SealTo(body, &key.Public)
		if err != nil {
			t.Fatalf("seal: %v", err)
		}
		if _, err := st.InsertEvent(ctx, store.InsertEventParams{
			EndpointID: created.Endpoint.ID,
			KID:        key.KID,
			Ciphertext: sealed,
			SizeBytes:  len(sealed),
			Status:     "stored",
		}); err != nil {
			t.Fatalf("insert event %d: %v", i, err)
		}
	}

	sweeper := retention.New(st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	sweeper.Sweep(ctx)

	endpoint, err := st.EndpointByID(ctx, created.Endpoint.ID)
	if err != nil {
		t.Fatalf("reload endpoint: %v", err)
	}
	if endpoint.BytesUsed > maxBytes {
		t.Fatalf("bytes_used %d still above max_bytes %d", endpoint.BytesUsed, maxBytes)
	}
	if endpoint.EvictedEvents == 0 {
		t.Fatal("size policy did not record an eviction")
	}

	// Age: backdate everything, sweep, and expect the counters to reach zero.
	if _, err := st.Pool().Exec(ctx,
		`update event set received_at = now() - interval '3 days' where endpoint_id = $1::uuid`,
		created.Endpoint.ID); err != nil {
		t.Fatalf("backdate: %v", err)
	}
	sweeper.Sweep(ctx)

	endpoint, err = st.EndpointByID(ctx, created.Endpoint.ID)
	if err != nil {
		t.Fatalf("reload endpoint: %v", err)
	}
	if endpoint.EventsUsed != 0 || endpoint.BytesUsed != 0 {
		t.Fatalf("age policy left %d events / %d bytes", endpoint.EventsUsed, endpoint.BytesUsed)
	}
}

// A key pair is bound to exactly one endpoint: the token is the endpoint's
// identity, so sharing it would widen the blast radius of a leak. The inverse is
// allowed — several keys on one endpoint, for rotation or a second reader.
func TestKeyBelongsToExactlyOneEndpoint(t *testing.T) {
	_, controlPlane, _ := newHarness(t)

	key, err := vault.Generate()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	first := createEndpoint(t, controlPlane.URL, key, nil)

	registration := map[string]any{
		"public_key":   vault.EncodePublic(key.Public[:]),
		"token_sha256": hex.EncodeToString(vault.HashToken(key.Token)),
	}
	withName := map[string]any{"name": "second"}
	for k, v := range registration {
		withName[k] = v
	}
	body, _ := json.Marshal(withName)

	status, respBody, _ := do(t, http.MethodPost, controlPlane.URL+"/v1/endpoints", body,
		map[string]string{"Content-Type": "application/json"})
	if status != http.StatusConflict {
		t.Fatalf("reused key on another endpoint: status %d, want 409 (body %s)", status, respBody)
	}
	if !strings.Contains(string(respBody), "token_in_use") {
		t.Fatalf("expected token_in_use, got %s", respBody)
	}

	// A second key on the same endpoint is how a rotation or a second consumer
	// is added, so it must succeed.
	other, err := vault.Generate()
	if err != nil {
		t.Fatalf("generate second key: %v", err)
	}
	rotation, _ := json.Marshal(map[string]any{
		"public_key":   vault.EncodePublic(other.Public[:]),
		"token_sha256": hex.EncodeToString(vault.HashToken(other.Token)),
	})
	status, respBody, _ = do(t, http.MethodPost,
		controlPlane.URL+"/v1/endpoints/"+first.Endpoint.ID+"/keys", rotation,
		map[string]string{"Content-Type": "application/json"})
	if status != http.StatusCreated {
		t.Fatalf("second key on the same endpoint: status %d, want 201 (body %s)", status, respBody)
	}

	// Re-registering the same key on its own endpoint is idempotent, which is
	// what makes a retried registration safe.
	reRegister, _ := json.Marshal(registration)
	status, respBody, _ = do(t, http.MethodPost,
		controlPlane.URL+"/v1/endpoints/"+first.Endpoint.ID+"/keys", reRegister,
		map[string]string{"Content-Type": "application/json"})
	if status != http.StatusCreated {
		t.Fatalf("idempotent re-registration: status %d, want 201 (body %s)", status, respBody)
	}
}

// TestReadersNeverSkipEventsUnderConcurrentInserts is the invariant 4 regression
// test: with no visibility lag, a reader that advances its cursor while writers
// hammer one endpoint must still see every event. Before InsertEvent took the
// endpoint row lock before assigning the id, a reader could read a larger id
// first and then never fetch the smaller one that committed later.
func TestReadersNeverSkipEventsUnderConcurrentInserts(t *testing.T) {
	_, control, st := newHarness(t)
	key, err := vault.Generate()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	endpoint := createEndpoint(t, control.URL, key, nil)

	const writers, perWriter = 12, 20
	total := writers * perWriter

	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perWriter; j++ {
				if _, err := st.InsertEvent(context.Background(), store.InsertEventParams{
					EndpointID: endpoint.Endpoint.ID,
					KID:        endpoint.Key.KID,
					Ciphertext: []byte{0x01, 0x02, 0x03},
					SizeBytes:  3,
				}); err != nil {
					t.Errorf("insert: %v", err)
					return
				}
			}
		}()
	}

	seen := make(map[string]bool, total)
	var cursor *string
	deadline := time.Now().Add(30 * time.Second)
	for len(seen) < total && time.Now().Before(deadline) {
		page, _, err := st.FetchEvents(context.Background(), store.FetchParams{
			EndpointID: endpoint.Endpoint.ID,
			Cursor:     cursor,
			Limit:      7,
			Lag:        0,
		})
		if err != nil {
			t.Fatalf("fetch: %v", err)
		}
		for _, event := range page {
			if seen[event.ID] {
				t.Fatalf("event %s returned twice", event.ID)
			}
			seen[event.ID] = true
			id := event.ID
			cursor = &id
		}
		if len(page) == 0 {
			time.Sleep(2 * time.Millisecond)
		}
	}
	wg.Wait()

	// Drain whatever committed after the loop's last poll: the set must be exact.
	for {
		page, _, err := st.FetchEvents(context.Background(), store.FetchParams{
			EndpointID: endpoint.Endpoint.ID,
			Cursor:     cursor,
			Limit:      100,
			Lag:        0,
		})
		if err != nil {
			t.Fatalf("final fetch: %v", err)
		}
		if len(page) == 0 {
			break
		}
		for _, event := range page {
			seen[event.ID] = true
			id := event.ID
			cursor = &id
		}
	}

	if len(seen) != total {
		t.Fatalf("reader saw %d of %d events: %d were skipped by the cursor", len(seen), total, total-len(seen))
	}
}

// TestEventsStreamPushesCommittedEvents covers the SSE path end to end: the
// stream opens with the token, an ingest commits, and the frame arrives without
// the client asking again.
func TestEventsStreamPushesCommittedEvents(t *testing.T) {
	dataPlane, control, _ := newHarness(t)
	key, err := vault.Generate()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	endpoint := createEndpoint(t, control.URL, key, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dataPlane.URL+"/v1/events/stream", nil)
	if err != nil {
		t.Fatalf("build stream request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+key.Token)

	resp, err := http.DefaultClient.Do(req) //nolint:bodyclose // the body is drained by the scanner goroutine below and closed by the deferred Close
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stream status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("content type = %q, want text/event-stream", ct)
	}

	lines := make(chan string, 64)
	go func() {
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
		close(lines)
	}()

	status, body, _ := do(t, http.MethodPost, dataPlane.URL+"/in/"+endpoint.Endpoint.Slug,
		[]byte(`{"hello":"world"}`), map[string]string{"Content-Type": "application/json"})
	if status != http.StatusOK {
		t.Fatalf("ingest status = %d, want 200 (body %s)", status, body)
	}
	var ingested struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &ingested); err != nil {
		t.Fatalf("decode ingest response: %v", err)
	}

	timeout := time.After(10 * time.Second)
	sawRetry := false
	for {
		select {
		case line, ok := <-lines:
			if !ok {
				t.Fatalf("stream closed before delivering event %s", ingested.ID)
			}
			switch {
			case strings.HasPrefix(line, "retry: "):
				sawRetry = true
			case strings.HasPrefix(line, "id: "):
				if strings.TrimPrefix(line, "id: ") == ingested.ID {
					if !sawRetry {
						t.Fatal("the stream must send its retry hint before any event")
					}
					return
				}
			}
		case <-timeout:
			t.Fatalf("stream did not deliver event %s", ingested.ID)
		}
	}
}
