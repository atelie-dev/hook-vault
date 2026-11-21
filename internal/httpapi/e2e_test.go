package httpapi_test

import (
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

	logOut := io.Writer(io.Discard)
	if os.Getenv("HOOKVAULT_TEST_VERBOSE") != "" {
		logOut = os.Stderr
	}
	logger := slog.New(slog.NewTextHandler(logOut, nil))
	api := httpapi.New(httpapi.Options{
		Store:        st,
		MaxBodyBytes: 1 << 20,
		ReadLag:      0,
		Logger:       logger,
	})

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
		ID            string  `json:"id"`
		Slug          string  `json:"slug"`
		Name          string  `json:"name"`
		IngestURL     string  `json:"ingest_url"`
		RetentionDays *int    `json:"retention_days"`
		MaxBytes      *int64  `json:"max_bytes"`
		BytesUsed     int64   `json:"bytes_used"`
		EventsUsed    int64   `json:"events_used"`
		EvictedEvents int64   `json:"evicted_events"`
		Verify        string  `json:"verify"`
		ActiveKID     *string `json:"active_kid"`
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
