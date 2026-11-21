package httpapi_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/atelie-dev/hook-vault/internal/httpapi"
	"github.com/atelie-dev/hook-vault/internal/store"
	"github.com/atelie-dev/hook-vault/internal/vault"
)

// The panel needs a store but no token: when AdminToken is empty the whole
// control plane is open (loopback-only deployments).
func newPanelHarness(t *testing.T, adminToken string) *httptest.Server {
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
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	api := httpapi.New(httpapi.Options{
		Store:      st,
		AdminToken: adminToken,
		Version:    "test",
		Logger:     logger,
	})
	control := httptest.NewServer(api.ControlPlane())
	t.Cleanup(func() {
		control.Close()
		st.Close()
	})
	return control
}

// noRedirect stops at the first response: the panel redirects after login and
// logout, and following them would drop the Set-Cookie (no cookie jar here).
var noRedirect = &http.Client{
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func postForm(t *testing.T, url, body string) (int, string, http.Header) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatalf("request %s: %v", url, err)
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, string(payload), resp.Header
}

func TestPanelHealthzAndStaticNeedNoCredential(t *testing.T) {
	control := newPanelHarness(t, "topsecret")

	status, body, _ := do(t, http.MethodGet, control.URL+"/healthz", nil, nil)
	if status != http.StatusOK {
		t.Fatalf("/healthz: status %d, body %s", status, body)
	}

	status, body, _ = do(t, http.MethodGet, control.URL+"/static/keygen.js", nil, nil)
	if status != http.StatusOK {
		t.Fatalf("/static/keygen.js: status %d, body %s", status, body)
	}
	if !strings.Contains(string(body), "hook-vault.auth.v1") {
		t.Fatal("keygen.js lost the HKDF info string")
	}
}

func TestPanelLoginIssuesCookie(t *testing.T) {
	control := newPanelHarness(t, "topsecret")

	// The login page is public; everything else is not.
	status, body, _ := do(t, http.MethodGet, control.URL+"/login", nil, nil)
	if status != http.StatusOK || !strings.Contains(string(body), "Admin token") {
		t.Fatalf("login page: status %d, body %s", status, body)
	}
	status, body, _ = do(t, http.MethodGet, control.URL+"/", nil, nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("list without login: status %d, body %s", status, body)
	}

	// Wrong token: 401 and no cookie.
	status, page, headers := postForm(t, control.URL+"/login", "token=wrong")
	if status != http.StatusUnauthorized {
		t.Fatalf("wrong token: status %d, body %s", status, page)
	}
	if len(headers.Values("Set-Cookie")) != 0 {
		t.Fatal("a failed login must not set a cookie")
	}

	// Right token: redirect + cookie.
	status, page, headers = postForm(t, control.URL+"/login", "token=topsecret")
	if status != http.StatusSeeOther {
		t.Fatalf("login: status %d, body %s", status, page)
	}
	cookies := headers.Values("Set-Cookie")
	if len(cookies) != 1 || !strings.HasPrefix(cookies[0], "hookvault_admin=") {
		t.Fatalf("login did not set the session cookie: %v", cookies)
	}
	if !strings.Contains(cookies[0], "HttpOnly") {
		t.Fatal("session cookie must be HttpOnly")
	}
	value := strings.SplitN(strings.TrimPrefix(cookies[0], "hookvault_admin="), ";", 2)[0]

	// The cookie opens the panel pages and the management API.
	for _, path := range []string{"/", "/new"} {
		status, body, _ := do(t, http.MethodGet, control.URL+path, nil,
			map[string]string{"Cookie": "hookvault_admin=" + value})
		if status != http.StatusOK {
			t.Fatalf("%s with session cookie: status %d, body %s", path, status, body)
		}
	}

	// The management API accepts the cookie instead of the Bearer header.
	status, apiBody, _ := do(t, http.MethodGet, control.URL+"/v1/endpoints", nil,
		map[string]string{"Cookie": "hookvault_admin=" + value})
	if status != http.StatusOK {
		t.Fatalf("API with session cookie: status %d, body %s", status, apiBody)
	}
	if !strings.Contains(string(apiBody), `"endpoints"`) {
		t.Fatalf("the API response does not look like the endpoints list: %s", apiBody)
	}

	// A tampered cookie is rejected.
	status, _, _ = do(t, http.MethodGet, control.URL+"/", nil,
		map[string]string{"Cookie": "hookvault_admin=AAAA." + strings.SplitN(value, ".", 2)[1]})
	if status != http.StatusUnauthorized {
		t.Fatal("a tampered session was accepted")
	}

	// The Bearer header still works for scripts.
	status, _, _ = do(t, http.MethodGet, control.URL+"/v1/endpoints", nil,
		map[string]string{"Authorization": "Bearer topsecret"})
	if status != http.StatusOK {
		t.Fatalf("bearer on control plane: status %d", status)
	}

	// Log out clears the cookie.
	req, err := http.NewRequest(http.MethodGet, control.URL+"/logout", nil)
	if err != nil {
		t.Fatalf("build logout: %v", err)
	}
	req.Header.Set("Cookie", "hookvault_admin="+value)
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("logout: status %d", resp.StatusCode)
	}
	if !strings.Contains(resp.Header.Get("Set-Cookie"), "Max-Age=0") {
		t.Fatalf("logout did not clear the cookie: %q", resp.Header.Get("Set-Cookie"))
	}
}

func TestPanelListsEndpoints(t *testing.T) {
	control := newPanelHarness(t, "")

	key, err := vault.Generate()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	view := createEndpoint(t, control.URL, key, map[string]any{"retention_days": 30, "max_bytes": 1073741824})

	status, body, _ := do(t, http.MethodGet, control.URL+"/", nil, nil)
	if status != http.StatusOK {
		t.Fatalf("panel: status %d, body %s", status, body)
	}
	for _, want := range []string{view.Endpoint.Name, view.Endpoint.Slug, "30d", "1.0 GiB"} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("panel is missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(string(body), "evicting") {
		t.Fatal("a fresh endpoint must not show an eviction badge")
	}
}

// The panel's form posts exactly what the create API accepts — the UI is a
// rendering of the API, not a new capability.
func TestPanelCreatePostsToExistingAPI(t *testing.T) {
	control := newPanelHarness(t, "")

	key, err := vault.Generate()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	payload := map[string]any{
		"name":         "panel created",
		"verify":       "none",
		"public_key":   vault.EncodePublic(key.Public[:]),
		"token_sha256": hex.EncodeToString(vault.HashToken(key.Token)),
	}
	body, _ := json.Marshal(payload)

	status, body, _ := do(t, http.MethodPost, control.URL+"/v1/endpoints", body,
		map[string]string{"Content-Type": "application/json"})
	if status != http.StatusCreated {
		t.Fatalf("create: status %d, body %s", status, body)
	}
	var created endpointView
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if created.Endpoint.Slug == "" || created.Key.KID == "" {
		t.Fatalf("incomplete response: %+v", created)
	}
}
