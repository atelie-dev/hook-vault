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

// get stops at the first response: the panel redirects unauthenticated pages to
// /login, and following that redirect would hide what the server actually did.
var panelClient = &http.Client{
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func request(t *testing.T, client *http.Client, method, url, cookie, body string) (int, string, http.Header) {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if body != "" {
		req.Body = io.NopCloser(strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
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

	status, body, _ := request(t, panelClient, http.MethodGet, control.URL+"/healthz", "", "")
	if status != http.StatusOK {
		t.Fatalf("/healthz: status %d, body %s", status, body)
	}

	status, body, _ = request(t, panelClient, http.MethodGet, control.URL+"/static/keygen.js", "", "")
	if status != http.StatusOK {
		t.Fatalf("/static/keygen.js: status %d, body %s", status, body)
	}
	if !strings.Contains(body, "hook-vault.auth.v1") {
		t.Fatal("keygen.js lost the HKDF info string")
	}
}

func TestPanelLoginIssuesCookie(t *testing.T) {
	control := newPanelHarness(t, "topsecret")
	const cookieName = "hookvault_admin="

	// The login page is public; the dashboard is not.
	status, body, _ := request(t, panelClient, http.MethodGet, control.URL+"/login", "", "")
	if status != http.StatusOK || !strings.Contains(body, "Admin token") {
		t.Fatalf("login page: status %d, body %s", status, body)
	}
	status, body, headers := request(t, panelClient, http.MethodGet, control.URL+"/", "", "")
	if status != http.StatusSeeOther || headers.Get("Location") != "/login" {
		t.Fatalf("dashboard without session: status %d, location %q (body %s)", status, headers.Get("Location"), body)
	}

	// Wrong token: 401, no cookie, and the form comes back with the error.
	status, body, headers = request(t, panelClient, http.MethodPost, control.URL+"/login", "", "token=wrong")
	if status != http.StatusUnauthorized {
		t.Fatalf("wrong token: status %d, body %s", status, body)
	}
	if len(headers.Values("Set-Cookie")) != 0 {
		t.Fatal("a failed login must not set a cookie")
	}
	if !strings.Contains(body, "did not match") {
		t.Fatal("a failed login must return the form, not a JSON error")
	}

	// Right token: redirect + stateless cookie.
	status, body, headers = request(t, panelClient, http.MethodPost, control.URL+"/login", "", "token=topsecret")
	if status != http.StatusSeeOther {
		t.Fatalf("login: status %d, body %s", status, body)
	}
	cookies := headers.Values("Set-Cookie")
	if len(cookies) != 1 || !strings.HasPrefix(cookies[0], cookieName) {
		t.Fatalf("login did not set the session cookie: %v", cookies)
	}
	if !strings.Contains(cookies[0], "HttpOnly") {
		t.Fatal("session cookie must be HttpOnly")
	}
	session := strings.SplitN(strings.TrimPrefix(cookies[0], cookieName), ";", 2)[0]

	// The cookie opens the panel pages…
	status, body, _ = request(t, panelClient, http.MethodGet, control.URL+"/", cookieName+session, "")
	if status != http.StatusOK || !strings.Contains(body, "New endpoint") {
		t.Fatalf("dashboard with session: status %d (body %s)", status, body)
	}
	status, body, _ = request(t, panelClient, http.MethodGet, control.URL+"/new", cookieName+session, "")
	if status != http.StatusOK || !strings.Contains(body, "generate in this browser") {
		t.Fatalf("create page with session: status %d (body %s)", status, body)
	}

	// …and the management API, instead of the Bearer header.
	status, body, _ = request(t, panelClient, http.MethodGet, control.URL+"/v1/endpoints", cookieName+session, "")
	if status != http.StatusOK || !strings.Contains(body, `"endpoints"`) {
		t.Fatalf("API with session: status %d, body %s", status, body)
	}

	// A tampered cookie is rejected — JSON, because it hit the API middleware.
	status, body, _ = request(t, panelClient, http.MethodGet, control.URL+"/v1/endpoints", cookieName+"AAAA.forged", "")
	if status != http.StatusUnauthorized {
		t.Fatalf("tampered cookie: status %d, body %s", status, body)
	}

	// The Bearer header still works for scripts.
	status, apiBody, _ := do(t, http.MethodGet, control.URL+"/v1/endpoints", nil,
		map[string]string{"Authorization": "Bearer topsecret"})
	if status != http.StatusOK {
		t.Fatalf("bearer on control plane: status %d, body %s", status, apiBody)
	}

	// Log out clears the cookie…
	status, body, headers = request(t, panelClient, http.MethodGet, control.URL+"/logout", cookieName+session, "")
	if status != http.StatusSeeOther {
		t.Fatalf("logout: status %d, body %s", status, body)
	}
	if !strings.Contains(headers.Get("Set-Cookie"), "Max-Age=0") {
		t.Fatalf("logout did not clear the cookie: %q", headers.Get("Set-Cookie"))
	}

	// …and the dashboard is locked again.
	status, _, headers = request(t, panelClient, http.MethodGet, control.URL+"/", "", "")
	if status != http.StatusSeeOther || headers.Get("Location") != "/login" {
		t.Fatalf("after logout: status %d, location %q", status, headers.Get("Location"))
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
//
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

// Every profile the server accepts must be selectable in the form. A profile
// missing from the select is a capability the UI silently hides — the meta
// profile was missing, so its verify-token field could never appear.
func TestPanelOffersEveryVerifyProfile(t *testing.T) {
	control := newPanelHarness(t, "")

	status, body, _ := do(t, http.MethodGet, control.URL+"/new", nil, nil)
	if status != http.StatusOK {
		t.Fatalf("create page: status %d", status)
	}
	for _, profile := range []string{"none", "github", "meta", "stripe", "generic-hmac"} {
		if !strings.Contains(string(body), `value="`+profile+`"`) {
			t.Errorf("form does not offer verify profile %q", profile)
		}
	}
}
