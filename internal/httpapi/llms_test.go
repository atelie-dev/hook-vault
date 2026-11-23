package httpapi

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// quiet keeps the request log out of the test output: the handler is under
// test, not the logger.
func quiet(opts Options) *Server {
	opts.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(opts)
}

// /llms.txt is the contract an agent reads before it has any other context, so
// the test pins what makes it useful: it is served without a credential, it
// names the routes that exist, and every copy-pasteable example points at the
// origin the operator configured.
func TestLLMsTxtServesPublicURL(t *testing.T) {
	h := quiet(Options{PublicURL: "https://hooks.example.com"}).DataPlane()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://hooks.example.com/llms.txt", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/plain") {
		t.Errorf("content-type = %q, want text/plain", got)
	}

	body := rec.Body.String()
	if strings.Contains(body, basePlaceholder) {
		t.Error("base placeholder was not substituted")
	}
	for _, want := range []string{
		"https://hooks.example.com/v1/me",
		"https://hooks.example.com/v1/events",
		"/llms.txt",
		"`/in/{slug}`", // the ingest route the binary serves
		"HOOKVAULT_KEY_FILE",
		`-H "authorization: Bearer $HOOKVAULT_TOKEN"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("document does not mention %q", want)
		}
	}

	// The binary is public: a deployment hostname or a live credential must
	// never be baked into the asset. The examples show "hv1_…", not a token.
	for _, unwanted := range []string{
		"atelie.dev.br",
		`hv1_[A-Za-z0-9_-]{4,}`,
	} {
		if regexp.MustCompile(unwanted).MatchString(body) {
			t.Errorf("document leaks %q", unwanted)
		}
	}
}

// Without --public-url the document still has to be usable, so the examples
// fall back to the origin of the request that asked for it.
func TestLLMsTxtFallsBackToRequestOrigin(t *testing.T) {
	h := quiet(Options{}).DataPlane()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/llms.txt", nil))

	body := rec.Body.String()
	if !strings.Contains(body, "http://127.0.0.1:8080/v1/events") {
		t.Error("examples do not use the request origin")
	}
	if strings.Contains(body, basePlaceholder) {
		t.Error("base placeholder was not substituted")
	}
}

// Discovery belongs to the public data plane; the control plane keeps its
// published surface small and does not answer for it.
func TestLLMsTxtIsNotOnControlPlane(t *testing.T) {
	h := quiet(Options{}).ControlPlane()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8081/llms.txt", nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}
