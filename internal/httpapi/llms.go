package httpapi

import (
	_ "embed"
	"io"
	"net/http"
	"strings"
)

// llmsTxt is the agent-facing contract served at the root of the data plane:
// routes, auth, event shape, cursor rules, CLI environment and a devenv recipe
// in one file, so an agent pointed at this host needs no other source.
//
// It is embedded rather than generated: it ships with the version that answers
// the request, so it cannot describe routes this binary does not serve.
//
//go:embed llms.txt
var llmsTxt string

// basePlaceholder is replaced with the origin a consumer reaches this host on.
// Keeping it in the document makes the curl and devenv examples copy-pasteable
// without hardcoding a hostname in a public binary.
const basePlaceholder = "{{base}}"

// handleLLMsTxt serves the embedded document. Nothing in it is secret and it
// needs no credential: that is the point of a discovery file.
func (s *Server) handleLLMsTxt(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = io.WriteString(w, strings.ReplaceAll(llmsTxt, basePlaceholder, s.baseURL(r)))
}

// baseURL is where a consumer reaches this host: the configured --public-url
// when the operator set one, otherwise the origin the request arrived on.
func (s *Server) baseURL(r *http.Request) string {
	if s.publicURL != "" {
		return s.publicURL
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}
