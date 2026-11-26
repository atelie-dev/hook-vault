// Package httpapi exposes two surfaces with two audiences:
//
//   - the data plane: public ingest and the token-authenticated read API;
//   - the control plane: endpoint management, keys and statistics.
//
// Keeping them on separate listeners is a product decision (only one of them is
// meant to face the internet), and it happens to map cleanly onto any reverse
// proxy topology without the binary knowing about one.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/atelie-dev/hook-vault/internal/store"
	"github.com/atelie-dev/hook-vault/internal/webui"
)

// Options configures a Server.
type Options struct {
	Store        *store.Store
	PublicURL    string
	MaxBodyBytes int64
	ReadLag      time.Duration
	AdminToken   string
	Logger       *slog.Logger
	Version      string
}

// Server holds the handlers and their dependencies.
type Server struct {
	store        *store.Store
	publicURL    string
	maxBodyBytes int64
	readLag      time.Duration
	adminToken   string
	logger       *slog.Logger
	version      string
	wake         chan struct{}
}

// New builds a Server. A nil logger falls back to slog.Default.
func New(opts Options) *Server {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{
		store:        opts.Store,
		publicURL:    opts.PublicURL,
		maxBodyBytes: opts.MaxBodyBytes,
		readLag:      opts.ReadLag,
		adminToken:   opts.AdminToken,
		logger:       logger,
		version:      opts.Version,
		wake:         make(chan struct{}, 1),
	}
}

// wakeReaders nudges open streams after a commit. Non-blocking, because one
// pending wake-up is enough: the stream re-reads everything visible when it
// wakes, so a coalesced signal loses nothing.
func (s *Server) wakeReaders() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// DataPlane returns the public handler: ingest plus the read API.
func (s *Server) DataPlane() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /in/{slug}", s.handleIngest)
	mux.HandleFunc("HEAD /in/{slug}", s.handleIngestProbe)
	mux.HandleFunc("GET /in/{slug}", s.handleHandshake)
	mux.HandleFunc("GET /v1/events", s.handleEvents)
	mux.HandleFunc("GET /v1/events/stream", s.handleEventsStream)
	mux.HandleFunc("GET /v1/me", s.handleMe)
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /llms.txt", s.handleLLMsTxt)
	mux.HandleFunc("/", s.notFound)
	return s.wrap(mux)
}

// ControlPlane serves the panel, the management API and static assets.
//
// Three audiences on one listener:
//
//   - /healthz and /static/*: no credential (assets are UI code, not secrets);
//   - /login: public by design, it *establishes* the credential;
//   - everything else: admin token as Bearer (CLI, scripts) or as the panel's
//     session cookie.
func (s *Server) ControlPlane() http.Handler {
	api := http.NewServeMux()
	api.HandleFunc("POST /v1/endpoints", s.handleCreateEndpoint)
	api.HandleFunc("GET /v1/endpoints", s.handleListEndpoints)
	api.HandleFunc("GET /v1/endpoints/{id}", s.handleGetEndpoint)
	api.HandleFunc("PATCH /v1/endpoints/{id}", s.handlePatchEndpoint)
	api.HandleFunc("GET /v1/endpoints/{id}/keys", s.handleListKeys)
	api.HandleFunc("POST /v1/endpoints/{id}/keys", s.handleRegisterKey)
	api.HandleFunc("DELETE /v1/endpoints/{id}/keys/{kid}", s.handleRevokeKey)
	api.HandleFunc("GET /v1/endpoints/{id}/stats", s.handleStats)

	panel := http.NewServeMux()
	panel.HandleFunc("GET /{$}", s.panelEndpoints)
	panel.HandleFunc("GET /new", s.panelCreate)
	panel.HandleFunc("GET /logout", s.panelLogout)
	panel.HandleFunc("/", s.notFound)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /login", s.panelLogin)
	mux.HandleFunc("POST /login", s.panelLoginPost)
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(webui.Static()))))
	mux.Handle("/v1/", s.requireAdminToken(api))
	mux.Handle("/", s.requireAdminPanel(panel))
	return s.wrap(mux)
}

func (s *Server) wrap(next http.Handler) http.Handler {
	return s.withRecover(s.withRequestLog(next))
}

func (s *Server) withRequestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		s.logger.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"bytes", rec.written,
			"remote", r.RemoteAddr,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	})
}

func (s *Server) withRecover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				s.logger.Error("panic serving request",
					"path", r.URL.Path,
					"panic", recovered,
					"stack", string(debug.Stack()),
				)
				writeError(w, http.StatusInternalServerError, "internal", "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// requireAdminToken guards the management API: scripts and the panel's own
// fetch calls expect a JSON error they can act on.
func (s *Server) requireAdminToken(next http.Handler) http.Handler {
	if s.adminToken == "" {
		// Only reachable when the listener is loopback-only; config.validate
		// refuses any other combination.
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.authenticated(r) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="hook-vault-admin"`)
			writeError(w, http.StatusUnauthorized, "unauthorized", "a valid admin token is required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireAdminPanel guards the panel pages: a person opening the panel should
// land on the login form, not on a JSON error.
func (s *Server) requireAdminPanel(next http.Handler) http.Handler {
	if s.adminToken == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.authenticated(r) {
			next.ServeHTTP(w, r)
			return
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	if err := s.store.Pool().Ping(ctx); err != nil {
		writeError(w, http.StatusServiceUnavailable, "database_unavailable", "database is not reachable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) notFound(w http.ResponseWriter, _ *http.Request) {
	writeError(w, http.StatusNotFound, "not_found", "no such route")
}

// statusRecorder captures what the log needs without buffering the response.
type statusRecorder struct {
	http.ResponseWriter
	status  int
	written int
	wrote   bool
}

func (r *statusRecorder) WriteHeader(code int) {
	if !r.wrote {
		r.status = code
		r.wrote = true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	r.wrote = true
	n, err := r.ResponseWriter.Write(b)
	r.written += n
	return n, err
}

// Flush lets a streaming handler push frames: without it the SSE handler could
// not reach the real ResponseWriter through the logging wrapper.
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap exposes the real writer to http.ResponseController, which needs it for
// the per-frame write deadline on a long-lived stream.
func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

type errorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorBody{Code: code, Message: message})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func bearerToken(r *http.Request) string {
	value := r.Header.Get("Authorization")
	if value == "" {
		return ""
	}
	const prefix = "bearer "
	if len(value) < len(prefix) || !equalFoldASCII(value[:len(prefix)], prefix) {
		return ""
	}
	return value[len(prefix):]
}

func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

func isNotFound(err error) bool { return errors.Is(err, store.ErrNotFound) }
