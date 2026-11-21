package httpapi

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"strings"

	"github.com/atelie-dev/hook-vault/internal/vault"
	"github.com/atelie-dev/hook-vault/internal/webui"
)

// The control-plane UI. It is a rendering of the same API the CLI uses — the
// panel adds pages and a login, not new capabilities.
//
// The admin token is the only credential. A browser cannot send a Bearer
// header on its own, so a successful login turns it into a stateless
// HttpOnly cookie: HMAC(adminToken, nonce). A restart does not log the
// operator out, and there is no session store to leak or clean up.
const adminCookieName = "hookvault_admin"

func (s *Server) sessionMAC(sid string) []byte {
	mac := hmac.New(sha256.New, []byte(s.adminToken))
	mac.Write([]byte(sid))
	return mac.Sum(nil)
}

func (s *Server) issueSession() string {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return ""
	}
	sid := base64.RawURLEncoding.EncodeToString(nonce)
	return sid + "." + base64.RawURLEncoding.EncodeToString(s.sessionMAC(sid))
}

func (s *Server) validSession(value string) bool {
	if s.adminToken == "" || value == "" {
		return false
	}
	sid, sig, ok := strings.Cut(value, ".")
	if !ok {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return false
	}
	return vault.HashEqual(decoded, s.sessionMAC(sid))
}

func (s *Server) hasSession(r *http.Request) bool {
	cookie, err := r.Cookie(adminCookieName)
	return err == nil && s.validSession(cookie.Value)
}

// authenticated accepts the admin token as a Bearer header (CLI and scripts)
// or as a session cookie (the panel).
func (s *Server) authenticated(r *http.Request) bool {
	if s.adminToken == "" {
		return true
	}
	if token := bearerToken(r); token != "" && vault.TokensEqual(token, s.adminToken) {
		return true
	}
	return s.hasSession(r)
}

func (s *Server) sessionCookie(r *http.Request, value string, maxAge int) *http.Cookie {
	secure := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
	return &http.Cookie{
		Name:     adminCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	}
}

// --- pages ----------------------------------------------------------------

type pageData struct {
	Title    string
	Version  string
	LoggedIn bool
	Flash    string
	Error    bool
}

var templateFuncs = template.FuncMap{
	"bytes": humanBytesOf,
}

// humanBytesOf renders counters the way an operator reads them.
//
// It takes any because html/template passes the DTO fields as they are, and
// the quota fields are *int64 (nil means "no limit").
func humanBytesOf(value any) string {
	switch n := value.(type) {
	case int64:
		return humanBytes(n)
	case *int64:
		if n == nil {
			return "no cap"
		}
		return humanBytes(*n)
	default:
		return "no cap"
	}
}

// humanBytes renders a plain counter.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	value, exp := float64(n), 0
	for value >= unit && exp < 4 {
		value /= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", value, "KMGTPE"[exp-1])
}

// render builds a fresh template set per page: every template file defines its
// own "content" (and optionally "scripts"), the layout consumes them.
func (s *Server) render(w http.ResponseWriter, _ *http.Request, status int, page string, data any) {
	t := template.New("layout.html").Funcs(templateFuncs)
	if _, err := t.ParseFS(webui.FS, "templates/layout.html", "templates/"+page); err != nil {
		s.logger.Error("parse panel template", "page", page, "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := t.ExecuteTemplate(w, "layout.html", data); err != nil {
		s.logger.Error("render panel page", "page", page, "error", err)
	}
}

func (s *Server) panelLogin(w http.ResponseWriter, r *http.Request) {
	if s.adminToken == "" || s.hasSession(r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.render(w, r, http.StatusOK, "login.html", &pageData{Title: "Sign in", Version: s.version})
}

func (s *Server) panelLoginPost(w http.ResponseWriter, r *http.Request) {
	if s.adminToken == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.render(w, r, http.StatusBadRequest, "login.html", &pageData{Title: "Sign in", Version: s.version})
		return
	}
	if !vault.TokensEqual(strings.TrimSpace(r.PostFormValue("token")), s.adminToken) {
		s.render(w, r, http.StatusUnauthorized, "login.html", &pageData{Title: "Sign in", Version: s.version, Error: true})
		return
	}
	http.SetCookie(w, s.sessionCookie(r, s.issueSession(), 12*60*60))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) panelLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, s.sessionCookie(r, "", -1))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

type endpointsPage struct {
	pageData
	Endpoints []endpointDTO
	PublicURL string
}

func (s *Server) panelEndpoints(w http.ResponseWriter, r *http.Request) {
	endpoints, err := s.store.ListEndpoints(r.Context())
	if err != nil {
		s.endpointError(w, err, "list endpoints")
		return
	}
	rows := make([]endpointDTO, 0, len(endpoints))
	for _, endpoint := range endpoints {
		rows = append(rows, s.toEndpointDTO(endpoint))
	}
	s.render(w, r, http.StatusOK, "endpoints.html", &endpointsPage{
		pageData:  pageData{Title: "Endpoints", Version: s.version, LoggedIn: s.hasSession(r)},
		Endpoints: rows,
	})
}

func (s *Server) panelCreate(w http.ResponseWriter, r *http.Request) {
	// A public key and a token hash can be pasted from the CLI; browser
	// generation is the convenience path. Either way the server only ever
	// receives what the create API already accepts.
	s.render(w, r, http.StatusOK, "create.html", &pageData{Title: "New endpoint", Version: s.version, LoggedIn: s.hasSession(r)})
}
