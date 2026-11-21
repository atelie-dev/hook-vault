package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/atelie-dev/hook-vault/internal/store"
	"github.com/atelie-dev/hook-vault/internal/vault"
)

const (
	defaultPageSize = 100
	maxPageSize     = 1000
)

type eventDTO struct {
	ID         string          `json:"id"`
	ReceivedAt time.Time       `json:"received_at"`
	KID        string          `json:"kid,omitempty"`
	Alg        string          `json:"alg"`
	CT         string          `json:"ct"`
	Size       int             `json:"size"`
	Status     string          `json:"status"`
	Meta       json.RawMessage `json:"meta,omitempty"`
}

type eventsResponse struct {
	Events       []eventDTO `json:"events"`
	NextCursor   *string    `json:"next_cursor"`
	HasMore      bool       `json:"has_more"`
	OldestCursor *string    `json:"oldest_cursor"`
	LagSeconds   float64    `json:"lag_seconds"`
}

// handleEvents is the read API: ciphertext in, ciphertext out. The consumer
// holds the cursor, so the server keeps no per-reader state.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	endpoint, _, ok := s.authenticate(w, r)
	if !ok {
		return
	}

	limit := defaultPageSize
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > maxPageSize {
			writeError(w, http.StatusBadRequest, "invalid_limit",
				"limit must be an integer between 1 and "+strconv.Itoa(maxPageSize))
			return
		}
		limit = parsed
	}

	var cursor *string
	if raw := r.URL.Query().Get("cursor"); raw != "" {
		if !validUUID(raw) {
			writeError(w, http.StatusBadRequest, "invalid_cursor", "cursor must be an event id returned by this API")
			return
		}
		cursor = &raw
	}

	includeRejected := r.URL.Query().Get("include_rejected") == "true"

	events, hasMore, err := s.store.FetchEvents(r.Context(), store.FetchParams{
		EndpointID:      endpoint.ID,
		Cursor:          cursor,
		Limit:           limit,
		Lag:             s.readLag,
		IncludeRejected: includeRejected,
	})
	if err != nil {
		s.logger.Error("fetch events", "endpoint", endpoint.ID, "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}

	oldest, err := s.store.Watermark(r.Context(), endpoint.ID)
	if err != nil {
		s.logger.Error("watermark", "endpoint", endpoint.ID, "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}

	out := eventsResponse{
		Events:       make([]eventDTO, 0, len(events)),
		HasMore:      hasMore,
		OldestCursor: oldest,
		LagSeconds:   s.readLag.Seconds(),
		NextCursor:   cursor,
	}
	for _, event := range events {
		out.Events = append(out.Events, eventDTO{
			ID:         event.ID,
			ReceivedAt: event.ReceivedAt,
			KID:        event.KID,
			Alg:        event.Alg,
			CT:         base64.RawURLEncoding.EncodeToString(event.Ciphertext),
			Size:       event.SizeBytes,
			Status:     event.Status,
			Meta:       event.Meta,
		})
	}
	if len(out.Events) > 0 {
		last := out.Events[len(out.Events)-1].ID
		out.NextCursor = &last
	}

	writeJSON(w, http.StatusOK, out)
}

// handleMe lets a consumer read its own posture: which key it is using, how
// much it has stored, and the oldest id still available.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	endpoint, key, ok := s.authenticate(w, r)
	if !ok {
		return
	}

	oldest, err := s.store.Watermark(r.Context(), endpoint.ID)
	if err != nil {
		s.logger.Error("watermark", "endpoint", endpoint.ID, "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"endpoint": map[string]any{
			"id":   endpoint.ID,
			"slug": endpoint.Slug,
			"name": endpoint.Name,
		},
		"key": map[string]any{"kid": key.KID},
		"storage": map[string]any{
			"bytes_used":     endpoint.BytesUsed,
			"events_used":    endpoint.EventsUsed,
			"evicted_events": endpoint.EvictedEvents,
			"retention_days": endpoint.RetentionDays,
			"max_bytes":      endpoint.MaxBytes,
		},
		"cursor": map[string]any{
			"oldest":      oldest,
			"lag_seconds": s.readLag.Seconds(),
		},
		"ingest_url": s.ingestURL(endpoint.Slug),
	})
}

// authenticate resolves a bearer token to its endpoint. Failures are
// deliberately indistinguishable: unknown, revoked and malformed all look the
// same from outside.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (store.Endpoint, store.Key, bool) {
	token := bearerToken(r)
	if token == "" || !strings.HasPrefix(token, vault.TokenPrefix) {
		unauthorized(w)
		return store.Endpoint{}, store.Key{}, false
	}

	endpoint, key, err := s.store.EndpointByTokenHash(r.Context(), vault.HashToken(token))
	if err != nil {
		if !isNotFound(err) {
			s.logger.Error("authenticate token", "error", err)
			writeError(w, http.StatusInternalServerError, "internal", "internal error")
			return store.Endpoint{}, store.Key{}, false
		}
		unauthorized(w)
		return store.Endpoint{}, store.Key{}, false
	}
	return endpoint, key, true
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="hook-vault"`)
	writeError(w, http.StatusUnauthorized, "unauthorized", "a valid API token is required")
}

func validUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		switch i {
		case 8, 13, 18, 23:
			if s[i] != '-' {
				return false
			}
		default:
			c := s[i]
			if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F') {
				return false
			}
		}
	}
	return true
}

func (s *Server) ingestURL(slug string) string {
	if s.publicURL == "" {
		return ""
	}
	return s.publicURL + "/in/" + slug
}
