package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/atelie-dev/hook-vault/internal/store"
	"github.com/atelie-dev/hook-vault/internal/vault"
)

// handleIngest accepts a webhook from a provider.
//
// Order of operations is deliberate: verify, seal, store, then answer. A
// provider that gets a 2xx assumes delivery, so the only acceptable failure
// after accepting the body is a 5xx that makes it retry.
func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	slug := r.PathValue("slug")

	endpoint, err := s.store.EndpointBySlug(ctx, slug)
	if err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "unknown_endpoint", "no endpoint with this slug")
			return
		}
		s.logger.Error("lookup endpoint", "slug", slug, "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	if endpoint.DisabledAt != nil {
		writeError(w, http.StatusGone, "endpoint_disabled", "this endpoint is disabled")
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.maxBodyBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "payload_too_large",
				fmt.Sprintf("body exceeds the %d byte limit", s.maxBodyBytes))
			return
		}
		writeError(w, http.StatusBadRequest, "unreadable_body", "could not read the request body")
		return
	}
	if len(body) == 0 {
		writeError(w, http.StatusBadRequest, "empty_body", "refusing to store an empty body")
		return
	}

	verification := VerifyRequest(endpoint.Verify, derefString(endpoint.VerifySecret), body, r.Header)

	key, err := s.store.ActiveKey(ctx, endpoint.ID)
	if err != nil {
		if isNotFound(err) {
			s.logger.Error("endpoint has no active recipient key", "slug", slug)
			writeError(w, http.StatusServiceUnavailable, "no_active_key",
				"endpoint has no active recipient key; register one before sending webhooks")
			return
		}
		s.logger.Error("load active key", "slug", slug, "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}

	public, err := publicKey(key.PublicKey)
	if err != nil {
		s.logger.Error("stored public key is invalid", "slug", slug, "kid", key.KID, "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}

	sealed, err := vault.SealTo(body, public)
	if err != nil {
		s.logger.Error("seal payload", "slug", slug, "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}

	meta, err := json.Marshal(ExtractMeta(endpoint.Verify, r.Header, body))
	if err != nil {
		meta = []byte(`{}`)
	}

	status := "stored"
	if !verification.Verified {
		status = "rejected"
	}

	id, err := s.store.InsertEvent(ctx, store.InsertEventParams{
		EndpointID: endpoint.ID,
		KID:        key.KID,
		Ciphertext: sealed,
		SizeBytes:  len(sealed),
		Status:     status,
		Meta:       meta,
	})
	if err != nil {
		s.logger.Error("store event", "slug", slug, "error", err)
		writeError(w, http.StatusServiceUnavailable, "storage_error",
			"could not store the event; the provider should retry")
		return
	}

	w.Header().Set("X-HookVault-Event-Id", id)

	if !verification.Verified {
		// Stored as evidence rather than dropped: a silent rejection is
		// indistinguishable from a network problem, and this is the payload an
		// operator needs in order to understand the failure.
		s.logger.Warn("webhook failed verification and was stored as rejected",
			"slug", slug, "kid", key.KID, "id", id, "reason", verification.Reason)
		writeError(w, http.StatusUnauthorized, "signature_invalid", "the provider signature did not verify")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"id": id})
}

// handleHandshake answers Meta's subscription challenge:
//
//	GET /in/{slug}?hub.mode=subscribe&hub.verify_token=…&hub.challenge=…
//
// Without it a Meta webhook subscription never becomes active.
func (s *Server) handleHandshake(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	challenge := query.Get("hub.challenge")
	if query.Get("hub.mode") == "" {
		writeError(w, http.StatusBadRequest, "not_a_handshake",
			"a GET on an ingest URL only answers a hub.challenge handshake")
		return
	}
	if query.Get("hub.mode") != "subscribe" || challenge == "" || len(challenge) > 1024 {
		writeError(w, http.StatusBadRequest, "invalid_handshake", "unsupported hub.mode or missing hub.challenge")
		return
	}

	endpoint, err := s.store.EndpointBySlug(r.Context(), r.PathValue("slug"))
	if err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "unknown_endpoint", "no endpoint with this slug")
			return
		}
		s.logger.Error("lookup endpoint for handshake", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}

	if endpoint.VerifyToken == nil || *endpoint.VerifyToken == "" {
		writeError(w, http.StatusForbidden, "no_verify_token",
			"endpoint has no verify_token configured")
		return
	}
	if !vault.TokensEqual(*endpoint.VerifyToken, query.Get("hub.verify_token")) {
		s.logger.Warn("handshake with wrong verify token", "slug", endpoint.Slug)
		writeError(w, http.StatusForbidden, "invalid_verify_token", "hub.verify_token does not match")
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, challenge)
}

func publicKey(raw []byte) (*[32]byte, error) {
	if len(raw) != vault.PublicKeySize {
		return nil, fmt.Errorf("public key must be %d bytes, got %d", vault.PublicKeySize, len(raw))
	}
	var public [32]byte
	copy(public[:], raw)
	return &public, nil
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
