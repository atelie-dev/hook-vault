package httpapi

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/atelie-dev/hook-vault/internal/store"
	"github.com/atelie-dev/hook-vault/internal/vault"
)

const maxAdminBodyBytes = 64 << 10

var slugPattern = regexp.MustCompile(`^[a-z0-9]{12,64}$`)

// endpointDTO is the control-plane view of an endpoint. It deliberately has no
// field for the provider secret or the verify token: those are write-only.
type endpointDTO struct {
	ID             string     `json:"id"`
	Slug           string     `json:"slug"`
	Name           string     `json:"name"`
	IngestURL      string     `json:"ingest_url,omitempty"`
	RetentionDays  *int       `json:"retention_days"`
	MaxBytes       *int64     `json:"max_bytes"`
	BytesUsed      int64      `json:"bytes_used"`
	EventsUsed     int64      `json:"events_used"`
	EvictedEvents  int64      `json:"evicted_events"`
	Verify         string     `json:"verify"`
	SNSAutoConfirm bool       `json:"sns_auto_confirm"`
	SNSTopics      []string   `json:"sns_topics"`
	ActiveKID      *string    `json:"active_kid"`
	CreatedAt      time.Time  `json:"created_at"`
	DisabledAt     *time.Time `json:"disabled_at"`
}

type keyDTO struct {
	KID       string     `json:"kid"`
	PublicKey string     `json:"public_key"`
	Active    bool       `json:"active"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at"`
}

func (s *Server) toEndpointDTO(ep store.Endpoint) endpointDTO {
	topics := ep.SNSTopics
	if topics == nil {
		topics = []string{}
	}
	return endpointDTO{
		ID:             ep.ID,
		Slug:           ep.Slug,
		Name:           ep.Name,
		IngestURL:      s.ingestURL(ep.Slug),
		RetentionDays:  ep.RetentionDays,
		MaxBytes:       ep.MaxBytes,
		BytesUsed:      ep.BytesUsed,
		EventsUsed:     ep.EventsUsed,
		EvictedEvents:  ep.EvictedEvents,
		Verify:         ep.Verify,
		SNSAutoConfirm: ep.SNSAutoConfirm,
		SNSTopics:      topics,
		ActiveKID:      ep.ActiveKID,
		CreatedAt:      ep.CreatedAt,
		DisabledAt:     ep.DisabledAt,
	}
}

type createEndpointRequest struct {
	Name           string   `json:"name"`
	Slug           string   `json:"slug"`
	RetentionDays  *int     `json:"retention_days"`
	MaxBytes       *int64   `json:"max_bytes"`
	Verify         string   `json:"verify"`
	VerifySecret   string   `json:"verify_secret"`
	VerifyToken    string   `json:"verify_token"`
	SNSAutoConfirm bool     `json:"sns_auto_confirm"`
	SNSTopics      []string `json:"sns_topics"`
	PublicKey      string   `json:"public_key"`
	TokenSHA256    string   `json:"token_sha256"`
}

type createEndpointResponse struct {
	Endpoint endpointDTO `json:"endpoint"`
	Key      keyDTO      `json:"key"`
}

// handleCreateEndpoint creates an endpoint together with its first recipient
// key. There is no useful endpoint without a key: it could not seal anything.
func (s *Server) handleCreateEndpoint(w http.ResponseWriter, r *http.Request) {
	var req createEndpointRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" || len(name) > 200 {
		writeError(w, http.StatusUnprocessableEntity, "invalid_name", "name is required and must be at most 200 characters")
		return
	}
	if req.Slug != "" && !slugPattern.MatchString(req.Slug) {
		writeError(w, http.StatusUnprocessableEntity, "invalid_slug", "slug must be 12 to 64 lowercase alphanumeric characters")
		return
	}
	if req.RetentionDays != nil && *req.RetentionDays <= 0 {
		writeError(w, http.StatusUnprocessableEntity, "invalid_retention", "retention_days must be positive, or omitted for no age limit")
		return
	}
	if req.MaxBytes != nil && *req.MaxBytes <= 0 {
		writeError(w, http.StatusUnprocessableEntity, "invalid_max_bytes", "max_bytes must be positive, or omitted for no size limit")
		return
	}

	verify := req.Verify
	if verify == "" {
		verify = VerifyNone
	}
	if !validVerifyProfile(verify) {
		writeError(w, http.StatusUnprocessableEntity, "invalid_verify", "verify must be one of none, github, meta, stripe, generic-hmac, sns")
		return
	}
	// SNS has no shared secret: its material is the topic allowlist.
	if verify != VerifyNone && verify != VerifySNS && req.VerifySecret == "" {
		writeError(w, http.StatusUnprocessableEntity, "missing_verify_secret", "verify_secret is required for the chosen profile")
		return
	}
	if verify != VerifySNS && (req.SNSAutoConfirm || len(req.SNSTopics) > 0) {
		writeError(w, http.StatusUnprocessableEntity, "invalid_sns", "sns_auto_confirm and sns_topics only apply to verify=sns")
		return
	}
	topics, err := normalizeSNSTopics(req.SNSTopics)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid_sns", err.Error())
		return
	}

	public, err := vault.ParsePublicKey(req.PublicKey)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid_public_key", err.Error())
		return
	}
	tokenHash, err := parseTokenHash(req.TokenSHA256)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid_token_sha256", err.Error())
		return
	}

	endpoint, err := s.store.CreateEndpointWithKey(r.Context(),
		store.CreateEndpointParams{
			Slug:           req.Slug,
			Name:           name,
			RetentionDays:  req.RetentionDays,
			MaxBytes:       req.MaxBytes,
			Verify:         verify,
			VerifySecret:   optional(req.VerifySecret),
			VerifyToken:    optional(req.VerifyToken),
			SNSAutoConfirm: req.SNSAutoConfirm,
			SNSTopics:      topics,
		},
		vault.KIDFor(public[:]), public[:], tokenHash,
	)
	if err != nil {
		if errors.Is(err, store.ErrTokenInUse) {
			writeError(w, http.StatusConflict, "token_in_use", "this key is already registered on another endpoint")
			return
		}
		s.logger.Error("create endpoint", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}

	writeJSON(w, http.StatusCreated, createEndpointResponse{
		Endpoint: s.toEndpointDTO(endpoint),
		Key: keyDTO{
			KID:       vault.KIDFor(public[:]),
			PublicKey: vault.EncodePublic(public[:]),
			Active:    true,
			CreatedAt: endpoint.CreatedAt,
		},
	})
}

func (s *Server) handleListEndpoints(w http.ResponseWriter, r *http.Request) {
	endpoints, err := s.store.ListEndpoints(r.Context())
	if err != nil {
		s.logger.Error("list endpoints", "error", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	out := make([]endpointDTO, 0, len(endpoints))
	for _, ep := range endpoints {
		out = append(out, s.toEndpointDTO(ep))
	}
	writeJSON(w, http.StatusOK, map[string]any{"endpoints": out})
}

func (s *Server) handleGetEndpoint(w http.ResponseWriter, r *http.Request) {
	id, ok := s.endpointID(w, r)
	if !ok {
		return
	}
	endpoint, err := s.store.EndpointByID(r.Context(), id)
	if err != nil {
		s.endpointError(w, err, "load endpoint")
		return
	}
	keys, err := s.store.ListKeys(r.Context(), id)
	if err != nil {
		s.endpointError(w, err, "list keys")
		return
	}
	keyViews := make([]keyDTO, 0, len(keys))
	for _, key := range keys {
		keyViews = append(keyViews, keyDTO{
			KID:       key.KID,
			PublicKey: vault.EncodePublic(key.PublicKey),
			Active:    key.RevokedAt == nil,
			CreatedAt: key.CreatedAt,
			RevokedAt: key.RevokedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"endpoint": s.toEndpointDTO(endpoint),
		"keys":     keyViews,
	})
}

type patchEndpointRequest struct {
	Name           *string   `json:"name"`
	RetentionDays  *int      `json:"retention_days"`
	MaxBytes       *int64    `json:"max_bytes"`
	Verify         *string   `json:"verify"`
	VerifySecret   *string   `json:"verify_secret"`
	VerifyToken    *string   `json:"verify_token"`
	SNSAutoConfirm *bool     `json:"sns_auto_confirm"`
	SNSTopics      *[]string `json:"sns_topics"`
	Disabled       *bool     `json:"disabled"`
}

func (s *Server) handlePatchEndpoint(w http.ResponseWriter, r *http.Request) {
	id, ok := s.endpointID(w, r)
	if !ok {
		return
	}

	var req patchEndpointRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Name != nil {
		trimmed := strings.TrimSpace(*req.Name)
		if trimmed == "" || len(trimmed) > 200 {
			writeError(w, http.StatusUnprocessableEntity, "invalid_name", "name must be between 1 and 200 characters")
			return
		}
		req.Name = &trimmed
	}
	if req.RetentionDays != nil && *req.RetentionDays < 0 {
		writeError(w, http.StatusUnprocessableEntity, "invalid_retention", "retention_days must be 0 to clear the limit or a positive number")
		return
	}
	if req.MaxBytes != nil && *req.MaxBytes < 0 {
		writeError(w, http.StatusUnprocessableEntity, "invalid_max_bytes", "max_bytes must be 0 to clear the limit or a positive number")
		return
	}
	if req.Verify != nil && !validVerifyProfile(*req.Verify) {
		writeError(w, http.StatusUnprocessableEntity, "invalid_verify", "verify must be one of none, github, meta, stripe, generic-hmac, sns")
		return
	}
	if req.Verify != nil && *req.Verify != VerifySNS &&
		(req.SNSAutoConfirm != nil || req.SNSTopics != nil) {
		writeError(w, http.StatusUnprocessableEntity, "invalid_sns", "sns_auto_confirm and sns_topics only apply to verify=sns")
		return
	}
	var topics *[]string
	if req.SNSTopics != nil {
		normalized, err := normalizeSNSTopics(*req.SNSTopics)
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity, "invalid_sns", err.Error())
			return
		}
		topics = &normalized
	}

	endpoint, err := s.store.UpdateEndpoint(r.Context(), id, store.EndpointPatch{
		Name:           req.Name,
		RetentionDays:  req.RetentionDays,
		MaxBytes:       req.MaxBytes,
		Verify:         req.Verify,
		VerifySecret:   req.VerifySecret,
		VerifyToken:    req.VerifyToken,
		SNSAutoConfirm: req.SNSAutoConfirm,
		SNSTopics:      topics,
		Disabled:       req.Disabled,
	})
	if err != nil {
		s.endpointError(w, err, "update endpoint")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"endpoint": s.toEndpointDTO(endpoint)})
}

type registerKeyRequest struct {
	PublicKey   string `json:"public_key"`
	TokenSHA256 string `json:"token_sha256"`
}

func (s *Server) handleRegisterKey(w http.ResponseWriter, r *http.Request) {
	id, ok := s.endpointID(w, r)
	if !ok {
		return
	}

	var req registerKeyRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	public, err := vault.ParsePublicKey(req.PublicKey)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid_public_key", err.Error())
		return
	}
	tokenHash, err := parseTokenHash(req.TokenSHA256)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid_token_sha256", err.Error())
		return
	}

	key, err := s.store.RegisterKey(r.Context(), id, vault.KIDFor(public[:]), public[:], tokenHash)
	if err != nil {
		if errors.Is(err, store.ErrTokenInUse) {
			writeError(w, http.StatusConflict, "token_in_use", "this key is already registered on another endpoint")
			return
		}
		s.endpointError(w, err, "register key")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"key": keyDTO{
			KID:       key.KID,
			PublicKey: vault.EncodePublic(key.PublicKey),
			Active:    true,
			CreatedAt: key.CreatedAt,
		},
	})
}

func (s *Server) handleListKeys(w http.ResponseWriter, r *http.Request) {
	id, ok := s.endpointID(w, r)
	if !ok {
		return
	}
	keys, err := s.store.ListKeys(r.Context(), id)
	if err != nil {
		s.endpointError(w, err, "list keys")
		return
	}
	out := make([]keyDTO, 0, len(keys))
	for _, key := range keys {
		out = append(out, keyDTO{
			KID:       key.KID,
			PublicKey: vault.EncodePublic(key.PublicKey),
			Active:    key.RevokedAt == nil,
			CreatedAt: key.CreatedAt,
			RevokedAt: key.RevokedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": out})
}

func (s *Server) handleRevokeKey(w http.ResponseWriter, r *http.Request) {
	id, ok := s.endpointID(w, r)
	if !ok {
		return
	}
	if err := s.store.RevokeKey(r.Context(), id, r.PathValue("kid")); err != nil {
		s.endpointError(w, err, "revoke key")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	id, ok := s.endpointID(w, r)
	if !ok {
		return
	}

	window := 24 * time.Hour
	if raw := r.URL.Query().Get("window"); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil || parsed <= 0 || parsed > 90*24*time.Hour {
			writeError(w, http.StatusBadRequest, "invalid_window", "window must be a duration between 1s and 2160h")
			return
		}
		window = parsed
	}

	endpoint, err := s.store.EndpointByID(r.Context(), id)
	if err != nil {
		s.endpointError(w, err, "load endpoint")
		return
	}
	buckets, err := s.store.Stats(r.Context(), id, window)
	if err != nil {
		s.endpointError(w, err, "stats")
		return
	}

	out := make([]map[string]any, 0, len(buckets))
	for _, bucket := range buckets {
		out = append(out, map[string]any{
			"start":    bucket.Start,
			"events":   bucket.Events,
			"rejected": bucket.Rejected,
			"bytes":    bucket.Bytes,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"window_seconds": window.Seconds(),
		"buckets":        out,
		"storage": map[string]any{
			"bytes_used":     endpoint.BytesUsed,
			"events_used":    endpoint.EventsUsed,
			"evicted_events": endpoint.EvictedEvents,
			"max_bytes":      endpoint.MaxBytes,
			"retention_days": endpoint.RetentionDays,
		},
	})
}

func (s *Server) endpointID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("id")
	if !validUUID(id) {
		writeError(w, http.StatusBadRequest, "invalid_endpoint_id", "endpoint id must be a uuid")
		return "", false
	}
	return id, true
}

func (s *Server) endpointError(w http.ResponseWriter, err error, operation string) {
	if isNotFound(err) {
		writeError(w, http.StatusNotFound, "not_found", "no such endpoint or key")
		return
	}
	s.logger.Error(operation, "error", err)
	writeError(w, http.StatusInternalServerError, "internal", "internal error")
}

func validVerifyProfile(profile string) bool {
	switch profile {
	case VerifyNone, VerifyGitHub, VerifyMeta, VerifyStripe, VerifyGeneric, VerifySNS:
		return true
	default:
		return false
	}
}

// snsTopicARNPattern is the shape of an SNS topic ARN in every partition.
var snsTopicARNPattern = regexp.MustCompile(`^arn:aws(-cn|-us-gov)?:sns:[a-z0-9-]+:[0-9]{12}:[A-Za-z0-9_-]{1,256}$`)

// maxSNSTopics bounds the allowlist: an endpoint belongs to a handful of
// topics, and an unbounded list is a list nobody reads.
const maxSNSTopics = 20

// normalizeSNSTopics trims, validates and dedupes the topic allowlist. Blank
// lines are what a textarea sends, so they are dropped rather than refused.
func normalizeSNSTopics(topics []string) ([]string, error) {
	normalized := make([]string, 0, len(topics))
	for _, topic := range topics {
		topic = strings.TrimSpace(topic)
		if topic == "" {
			continue
		}
		if !snsTopicARNPattern.MatchString(topic) {
			return nil, fmt.Errorf("sns_topics entry %q is not an SNS topic ARN", topic)
		}
		if !slices.Contains(normalized, topic) {
			normalized = append(normalized, topic)
		}
	}
	if len(normalized) > maxSNSTopics {
		return nil, fmt.Errorf("sns_topics is limited to %d topics", maxSNSTopics)
	}
	return normalized, nil
}

func parseTokenHash(value string) ([]byte, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(value))
	if err != nil || len(raw) != 32 {
		return nil, fmt.Errorf("token_sha256 must be 64 hex characters (the SHA-256 of the derived token)")
	}
	return raw, nil
}

func optional(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxAdminBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "could not decode request body: "+err.Error())
		return false
	}
	return true
}
