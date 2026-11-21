package httpapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Verification profiles. The provider secret authenticates the sender; it can
// never reveal a payload, because payloads are sealed with a key the server
// does not hold.
const (
	VerifyNone    = "none"
	VerifyGitHub  = "github"
	VerifyMeta    = "meta"
	VerifyStripe  = "stripe"
	VerifyGeneric = "generic-hmac"
)

// stripeTolerance bounds replay of a Stripe delivery.
const stripeTolerance = 5 * time.Minute

// maxMetaParseBytes bounds the JSON probe that extracts routing hints from a
// body. Larger bodies are stored without hints rather than parsed.
const maxMetaParseBytes = 256 << 10

// Verification is the outcome of checking a provider signature.
type Verification struct {
	Verified bool
	Reason   string
}

// VerifyRequest checks the signature for the endpoint's profile.
//
// GitHub and Meta share the same scheme (X-Hub-Signature-256: sha256=<hex>
// HMAC of the raw body), so one implementation covers both.
func VerifyRequest(profile, secret string, body []byte, header http.Header) Verification {
	if profile == VerifyNone || profile == "" {
		return Verification{Verified: true, Reason: "verification disabled"}
	}
	if secret == "" {
		return Verification{Reason: "no secret configured for profile " + profile}
	}

	switch profile {
	case VerifyGitHub, VerifyMeta, VerifyGeneric:
		name := "X-Hub-Signature-256"
		if profile == VerifyGeneric {
			name = "X-HookVault-Signature"
		}
		return verifyHexHMAC(secret, body, header.Get(name), name)

	case VerifyStripe:
		return verifyStripe(secret, body, header.Get("Stripe-Signature"))

	default:
		return Verification{Reason: "unknown verification profile " + profile}
	}
}

func verifyHexHMAC(secret string, body []byte, value, headerName string) Verification {
	if value == "" {
		return Verification{Reason: "missing " + headerName + " header"}
	}
	algorithm, signature, found := strings.Cut(value, "=")
	if !found || !strings.EqualFold(algorithm, "sha256") {
		return Verification{Reason: headerName + " is not a sha256 signature"}
	}
	expected := hmacHex(secret, body)
	if !hmac.Equal([]byte(strings.ToLower(signature)), []byte(expected)) {
		return Verification{Reason: "signature mismatch"}
	}
	return Verification{Verified: true, Reason: "signature verified"}
}

func verifyStripe(secret string, body []byte, value string) Verification {
	if value == "" {
		return Verification{Reason: "missing Stripe-Signature header"}
	}

	var timestamp string
	var signatures []string
	for _, part := range strings.Split(value, ",") {
		key, val, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		switch key {
		case "t":
			timestamp = val
		case "v1":
			signatures = append(signatures, val)
		}
	}
	if timestamp == "" || len(signatures) == 0 {
		return Verification{Reason: "Stripe-Signature lacks a timestamp or v1 signature"}
	}

	seconds, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return Verification{Reason: "Stripe-Signature timestamp is not an integer"}
	}
	if skew := time.Since(time.Unix(seconds, 0)); skew > stripeTolerance || skew < -stripeTolerance {
		return Verification{Reason: "Stripe-Signature timestamp is outside the tolerance window"}
	}

	expected := hmacHex(secret, append([]byte(timestamp+"."), body...))
	for _, signature := range signatures {
		if hmac.Equal([]byte(strings.ToLower(signature)), []byte(expected)) {
			return Verification{Verified: true, Reason: "signature verified"}
		}
	}
	return Verification{Reason: "signature mismatch"}
}

func hmacHex(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// ExtractMeta collects whitelisted routing hints for the panel and for filters.
// It never includes the body or any header that may carry credentials.
func ExtractMeta(profile string, header http.Header, body []byte) map[string]any {
	meta := map[string]any{
		"source":       profile,
		"content_type": header.Get("Content-Type"),
		"user_agent":   truncate(header.Get("User-Agent"), 200),
	}
	if meta["source"] == "" || meta["source"] == VerifyNone {
		meta["source"] = "generic"
	}

	switch profile {
	case VerifyGitHub:
		meta["event"] = truncate(header.Get("X-GitHub-Event"), 100)
		meta["delivery"] = truncate(header.Get("X-GitHub-Delivery"), 100)
	case VerifyMeta:
		probe := probeJSON(body)
		meta["event"] = truncate(probe.Object, 100)
		meta["delivery"] = truncate(probe.ID, 100)
	case VerifyStripe:
		probe := probeJSON(body)
		meta["event"] = truncate(probe.Type, 100)
		meta["delivery"] = truncate(probe.ID, 100)
	case VerifyGeneric:
		meta["event"] = truncate(header.Get("X-HookVault-Event"), 100)
	}

	for key, value := range meta {
		if value == "" {
			delete(meta, key)
		}
	}
	return meta
}

type jsonProbe struct {
	Object string `json:"object"`
	Type   string `json:"type"`
	ID     string `json:"id"`
}

func probeJSON(body []byte) jsonProbe {
	if len(body) > maxMetaParseBytes {
		return jsonProbe{}
	}
	var probe jsonProbe
	_ = json.Unmarshal(body, &probe)
	return probe
}

func truncate(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return s[:limit]
}
