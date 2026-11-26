package httpapi_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/atelie-dev/hook-vault/internal/httpapi"
	"github.com/atelie-dev/hook-vault/internal/snssig"
	"github.com/atelie-dev/hook-vault/internal/vault"
)

const (
	snsCertHost     = "sns.sa-east-1.amazonaws.com"
	snsCertURL      = "https://sns.sa-east-1.amazonaws.com/SimpleNotificationService-test.pem"
	snsTopic        = "arn:aws:sns:sa-east-1:123456789012:receita-cbs"
	snsSubscribeURL = "https://sns.sa-east-1.amazonaws.com/?Action=ConfirmSubscription&TopicArn=" + snsTopic + "&Token=t"
)

// snsCertificates stands in for AWS: the certificate is local, so no test
// reaches the network.
type snsCertificates struct{ certificate *x509.Certificate }

func (f snsCertificates) Certificate(context.Context, string) (*x509.Certificate, error) {
	return f.certificate, nil
}

type snsConfirmer struct {
	urls []string
	err  error
}

func (f *snsConfirmer) Confirm(_ context.Context, url string) error {
	f.urls = append(f.urls, url)
	return f.err
}

func snsTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func snsTestCertificate(t *testing.T, key *rsa.PrivateKey) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: snsCertHost},
		DNSNames:     []string{snsCertHost},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return certificate
}

// snsMessage builds and signs an envelope the way SNS would.
func snsMessage(t *testing.T, key *rsa.PrivateKey, fields snssig.Message) []byte {
	t.Helper()
	fields.SigningCertURL = snsCertURL
	fields.SignatureVersion = "2"
	if fields.TopicARN == "" {
		fields.TopicARN = snsTopic
	}
	stringToSign, err := fields.StringToSign()
	if err != nil {
		t.Fatalf("string to sign: %v", err)
	}
	sum := sha256.Sum256(stringToSign)
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	fields.Signature = base64.StdEncoding.EncodeToString(signature)

	body, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return body
}

func storedEvents(t *testing.T, dataPlaneURL string, token string, includeRejected bool) pageView {
	t.Helper()
	url := dataPlaneURL + "/v1/events"
	if includeRejected {
		url += "?include_rejected=true"
	}
	status, body, _ := do(t, http.MethodGet, url, nil,
		map[string]string{"Authorization": "Bearer " + token})
	if status != http.StatusOK {
		t.Fatalf("read events: status %d, body %s", status, body)
	}
	var page pageView
	if err := json.Unmarshal(body, &page); err != nil {
		t.Fatalf("decode page: %v", err)
	}
	return page
}

// TestSNSNotificationIsVerifiedAndStored covers the delivery path: the
// signature is the only thing that makes an SNS body trustworthy, so a bad one
// is evidence, not an event.
func TestSNSNotificationIsVerifiedAndStored(t *testing.T) {
	rsaKey := snsTestKey(t)
	confirmer := &snsConfirmer{}
	dataPlane, controlPlane, _ := newHarnessWith(t, httpapi.Options{
		Certificates: snsCertificates{certificate: snsTestCertificate(t, rsaKey)},
		SNSConfirmer: confirmer,
	})

	key, err := vault.Generate()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	created := createEndpoint(t, controlPlane.URL, key, map[string]any{"verify": "sns"})
	ingestURL := dataPlane.URL + "/in/" + created.Endpoint.Slug

	body := snsMessage(t, rsaKey, snssig.Message{
		Type:      snssig.TypeNotification,
		MessageID: "6a1c2f0e-0000-4000-8000-000000000001",
		Message:   `{"tiqueteSolicitacao":"abc"}`,
		Timestamp: "2026-11-26T12:00:00.000Z",
	})
	status, response, _ := do(t, http.MethodPost, ingestURL, body,
		map[string]string{"Content-Type": "text/plain; charset=UTF-8"})
	if status != http.StatusOK {
		t.Fatalf("sns notification: status %d, body %s", status, response)
	}

	page := storedEvents(t, dataPlane.URL, key.Token, false)
	if len(page.Events) != 1 || page.Events[0].Status != "stored" {
		t.Fatalf("events: %+v", page.Events)
	}
	if got := page.Events[0].Meta["source"]; got != "sns" {
		t.Fatalf("meta.source = %v, want sns", got)
	}
	if got := page.Events[0].Meta["event"]; got != snssig.TypeNotification {
		t.Fatalf("meta.event = %v, want Notification", got)
	}
	if got := page.Events[0].Meta["delivery"]; got != "6a1c2f0e-0000-4000-8000-000000000001" {
		t.Fatalf("meta.delivery = %v", got)
	}

	// A message signed with another key is what a forged delivery looks like.
	forgedKey := snsTestKey(t)
	forged := snsMessage(t, forgedKey, snssig.Message{
		Type:      snssig.TypeNotification,
		MessageID: "6a1c2f0e-0000-4000-8000-000000000002",
		Message:   "forged",
		Timestamp: "2026-11-26T12:00:01.000Z",
	})
	status, _, _ = do(t, http.MethodPost, ingestURL, forged, nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("forged notification: status %d, want 401", status)
	}
	page = storedEvents(t, dataPlane.URL, key.Token, true)
	if len(page.Events) != 2 || page.Events[1].Status != "rejected" {
		t.Fatalf("the forged body was not kept as evidence: %+v", page.Events)
	}
	if len(confirmer.urls) != 0 {
		t.Fatalf("confirmed %d subscriptions for notifications", len(confirmer.urls))
	}
}

// TestSNSNotifiesOnlyAllowedTopics covers what the signature does not: it
// proves AWS sent the message, not that the topic belongs to this endpoint.
func TestSNSNotifiesOnlyAllowedTopics(t *testing.T) {
	rsaKey := snsTestKey(t)
	dataPlane, controlPlane, _ := newHarnessWith(t, httpapi.Options{
		Certificates: snsCertificates{certificate: snsTestCertificate(t, rsaKey)},
		SNSConfirmer: &snsConfirmer{},
	})

	key, err := vault.Generate()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	created := createEndpoint(t, controlPlane.URL, key, map[string]any{
		"verify":     "sns",
		"sns_topics": []string{snsTopic},
	})
	ingestURL := dataPlane.URL + "/in/" + created.Endpoint.Slug

	if got := created.Endpoint.SNSTopics; len(got) != 1 || got[0] != snsTopic {
		t.Fatalf("endpoint reports topics %v", got)
	}

	allowed := snsMessage(t, rsaKey, snssig.Message{
		Type:      snssig.TypeNotification,
		MessageID: "id-allowed",
		Message:   "ok",
		Timestamp: "2026-11-26T12:00:00.000Z",
	})
	if status, body, _ := do(t, http.MethodPost, ingestURL, allowed, nil); status != http.StatusOK {
		t.Fatalf("allowed topic: status %d, body %s", status, body)
	}

	other := snsMessage(t, rsaKey, snssig.Message{
		Type:      snssig.TypeNotification,
		MessageID: "id-other",
		Message:   "not yours",
		Timestamp: "2026-11-26T12:00:01.000Z",
		TopicARN:  "arn:aws:sns:sa-east-1:999999999999:someone-else",
	})
	if status, _, _ := do(t, http.MethodPost, ingestURL, other, nil); status != http.StatusUnauthorized {
		t.Fatalf("foreign topic: status %d, want 401", status)
	}
}

// TestSNSSubscriptionConfirmation follows the operator's choice: automatic
// confirms, manual keeps the confirmation as evidence and touches nothing.
func TestSNSSubscriptionConfirmation(t *testing.T) {
	rsaKey := snsTestKey(t)
	certificates := snsCertificates{certificate: snsTestCertificate(t, rsaKey)}

	for name, tc := range map[string]struct {
		autoConfirm bool
		confirmer   *snsConfirmer
		wantStatus  int
		wantCalls   int
	}{
		"automatic": {autoConfirm: true, confirmer: &snsConfirmer{}, wantStatus: http.StatusOK, wantCalls: 1},
		"manual":    {autoConfirm: false, confirmer: &snsConfirmer{}, wantStatus: http.StatusOK, wantCalls: 0},
		"failure retries": {
			autoConfirm: true,
			confirmer:   &snsConfirmer{err: errors.New("sns answered 500")},
			wantStatus:  http.StatusServiceUnavailable,
			wantCalls:   1,
		},
	} {
		t.Run(name, func(t *testing.T) {
			dataPlane, controlPlane, _ := newHarnessWith(t, httpapi.Options{
				Certificates: certificates,
				SNSConfirmer: tc.confirmer,
			})
			key, err := vault.Generate()
			if err != nil {
				t.Fatalf("generate key: %v", err)
			}
			created := createEndpoint(t, controlPlane.URL, key, map[string]any{
				"verify":           "sns",
				"sns_auto_confirm": tc.autoConfirm,
				"sns_topics":       []string{snsTopic},
			})
			ingestURL := dataPlane.URL + "/in/" + created.Endpoint.Slug

			body := snsMessage(t, rsaKey, snssig.Message{
				Type:         snssig.TypeSubscriptionConfirmation,
				MessageID:    "id-confirm",
				Message:      "please confirm",
				Timestamp:    "2026-11-26T12:00:00.000Z",
				SubscribeURL: snsSubscribeURL,
				Token:        "t",
			})
			status, response, _ := do(t, http.MethodPost, ingestURL, body, nil)
			if status != tc.wantStatus {
				t.Fatalf("status %d, want %d (body %s)", status, tc.wantStatus, response)
			}
			if len(tc.confirmer.urls) != tc.wantCalls {
				t.Fatalf("confirm calls = %v, want %d", tc.confirmer.urls, tc.wantCalls)
			}
			if tc.wantCalls == 1 && tc.confirmer.urls[0] != snsSubscribeURL {
				t.Fatalf("confirmed %q, want %q", tc.confirmer.urls[0], snsSubscribeURL)
			}

			// The confirmation is evidence in every mode, including the one
			// that also acted on it.
			page := storedEvents(t, dataPlane.URL, key.Token, false)
			if len(page.Events) != 1 || page.Events[0].Status != "stored" {
				t.Fatalf("events: %+v", page.Events)
			}
			if got := page.Events[0].Meta["event"]; got != snssig.TypeSubscriptionConfirmation {
				t.Fatalf("meta.event = %v", got)
			}
		})
	}
}

func TestSNSRequiresATopicARNToBeATopicARN(t *testing.T) {
	_, controlPlane, _ := newHarness(t)

	create := func(extra map[string]any) (int, string) {
		key, err := vault.Generate()
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		payload := map[string]any{
			"name":         "receita",
			"public_key":   vault.EncodePublic(key.Public[:]),
			"token_sha256": hex.EncodeToString(vault.HashToken(key.Token)),
		}
		for name, value := range extra {
			payload[name] = value
		}
		body, _ := json.Marshal(payload)
		status, response, _ := do(t, http.MethodPost, controlPlane.URL+"/v1/endpoints", body,
			map[string]string{"Content-Type": "application/json"})
		return status, string(response)
	}

	if status, body := create(map[string]any{
		"verify":     "sns",
		"sns_topics": []string{"not-an-arn"},
	}); status != http.StatusUnprocessableEntity {
		t.Fatalf("invalid topic: status %d, body %s", status, body)
	}

	// SNS fields on another profile are a configuration mistake, not a no-op.
	if status, body := create(map[string]any{
		"verify":           "github",
		"verify_secret":    "s3cr3t",
		"sns_auto_confirm": true,
	}); status != http.StatusUnprocessableEntity {
		t.Fatalf("sns fields on github: status %d, body %s", status, body)
	}

	// SNS has no shared secret, so the profile must be selectable without one.
	if status, body := create(map[string]any{"verify": "sns"}); status != http.StatusCreated {
		t.Fatalf("sns without a secret: status %d, body %s", status, body)
	}
}

// The signature must be over the documented canonical form: this pins the
// version-1 (SHA1) path that every older topic still uses.
func TestSNSSignatureVersion1(t *testing.T) {
	key := snsTestKey(t)
	dataPlane, controlPlane, _ := newHarnessWith(t, httpapi.Options{
		Certificates: snsCertificates{certificate: snsTestCertificate(t, key)},
		SNSConfirmer: &snsConfirmer{},
	})
	apiKey, err := vault.Generate()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	created := createEndpoint(t, controlPlane.URL, apiKey, map[string]any{"verify": "sns"})

	envelope := snssig.Message{
		Type:             snssig.TypeNotification,
		MessageID:        "id-sha1",
		Message:          "hello",
		Timestamp:        "2026-11-26T12:00:00.000Z",
		TopicARN:         snsTopic,
		SigningCertURL:   snsCertURL,
		SignatureVersion: "1",
	}
	stringToSign, err := envelope.StringToSign()
	if err != nil {
		t.Fatalf("string to sign: %v", err)
	}
	sum := sha1.Sum(stringToSign)
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA1, sum[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	envelope.Signature = base64.StdEncoding.EncodeToString(signature)
	body, _ := json.Marshal(envelope)

	status, response, _ := do(t, http.MethodPost, dataPlane.URL+"/in/"+created.Endpoint.Slug, body, nil)
	if status != http.StatusOK {
		t.Fatalf("SignatureVersion 1: status %d, body %s", status, response)
	}
}
