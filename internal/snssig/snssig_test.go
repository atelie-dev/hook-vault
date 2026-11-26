package snssig

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
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"
)

const testCertURL = "https://sns.us-east-1.amazonaws.com/SimpleNotificationService-test.pem"

// testRSAKey is generated once: 2048-bit generation is slow and every case
// signs with the same key, which is what the certificate is for.
func testRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func testCertificate(t *testing.T, key *rsa.PrivateKey, host string) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
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

func pemOf(certificate *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
}

type staticFetcher struct {
	certificate *x509.Certificate
	calls       int
}

func (f *staticFetcher) Certificate(context.Context, string) (*x509.Certificate, error) {
	f.calls++
	return f.certificate, nil
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func response(status int, body []byte) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(string(body))),
		Header:     make(http.Header),
	}
}

// signedNotification returns a valid notification signed the way SNS signs one.
func signedNotification(t *testing.T, key *rsa.PrivateKey, version string) Message {
	t.Helper()
	message := Message{
		Type:             TypeNotification,
		MessageID:        "da41e39f-ea4d-435a-b922-c6aae3915ebe",
		TopicARN:         "arn:aws:sns:us-east-1:123456789012:MyTopic",
		Subject:          "test",
		Message:          "test message",
		Timestamp:        "2012-04-25T21:49:25.719Z",
		SignatureVersion: version,
		SigningCertURL:   testCertURL,
	}
	stringToSign, err := message.StringToSign()
	if err != nil {
		t.Fatalf("string to sign: %v", err)
	}
	message.Signature = signBytes(t, key, version, stringToSign)
	return message
}

func signBytes(t *testing.T, key *rsa.PrivateKey, version string, payload []byte) string {
	t.Helper()
	var signature []byte
	var err error
	switch version {
	case "1":
		sum := sha1.Sum(payload)
		signature, err = rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA1, sum[:])
	case "2":
		sum := sha256.Sum256(payload)
		signature, err = rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	default:
		t.Fatalf("unsupported version %q", version)
	}
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return base64.StdEncoding.EncodeToString(signature)
}

func TestStringToSignMatchesTheDocumentedFields(t *testing.T) {
	base := Message{
		Type:      TypeNotification,
		MessageID: "mid",
		TopicARN:  "arn:aws:sns:us-east-1:123456789012:MyTopic",
		Message:   "hello",
		Timestamp: "2024-01-01T00:00:00.000Z",
	}

	withoutSubject, err := base.StringToSign()
	if err != nil {
		t.Fatalf("string to sign: %v", err)
	}
	want := "Message\nhello\n" +
		"MessageId\nmid\n" +
		"Timestamp\n2024-01-01T00:00:00.000Z\n" +
		"TopicArn\narn:aws:sns:us-east-1:123456789012:MyTopic\n" +
		"Type\nNotification\n"
	if string(withoutSubject) != want {
		t.Fatalf("notification without subject:\n got %q\nwant %q", withoutSubject, want)
	}

	withSubject := base
	withSubject.Subject = "a subject"
	withSubjectBytes, err := withSubject.StringToSign()
	if err != nil {
		t.Fatalf("string to sign: %v", err)
	}
	if !strings.Contains(string(withSubjectBytes), "MessageId\nmid\nSubject\na subject\n") {
		t.Fatalf("subject is not where byte-sort order puts it: %q", withSubjectBytes)
	}

	confirmation := Message{
		Type:         TypeSubscriptionConfirmation,
		MessageID:    "mid",
		Message:      "please confirm",
		SubscribeURL: "https://sns.us-east-1.amazonaws.com/?Action=ConfirmSubscription",
		Timestamp:    "2024-01-01T00:00:00.000Z",
		Token:        "token",
		TopicARN:     "arn:aws:sns:us-east-1:123456789012:MyTopic",
	}
	confirmationBytes, err := confirmation.StringToSign()
	if err != nil {
		t.Fatalf("string to sign: %v", err)
	}
	wantConfirmation := "Message\nplease confirm\n" +
		"MessageId\nmid\n" +
		"SubscribeURL\nhttps://sns.us-east-1.amazonaws.com/?Action=ConfirmSubscription\n" +
		"Timestamp\n2024-01-01T00:00:00.000Z\n" +
		"Token\ntoken\n" +
		"TopicArn\narn:aws:sns:us-east-1:123456789012:MyTopic\n" +
		"Type\nSubscriptionConfirmation\n"
	if string(confirmationBytes) != wantConfirmation {
		t.Fatalf("confirmation:\n got %q\nwant %q", confirmationBytes, wantConfirmation)
	}
}

func TestVerifyAcceptsBothSignatureVersions(t *testing.T) {
	key := testRSAKey(t)
	fetcher := &staticFetcher{certificate: testCertificate(t, key, "sns.us-east-1.amazonaws.com")}

	for _, version := range []string{"1", "2"} {
		message := signedNotification(t, key, version)
		if err := message.Verify(context.Background(), fetcher); err != nil {
			t.Fatalf("SignatureVersion %s: %v", version, err)
		}
	}

	// One byte changed in the payload is a different message.
	tampered := signedNotification(t, key, "2")
	tampered.Message = "test messagE"
	if err := tampered.Verify(context.Background(), fetcher); err == nil {
		t.Fatal("a tampered message verified")
	}

	unknown := signedNotification(t, key, "2")
	unknown.SignatureVersion = "3"
	if err := unknown.Verify(context.Background(), fetcher); err == nil {
		t.Fatal("an unsupported SignatureVersion verified")
	}
}

func TestVerifyRefusesForeignCertificateURLsBeforeFetching(t *testing.T) {
	key := testRSAKey(t)
	fetcher := &staticFetcher{certificate: testCertificate(t, key, "sns.us-east-1.amazonaws.com")}

	for name, url := range map[string]string{
		"plain http":            "http://sns.us-east-1.amazonaws.com/cert.pem",
		"another host":          "https://evil.example.com/cert.pem",
		"suffix after the host": "https://sns.us-east-1.amazonaws.com.evil.example.com/cert.pem",
		"not a certificate":     "https://sns.us-east-1.amazonaws.com/cert.txt",
		"credentials":           "https://user:pass@sns.us-east-1.amazonaws.com/cert.pem",
	} {
		message := signedNotification(t, key, "2")
		message.SigningCertURL = url
		if err := message.Verify(context.Background(), fetcher); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
	if fetcher.calls != 0 {
		t.Fatalf("fetched %d certificates for refused URLs, want 0", fetcher.calls)
	}
}

func TestAWSCertificatesCacheAndExpire(t *testing.T) {
	key := testRSAKey(t)
	certificate := testCertificate(t, key, "sns.us-east-1.amazonaws.com")
	fetches := 0

	cache := NewAWSCertificates()
	cache.client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		fetches++
		return response(http.StatusOK, pemOf(certificate)), nil
	})}
	now := time.Now()
	cache.now = func() time.Time { return now }

	for i := 0; i < 3; i++ {
		got, err := cache.Certificate(context.Background(), testCertURL)
		if err != nil {
			t.Fatalf("certificate: %v", err)
		}
		if !got.Equal(certificate) {
			t.Fatal("cache returned a different certificate")
		}
	}
	if fetches != 1 {
		t.Fatalf("fetched %d times, want 1", fetches)
	}

	now = now.Add(certificateTTL + time.Minute)
	if _, err := cache.Certificate(context.Background(), testCertURL); err != nil {
		t.Fatalf("certificate after expiry: %v", err)
	}
	if fetches != 2 {
		t.Fatalf("fetched %d times after the TTL, want 2", fetches)
	}
}

func TestAWSCertificatesRejectWhatDoesNotLookLikeSNSPublishedIt(t *testing.T) {
	key := testRSAKey(t)

	cases := map[string]struct {
		status      int
		body        []byte
		certificate *x509.Certificate
	}{
		"a 404":                    {status: http.StatusNotFound, body: []byte("nope")},
		"a body that is not a PEM": {status: http.StatusOK, body: []byte("not a certificate")},
		"a certificate for another host": {
			status:      http.StatusOK,
			certificate: testCertificate(t, key, "sns.eu-west-1.amazonaws.com"),
		},
	}

	for name, tc := range cases {
		cache := NewAWSCertificates()
		cache.client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			body := tc.body
			if tc.certificate != nil {
				body = pemOf(tc.certificate)
			}
			return response(tc.status, body), nil
		})}
		if _, err := cache.Certificate(context.Background(), testCertURL); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestAWSCertificatesNeverFetchAForeignHost(t *testing.T) {
	requests := 0
	cache := NewAWSCertificates()
	cache.client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		requests++
		return response(http.StatusOK, nil), nil
	})}

	for _, url := range []string{
		"https://evil.example.com/cert.pem",
		"http://sns.us-east-1.amazonaws.com/cert.pem",
		"https://sns.us-east-1.amazonaws.com/cert.txt",
	} {
		if _, err := cache.Certificate(context.Background(), url); err == nil {
			t.Errorf("%s: accepted", url)
		}
	}
	if requests != 0 {
		t.Fatalf("made %d requests, want 0", requests)
	}
}

func TestHTTPConfirmer(t *testing.T) {
	const subscribeURL = "https://sns.us-east-1.amazonaws.com/?Action=ConfirmSubscription&Token=t"

	confirmer := NewHTTPConfirmer()
	var requested string
	confirmer.client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requested = request.URL.String()
		return response(http.StatusOK, []byte("<ConfirmSubscriptionResponse/>")), nil
	})}

	if err := confirmer.Confirm(context.Background(), subscribeURL); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if requested != subscribeURL {
		t.Fatalf("requested %q, want %q", requested, subscribeURL)
	}

	confirmer.client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusForbidden, nil), nil
	})}
	if err := confirmer.Confirm(context.Background(), subscribeURL); err == nil {
		t.Fatal("a 403 counted as confirmed")
	}

	// A redirect is not followed: it would leave the allowlist.
	confirmer.client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusFound, nil), nil
	})}
	if err := confirmer.Confirm(context.Background(), subscribeURL); err == nil {
		t.Fatal("a redirect counted as confirmed")
	}

	fetched := false
	confirmer.client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		fetched = true
		return response(http.StatusOK, nil), nil
	})}
	if err := confirmer.Confirm(context.Background(), "https://evil.example.com/confirm"); err == nil {
		t.Fatal("a foreign host was confirmed")
	}
	if fetched {
		t.Fatal("a foreign host was called")
	}
}

func TestConfirmMessageOnlyConfirmsConfirmations(t *testing.T) {
	confirmer := NewHTTPConfirmer()
	confirmer.client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("confirmed a message that is not a subscription confirmation")
		return nil, errors.New("unreachable")
	})}

	for _, messageType := range []string{TypeNotification, TypeUnsubscribeConfirmation} {
		message := Message{Type: messageType, SubscribeURL: "https://sns.us-east-1.amazonaws.com/?x=1"}
		if err := ConfirmMessage(context.Background(), confirmer, message); !errors.Is(err, ErrNotConfirmable) {
			t.Fatalf("%s: %v", messageType, err)
		}
	}
}

func TestParseRejectsAnEnvelopeWithoutSignature(t *testing.T) {
	if _, err := Parse([]byte(`{"Type":"Notification"}`)); err == nil {
		t.Fatal("parsed an envelope with no signature")
	}
	if _, err := Parse([]byte(`not json`)); err == nil {
		t.Fatal("parsed a body that is not JSON")
	}
}
