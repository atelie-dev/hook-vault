package snssig

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// awsSNSHost is the only family of hosts this package will fetch from: the
// partition SNS publishes signing certificates and subscription URLs on, plus
// the China partition. Anything else in the message is data an attacker chose,
// so it is refused before a request exists.
var awsSNSHost = regexp.MustCompile(`^sns\.[a-z0-9-]+\.amazonaws\.com(\.cn)?$`)

const (
	maxCertificateBytes = 64 << 10
	certificateTTL      = 6 * time.Hour
	// fetchTimeout is per fetch. SNS gives an endpoint about fifteen seconds
	// to answer a delivery, and the certificate is cached after the first one.
	fetchTimeout = 5 * time.Second
)

// ValidateCertURL refuses anything but an https certificate URL on an AWS SNS
// host: following a SigningCertURL is trusting the message to choose where the
// trust comes from.
func ValidateCertURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return errors.New("sns: SigningCertURL is not a URL")
	}
	if parsed.Scheme != "https" {
		return errors.New("sns: SigningCertURL is not https")
	}
	if parsed.User != nil {
		return errors.New("sns: SigningCertURL carries credentials")
	}
	if !awsSNSHost.MatchString(parsed.Hostname()) {
		return errors.New("sns: SigningCertURL is not an AWS SNS host")
	}
	if !strings.HasSuffix(parsed.Path, ".pem") {
		return errors.New("sns: SigningCertURL does not point at a certificate")
	}
	return nil
}

// ValidateSubscriptionURL refuses anything but an https SubscribeURL on an AWS
// SNS host. It is the same boundary as ValidateCertURL: the URL comes from an
// unauthenticated POST until the signature has been checked.
func ValidateSubscriptionURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return errors.New("sns: SubscribeURL is not a URL")
	}
	if parsed.Scheme != "https" {
		return errors.New("sns: SubscribeURL is not https")
	}
	if parsed.User != nil {
		return errors.New("sns: SubscribeURL carries credentials")
	}
	if !awsSNSHost.MatchString(parsed.Hostname()) {
		return errors.New("sns: SubscribeURL is not an AWS SNS host")
	}
	return nil
}

// AWSCertificates fetches SNS signing certificates over HTTPS and caches them.
// The certificate rotates on AWS's schedule, not per message, and SNS delivers
// with a short deadline — a fetch per delivery would be both slow and pointless.
type AWSCertificates struct {
	client *http.Client
	ttl    time.Duration
	now    func() time.Time

	mu      sync.Mutex
	entries map[string]certificateEntry
}

type certificateEntry struct {
	certificate *x509.Certificate
	expires     time.Time
}

// NewAWSCertificates returns a cache with the production client: no redirects
// (a redirect would leave the allowlist), and a timeout short enough to answer
// SNS.
func NewAWSCertificates() *AWSCertificates {
	return &AWSCertificates{
		client: &http.Client{
			Timeout: fetchTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		ttl:     certificateTTL,
		now:     time.Now,
		entries: make(map[string]certificateEntry),
	}
}

// Certificate returns the certificate at a validated AWS URL, from the cache
// when it is still fresh.
func (c *AWSCertificates) Certificate(ctx context.Context, rawURL string) (*x509.Certificate, error) {
	if err := ValidateCertURL(rawURL); err != nil {
		return nil, err
	}

	c.mu.Lock()
	entry, cached := c.entries[rawURL]
	c.mu.Unlock()
	if cached && c.now().Before(entry.expires) {
		return entry.certificate, nil
	}

	certificate, err := c.fetch(ctx, rawURL)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.entries[rawURL] = certificateEntry{certificate: certificate, expires: c.now().Add(c.ttl)}
	c.mu.Unlock()
	return certificate, nil
}

func (c *AWSCertificates) fetch(ctx context.Context, rawURL string) (*x509.Certificate, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("sns: build certificate request: %w", err)
	}
	response, err := c.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("sns: fetch signing certificate: %w", err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sns: signing certificate answered %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxCertificateBytes+1))
	if err != nil {
		return nil, fmt.Errorf("sns: read signing certificate: %w", err)
	}
	if len(body) > maxCertificateBytes {
		return nil, errors.New("sns: signing certificate is larger than any SNS certificate")
	}

	block, _ := pem.Decode(body)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("sns: signing certificate is not a PEM certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("sns: parse signing certificate: %w", err)
	}
	if err := checkCertificate(certificate, rawURL, c.now()); err != nil {
		return nil, err
	}
	return certificate, nil
}

// checkCertificate holds the certificate to what AWS publishes: a live
// certificate issued for the host the message points at.
//
// The chain is not walked. Transport TLS already authenticated the host it was
// fetched from, and that host is allowlisted; a root bundle pinned here would
// be a new thing to keep current, for no boundary the allowlist does not
// already hold. That is a decision, not an oversight.
func checkCertificate(certificate *x509.Certificate, rawURL string, now time.Time) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return errors.New("sns: SigningCertURL is not a URL")
	}
	if now.Before(certificate.NotBefore) || now.After(certificate.NotAfter) {
		return errors.New("sns: signing certificate is not valid now")
	}
	if len(certificate.DNSNames) > 0 {
		if err := certificate.VerifyHostname(parsed.Hostname()); err != nil {
			return errors.New("sns: signing certificate is not for the SigningCertURL host")
		}
		return nil
	}
	if certificate.Subject.CommonName != parsed.Hostname() {
		return errors.New("sns: signing certificate is not for the SigningCertURL host")
	}
	return nil
}
