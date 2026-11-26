// Package snssig verifies what Amazon SNS signs, and confirms the subscription
// SNS demands before it delivers anything.
//
// SNS signs with an RSA key whose certificate it publishes, so a receiver that
// trusts the certificate in the message has verified nothing: the URL allowlist
// in this package is the security boundary, and the signature is what proves
// the envelope came from AWS once that boundary holds.
package snssig

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Message types SNS delivers to an HTTP endpoint.
const (
	TypeNotification             = "Notification"
	TypeSubscriptionConfirmation = "SubscriptionConfirmation"
	TypeUnsubscribeConfirmation  = "UnsubscribeConfirmation"
)

// maxEnvelopeBytes is SNS's own ceiling for a message body.
const maxEnvelopeBytes = 256 << 10

// Message is the JSON envelope SNS posts. Only the fields used to verify the
// signature and route the message are decoded; the payload stays in the body
// the caller already holds.
type Message struct {
	Type             string `json:"Type"`
	MessageID        string `json:"MessageId"`
	TopicARN         string `json:"TopicArn"`
	Subject          string `json:"Subject"`
	Message          string `json:"Message"`
	Timestamp        string `json:"Timestamp"`
	SignatureVersion string `json:"SignatureVersion"`
	Signature        string `json:"Signature"`
	SigningCertURL   string `json:"SigningCertURL"`
	SubscribeURL     string `json:"SubscribeURL"`
	Token            string `json:"Token"`
}

// Parse decodes an SNS envelope. It does not verify anything.
func Parse(body []byte) (Message, error) {
	if len(body) > maxEnvelopeBytes {
		return Message{}, errors.New("sns: envelope exceeds the SNS size ceiling")
	}
	var message Message
	if err := json.Unmarshal(body, &message); err != nil {
		return Message{}, fmt.Errorf("sns: envelope is not JSON: %w", err)
	}
	if message.Type == "" || message.Signature == "" {
		return Message{}, errors.New("sns: envelope has no Type or Signature")
	}
	return message, nil
}

// StringToSign builds the bytes SNS signs: the documented field set for the
// message type, in byte-sort order, each name and value on its own line and a
// newline after the last one. Subject belongs to a Notification only when the
// publisher set it.
func (m Message) StringToSign() ([]byte, error) {
	var b strings.Builder
	write := func(name, value string) {
		b.WriteString(name)
		b.WriteByte('\n')
		b.WriteString(value)
		b.WriteByte('\n')
	}

	switch m.Type {
	case TypeNotification:
		write("Message", m.Message)
		write("MessageId", m.MessageID)
		if m.Subject != "" {
			write("Subject", m.Subject)
		}
		write("Timestamp", m.Timestamp)
		write("TopicArn", m.TopicARN)
		write("Type", m.Type)
	case TypeSubscriptionConfirmation, TypeUnsubscribeConfirmation:
		write("Message", m.Message)
		write("MessageId", m.MessageID)
		write("SubscribeURL", m.SubscribeURL)
		write("Timestamp", m.Timestamp)
		write("Token", m.Token)
		write("TopicArn", m.TopicARN)
		write("Type", m.Type)
	default:
		return nil, fmt.Errorf("sns: unsupported message type %q", m.Type)
	}
	return []byte(b.String()), nil
}

// CertificateFetcher returns the signing certificate for a URL a message names.
// AWSCertificates is the implementation that belongs in production; tests
// inject their own.
type CertificateFetcher interface {
	Certificate(ctx context.Context, url string) (*x509.Certificate, error)
}

// Verify checks the RSA signature against the certificate at SigningCertURL,
// fetched through certificates. A certificate URL that is not an AWS SNS one is
// refused before anything is fetched.
func (m Message) Verify(ctx context.Context, certificates CertificateFetcher) error {
	if certificates == nil {
		return errors.New("sns: no certificate fetcher configured")
	}
	if err := ValidateCertURL(m.SigningCertURL); err != nil {
		return err
	}

	certificate, err := certificates.Certificate(ctx, m.SigningCertURL)
	if err != nil {
		return err
	}
	public, ok := certificate.PublicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("sns: signing certificate does not carry an RSA key")
	}

	signature, err := base64.StdEncoding.DecodeString(m.Signature)
	if err != nil {
		return errors.New("sns: signature is not base64")
	}
	stringToSign, err := m.StringToSign()
	if err != nil {
		return err
	}

	// SignatureVersion 1 is SHA1 because that is what AWS signs with by
	// default; version 2 is SHA256 and every new topic should opt into it.
	var digest []byte
	var algorithm crypto.Hash
	switch m.SignatureVersion {
	case "1":
		sum := sha1.Sum(stringToSign)
		digest, algorithm = sum[:], crypto.SHA1
	case "2":
		sum := sha256.Sum256(stringToSign)
		digest, algorithm = sum[:], crypto.SHA256
	default:
		return fmt.Errorf("sns: unsupported SignatureVersion %q", m.SignatureVersion)
	}

	if err := rsa.VerifyPKCS1v15(public, algorithm, digest, signature); err != nil {
		return errors.New("sns: signature does not match")
	}
	return nil
}
