package snssig

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// confirmTimeout bounds the GET that confirms a subscription. SNS gives an
// endpoint about fifteen seconds; this leaves room for the rest of the answer.
const confirmTimeout = 10 * time.Second

// Confirmer performs the GET SNS requires before it delivers anything: a
// subscription stays pending until the endpoint fetches the SubscribeURL that
// the confirmation message carries.
type Confirmer interface {
	Confirm(ctx context.Context, subscribeURL string) error
}

// HTTPConfirmer is the production Confirmer. It refuses redirects (a redirect
// would step outside the host allowlist) and ignores the XML body, because only
// the status says whether AWS accepted the confirmation.
type HTTPConfirmer struct {
	client *http.Client
}

// NewHTTPConfirmer returns a Confirmer with the production client.
func NewHTTPConfirmer() *HTTPConfirmer {
	return &HTTPConfirmer{
		client: &http.Client{
			Timeout: confirmTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Confirm fetches a validated SubscribeURL.
func (c *HTTPConfirmer) Confirm(ctx context.Context, subscribeURL string) error {
	if err := ValidateSubscriptionURL(subscribeURL); err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, subscribeURL, nil)
	if err != nil {
		return fmt.Errorf("sns: build confirmation request: %w", err)
	}
	response, err := c.client.Do(request)
	if err != nil {
		return fmt.Errorf("sns: confirm subscription: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	// Drain a bounded amount so the connection can be reused; the body is XML
	// nobody acts on.
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))

	if response.StatusCode/100 != 2 {
		return fmt.Errorf("sns: confirmation answered %d", response.StatusCode)
	}
	return nil
}

// ErrNotConfirmable is returned by Confirm when a message is not a subscription
// confirmation. It keeps the caller from confirming an unsubscribe, which would
// be the opposite of what the message asked for.
var ErrNotConfirmable = errors.New("sns: message is not a subscription confirmation")

// ConfirmMessage confirms a parsed subscription confirmation. The caller is
// expected to have verified the signature first: confirming proves the endpoint
// is reachable, and it subscribes the endpoint to the topic.
func ConfirmMessage(ctx context.Context, confirmer Confirmer, message Message) error {
	if confirmer == nil {
		return errors.New("sns: no confirmer configured")
	}
	if message.Type != TypeSubscriptionConfirmation {
		return ErrNotConfirmable
	}
	return confirmer.Confirm(ctx, message.SubscribeURL)
}
