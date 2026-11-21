package httpapi_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/atelie-dev/hook-vault/internal/store"
	"github.com/atelie-dev/hook-vault/internal/vault"
)

// The read API's `since` window is resolved against the database clock, which is
// the clock that stamped received_at.
func TestSinceFiltersByReceivedAt(t *testing.T) {
	dataPlane, controlPlane, st := newHarness(t)
	ctx := context.Background()

	key, err := vault.Generate()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	created := createEndpoint(t, controlPlane.URL, key, map[string]any{"verify": "none"})

	for i := 0; i < 3; i++ {
		sealed, err := vault.SealTo([]byte(fmt.Sprintf(`{"n":%d}`, i)), &key.Public)
		if err != nil {
			t.Fatalf("seal: %v", err)
		}
		if _, err := st.InsertEvent(ctx, store.InsertEventParams{
			EndpointID: created.Endpoint.ID,
			KID:        key.KID,
			Ciphertext: sealed,
			SizeBytes:  len(sealed),
		}); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}

	// Backdate the two oldest by two hours.
	if _, err := st.Pool().Exec(ctx, `
		update event set received_at = now() - interval '2 hours'
		 where endpoint_id = $1::uuid
		   and id < (select id from event where endpoint_id = $1::uuid order by id desc limit 1)`,
		created.Endpoint.ID); err != nil {
		t.Fatalf("backdate: %v", err)
	}

	auth := map[string]string{"Authorization": "Bearer " + key.Token}

	fetch := func(query string) (int, pageView, error) {
		status, body, _ := do(t, http.MethodGet, dataPlane.URL+"/v1/events?"+query, nil, auth)
		if status != http.StatusOK {
			return status, pageView{}, fmt.Errorf("status %d: %s", status, body)
		}
		var page pageView
		if err := json.Unmarshal(body, &page); err != nil {
			return status, pageView{}, err
		}
		return status, page, nil
	}

	_, page, err := fetch("since=1h")
	if err != nil {
		t.Fatalf("since=1h: %v", err)
	}
	if len(page.Events) != 1 {
		t.Fatalf("since=1h returned %d events, want 1", len(page.Events))
	}

	_, page, err = fetch("since=3h")
	if err != nil {
		t.Fatalf("since=3h: %v", err)
	}
	if len(page.Events) != 3 {
		t.Fatalf("since=3h returned %d events, want 3", len(page.Events))
	}

	// The kubectl-like word form works too.
	_, page, err = fetch("since=1hour")
	if err != nil {
		t.Fatalf("since=1hour: %v", err)
	}
	if len(page.Events) != 1 {
		t.Fatalf("since=1hour returned %d events, want 1", len(page.Events))
	}

	// Garbage is a 400 with a readable message, not a silent empty page.
	status, body, _ := do(t, http.MethodGet, dataPlane.URL+"/v1/events?since=banana", nil, auth)
	if status != http.StatusBadRequest {
		t.Fatalf("since=banana: status %d, body %s", status, body)
	}
	if !strings.Contains(string(body), "invalid_since") {
		t.Fatalf("error code missing: %s", body)
	}
}
