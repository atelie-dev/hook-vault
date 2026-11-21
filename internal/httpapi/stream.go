package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/atelie-dev/hook-vault/internal/store"
)

// Stream tuning. A page is drained in one query, so a burst costs one query per
// page rather than one per event. The fallback ticker only matters with more
// than one replica: the wake signal is in-process, so an event committed by
// another instance is picked up by the next tick instead of never.
const (
	streamPageSize     = 200
	streamFallback     = time.Second
	streamHeartbeat    = 15 * time.Second
	streamWriteTimeout = 30 * time.Second
	streamRetryMillis  = 2000
)

// handleEventsStream pushes events as they are committed, using server-sent
// events. Ciphertext in, ciphertext out, same as GET /v1/events: the frame's
// data is the same DTO, and its `id` is the cursor to resume from.
//
// Ordering is the whole point. Frames leave in id order because
// store.InsertEvent assigns ids under the endpoint's row lock, so a client that
// persists the last `id` can never advance past a row that commits later
// (AGENTS invariant 4).
func (s *Server) handleEventsStream(w http.ResponseWriter, r *http.Request) {
	endpoint, _, ok := s.authenticate(w, r)
	if !ok {
		return
	}

	cursor, err := streamCursor(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_cursor", err.Error())
		return
	}
	includeRejected := r.URL.Query().Get("include_rejected") == "true"

	rc := http.NewResponseController(w)
	header := w.Header()
	header.Set("Content-Type", "text/event-stream")
	header.Set("Cache-Control", "no-cache")
	// Caddy and nginx buffer by default; a buffered stream is a poll with extra
	// steps.
	header.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	if _, err := fmt.Fprintf(w, "retry: %d\n\n", streamRetryMillis); err != nil {
		return
	}
	if err := rc.Flush(); err != nil {
		return
	}

	ctx := r.Context()
	poll := time.NewTicker(streamFallback)
	defer poll.Stop()
	ping := time.NewTicker(streamHeartbeat)
	defer ping.Stop()

	for {
		for {
			page, hasMore, err := s.store.FetchEvents(ctx, store.FetchParams{
				EndpointID:      endpoint.ID,
				Cursor:          cursor,
				Limit:           streamPageSize,
				Lag:             s.readLag,
				IncludeRejected: includeRejected,
			})
			if err != nil {
				// The status line is long gone; the only honest move is to end the
				// stream and let the client reconnect with its cursor.
				s.logger.Error("stream fetch events", "endpoint", endpoint.ID, "error", err)
				return
			}
			if len(page) == 0 {
				break
			}
			if err := rc.SetWriteDeadline(time.Now().Add(streamWriteTimeout)); err != nil &&
				!errors.Is(err, http.ErrNotSupported) {
				return
			}
			for _, event := range page {
				if err := writeStreamEvent(w, s.toDTO(event)); err != nil {
					return
				}
				cursor = &event.ID
			}
			if err := rc.Flush(); err != nil {
				return
			}
			if !hasMore {
				break
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-s.wake:
		case <-poll.C:
		case <-ping.C:
			if _, err := io.WriteString(w, ": ping\n\n"); err != nil {
				return
			}
			if err := rc.Flush(); err != nil {
				return
			}
		}
	}
}

// writeStreamEvent frames one event. `id` is what an EventSource sends back as
// Last-Event-ID on reconnect, and what a hand-written client stores as cursor.
func writeStreamEvent(w io.Writer, event eventDTO) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "id: %s\nevent: event\ndata: %s\n\n", event.ID, payload)
	return err
}

// streamCursor reads the resume point: ?cursor= on a first connect, or the
// Last-Event-ID header a browser sends on its own when it reconnects.
func streamCursor(r *http.Request) (*string, error) {
	raw := r.URL.Query().Get("cursor")
	if raw == "" {
		raw = r.Header.Get("Last-Event-ID")
	}
	if raw == "" {
		return nil, nil
	}
	if !validUUID(raw) {
		return nil, errors.New("cursor must be an event id returned by this API")
	}
	return &raw, nil
}
