// Package retention enforces each endpoint's storage policy.
//
// Two independent limits, both optional:
//
//   - retention_days: delete events older than N days;
//   - max_bytes: delete the oldest events until the endpoint fits.
//
// The size policy evicts rather than rejects. Answering a provider with a 5xx
// because a disk is full turns one lost batch into an amplification event: the
// provider retries, more bodies arrive, nothing fits, and the backlog grows.
package retention

import (
	"context"
	"log/slog"
	"time"

	"github.com/atelie-dev/hook-vault/internal/store"
)

// batchSize bounds one delete statement so retention work never holds a long
// transaction or bloats the table faster than autovacuum can keep up.
const batchSize = 5000

// Sweeper applies retention policies on a timer.
type Sweeper struct {
	store  *store.Store
	logger *slog.Logger
}

// New builds a Sweeper.
func New(st *store.Store, logger *slog.Logger) *Sweeper {
	if logger == nil {
		logger = slog.Default()
	}
	return &Sweeper{store: st, logger: logger}
}

// Run sweeps until the context is cancelled.
func (s *Sweeper) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	s.Sweep(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.Sweep(ctx)
		}
	}
}

// Sweep applies every endpoint's policy once.
func (s *Sweeper) Sweep(ctx context.Context) {
	endpoints, err := s.store.ListEndpoints(ctx)
	if err != nil {
		s.logger.Error("retention: list endpoints", "error", err)
		return
	}

	for _, endpoint := range endpoints {
		if ctx.Err() != nil {
			return
		}
		if endpoint.DisabledAt != nil {
			continue
		}
		if endpoint.RetentionDays != nil {
			s.applyAge(ctx, endpoint)
		}
		if endpoint.MaxBytes != nil {
			s.applySize(ctx, endpoint)
		}
	}
}

func (s *Sweeper) applyAge(ctx context.Context, endpoint store.Endpoint) {
	age := time.Duration(*endpoint.RetentionDays) * 24 * time.Hour

	for ctx.Err() == nil {
		rows, bytes, err := s.store.DeleteOlderThan(ctx, endpoint.ID, age, batchSize)
		if err != nil {
			s.logger.Error("retention: delete by age", "endpoint", endpoint.ID, "error", err)
			return
		}
		if rows > 0 {
			s.logger.Info("retention: expired events removed",
				"endpoint", endpoint.ID, "events", rows, "bytes", bytes)
		}
		if rows < batchSize {
			return
		}
	}
}

func (s *Sweeper) applySize(ctx context.Context, endpoint store.Endpoint) {
	for ctx.Err() == nil {
		// Re-read the counter: the write path moves it between batches, and
		// guessing would either over-evict or loop forever.
		current, err := s.store.EndpointByID(ctx, endpoint.ID)
		if err != nil {
			s.logger.Error("retention: reload endpoint", "endpoint", endpoint.ID, "error", err)
			return
		}
		if current.MaxBytes == nil || current.BytesUsed <= *current.MaxBytes {
			return
		}

		rows, bytes, err := s.store.EvictOldest(ctx, current.ID, batchSize)
		if err != nil {
			s.logger.Error("retention: evict oldest", "endpoint", current.ID, "error", err)
			return
		}
		if rows == 0 {
			return
		}
		s.logger.Warn("retention: size policy evicting history",
			"endpoint", current.ID, "events", rows, "bytes", bytes,
			"bytes_used", current.BytesUsed, "max_bytes", *current.MaxBytes)
	}
}
