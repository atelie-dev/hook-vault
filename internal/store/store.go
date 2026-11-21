// Package store owns every SQL statement. The rest of hook-vault treats it as
// the only place that knows the schema.
package store

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store is a PostgreSQL-backed hook-vault database.
type Store struct {
	pool *pgxpool.Pool
}

// Open connects and verifies the connection is usable.
func Open(ctx context.Context, dsn string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse database-url: %w", err)
	}
	cfg.MaxConns = 10
	cfg.ConnConfig.RuntimeParams["application_name"] = "hook-vault"

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Close releases the pool.
func (s *Store) Close() { s.pool.Close() }

// Pool exposes the pool to tests.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Endpoint is a webhook destination with its storage and verification policy.
type Endpoint struct {
	ID            string
	Slug          string
	Name          string
	RetentionDays *int
	MaxBytes      *int64
	BytesUsed     int64
	EventsUsed    int64
	EvictedEvents int64
	Verify        string
	VerifySecret  *string
	VerifyToken   *string
	CreatedAt     time.Time
	DisabledAt    *time.Time
	ActiveKID     *string
}

// Key is one recipient key pair registered on an endpoint. The server knows
// only the public half.
type Key struct {
	EndpointID  string
	KID         string
	PublicKey   []byte
	TokenSHA256 []byte
	CreatedAt   time.Time
	RevokedAt   *time.Time
}

// Event is one stored webhook. Ciphertext is opaque to the server.
type Event struct {
	ID         string
	ReceivedAt time.Time
	KID        string
	Alg        string
	Ciphertext []byte
	SizeBytes  int
	Status     string
	Meta       json.RawMessage
}

// Bucket is one hour of ingest statistics.
type Bucket struct {
	Start    time.Time
	Events   int64
	Rejected int64
	Bytes    int64
}

var slugEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// NewSlug returns a 128-bit URL-safe path segment. It is not the authentication
// (the provider signature is), only a shield against background scanning.
func NewSlug() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate slug: %w", err)
	}
	return slugEncoding.EncodeToString(raw[:]), nil
}

const endpointSelect = `
	select e.id::text, e.slug, e.name, e.retention_days, e.max_bytes,
	       e.bytes_used, e.events_used, e.evicted_events,
	       e.verify, e.verify_secret, e.verify_token,
	       e.created_at, e.disabled_at,
	       (select k.kid from endpoint_key k
	         where k.endpoint_id = e.id and k.revoked_at is null
	         order by k.created_at desc
	         limit 1)
	  from endpoint e`

type rowScanner interface {
	Scan(dest ...any) error
}

func scanEndpoint(row rowScanner) (Endpoint, error) {
	var ep Endpoint
	err := row.Scan(&ep.ID, &ep.Slug, &ep.Name, &ep.RetentionDays, &ep.MaxBytes,
		&ep.BytesUsed, &ep.EventsUsed, &ep.EvictedEvents,
		&ep.Verify, &ep.VerifySecret, &ep.VerifyToken,
		&ep.CreatedAt, &ep.DisabledAt, &ep.ActiveKID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Endpoint{}, ErrNotFound
	}
	if err != nil {
		return Endpoint{}, fmt.Errorf("scan endpoint: %w", err)
	}
	return ep, nil
}

// CreateEndpointParams describes a new endpoint. An empty Slug gets a
// generated one.
type CreateEndpointParams struct {
	Slug          string
	Name          string
	RetentionDays *int
	MaxBytes      *int64
	Verify        string
	VerifySecret  *string
	VerifyToken   *string
}

// CreateEndpoint inserts an endpoint. A caller that let the database default
// the slug gets the generated one back.
func (s *Store) CreateEndpoint(ctx context.Context, p CreateEndpointParams) (Endpoint, error) {
	slug := p.Slug
	if slug == "" {
		generated, err := NewSlug()
		if err != nil {
			return Endpoint{}, err
		}
		slug = generated
	}
	verify := p.Verify
	if verify == "" {
		verify = "none"
	}

	var id string
	err := s.pool.QueryRow(ctx, `
		insert into endpoint (slug, name, retention_days, max_bytes, verify, verify_secret, verify_token)
		values ($1, $2, $3, $4, $5, $6, $7)
		returning id::text`,
		slug, p.Name, p.RetentionDays, p.MaxBytes, verify, p.VerifySecret, p.VerifyToken,
	).Scan(&id)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return Endpoint{}, fmt.Errorf("endpoint slug %q already exists", slug)
		}
		return Endpoint{}, fmt.Errorf("create endpoint: %w", err)
	}
	return s.EndpointByID(ctx, id)
}

// CreateEndpointWithKey creates the endpoint and registers its first recipient
// key in one statement, so a failure cannot leave behind an endpoint that has
// no key and therefore cannot seal anything.
func (s *Store) CreateEndpointWithKey(ctx context.Context, p CreateEndpointParams, kid string, publicKey, tokenSHA256 []byte) (Endpoint, error) {
	slug := p.Slug
	if slug == "" {
		generated, err := NewSlug()
		if err != nil {
			return Endpoint{}, err
		}
		slug = generated
	}
	verify := p.Verify
	if verify == "" {
		verify = "none"
	}

	var id string
	err := s.pool.QueryRow(ctx, `
		with ep as (
			insert into endpoint (slug, name, retention_days, max_bytes, verify, verify_secret, verify_token)
			values ($1, $2, $3, $4, $5, $6, $7)
			returning id
		), key as (
			insert into endpoint_key (endpoint_id, kid, public_key, token_sha256)
			select id, $8, $9, $10 from ep
		)
		select id::text from ep`,
		slug, p.Name, p.RetentionDays, p.MaxBytes, verify, p.VerifySecret, p.VerifyToken,
		kid, publicKey, tokenSHA256,
	).Scan(&id)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			switch pgErr.ConstraintName {
			case "endpoint_key_token_idx":
				return Endpoint{}, ErrTokenInUse
			case "endpoint_slug_key":
				return Endpoint{}, fmt.Errorf("endpoint slug %q already exists", slug)
			}
		}
		return Endpoint{}, fmt.Errorf("create endpoint: %w", err)
	}
	return s.EndpointByID(ctx, id)
}

// EndpointByID loads one endpoint.
func (s *Store) EndpointByID(ctx context.Context, id string) (Endpoint, error) {
	return scanEndpoint(s.pool.QueryRow(ctx, endpointSelect+` where e.id = $1::uuid`, id))
}

// EndpointBySlug powers the ingest path.
func (s *Store) EndpointBySlug(ctx context.Context, slug string) (Endpoint, error) {
	return scanEndpoint(s.pool.QueryRow(ctx, endpointSelect+` where e.slug = $1`, slug))
}

// ListEndpoints returns every endpoint, oldest first.
func (s *Store) ListEndpoints(ctx context.Context) ([]Endpoint, error) {
	rows, err := s.pool.Query(ctx, endpointSelect+` order by e.created_at`)
	if err != nil {
		return nil, fmt.Errorf("list endpoints: %w", err)
	}
	defer rows.Close()

	var out []Endpoint
	for rows.Next() {
		ep, err := scanEndpoint(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ep)
	}
	return out, rows.Err()
}

// EndpointPatch updates only the fields whose pointer is not nil.
//
// RetentionDays and MaxBytes use 0 to clear the limit and nil to leave it
// untouched; VerifySecret and VerifyToken use "" to clear.
type EndpointPatch struct {
	Name          *string
	RetentionDays *int
	MaxBytes      *int64
	Verify        *string
	VerifySecret  *string
	VerifyToken   *string
	Disabled      *bool
}

// UpdateEndpoint applies a patch and returns the stored row.
func (s *Store) UpdateEndpoint(ctx context.Context, id string, p EndpointPatch) (Endpoint, error) {
	var updated string
	err := s.pool.QueryRow(ctx, `
		update endpoint e set
			name = coalesce($2, e.name),
			retention_days = case when $3::int is null then e.retention_days
			                      when $3 = 0 then null else $3 end,
			max_bytes = case when $4::bigint is null then e.max_bytes
			                 when $4 = 0 then null else $4 end,
			verify = coalesce($5, e.verify),
			verify_secret = case when $6::text is null then e.verify_secret
			                     when $6 = '' then null else $6 end,
			verify_token = case when $7::text is null then e.verify_token
			                    when $7 = '' then null else $7 end,
			disabled_at = case when $8::boolean is null then e.disabled_at
			                   when $8 then coalesce(e.disabled_at, now()) else null end
		where e.id = $1::uuid
		returning e.id::text`,
		id, p.Name, p.RetentionDays, p.MaxBytes, p.Verify, p.VerifySecret, p.VerifyToken, p.Disabled,
	).Scan(&updated)
	if errors.Is(err, pgx.ErrNoRows) {
		return Endpoint{}, ErrNotFound
	}
	if err != nil {
		return Endpoint{}, fmt.Errorf("update endpoint: %w", err)
	}
	return s.EndpointByID(ctx, updated)
}

// RegisterKey adds a recipient public key and the hash of the token derived
// from the matching secret key. Re-registering the same kid revives it.
func (s *Store) RegisterKey(ctx context.Context, endpointID, kid string, publicKey, tokenSHA256 []byte) (Key, error) {
	var k Key
	err := s.pool.QueryRow(ctx, `
		insert into endpoint_key (endpoint_id, kid, public_key, token_sha256)
		values ($1::uuid, $2, $3, $4)
		on conflict (endpoint_id, kid) do update
			set public_key = excluded.public_key,
			    token_sha256 = excluded.token_sha256,
			    revoked_at = null
		returning endpoint_id::text, kid, public_key, token_sha256, created_at, revoked_at`,
		endpointID, kid, publicKey, tokenSHA256,
	).Scan(&k.EndpointID, &k.KID, &k.PublicKey, &k.TokenSHA256, &k.CreatedAt, &k.RevokedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.ConstraintName == "endpoint_key_token_idx" {
			return Key{}, ErrTokenInUse
		}
		return Key{}, fmt.Errorf("register key: %w", err)
	}
	return k, nil
}

// RevokeKey stops a key from authenticating. Events it sealed remain readable
// with the old secret key, which is why revocation is not deletion.
func (s *Store) RevokeKey(ctx context.Context, endpointID, kid string) error {
	tag, err := s.pool.Exec(ctx, `
		update endpoint_key set revoked_at = now()
		where endpoint_id = $1::uuid and kid = $2 and revoked_at is null`, endpointID, kid)
	if err != nil {
		return fmt.Errorf("revoke key: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

const keySelect = `
	select endpoint_id::text, kid, public_key, token_sha256, created_at, revoked_at
	from endpoint_key`

func scanKey(row rowScanner) (Key, error) {
	var k Key
	err := row.Scan(&k.EndpointID, &k.KID, &k.PublicKey, &k.TokenSHA256, &k.CreatedAt, &k.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Key{}, ErrNotFound
	}
	if err != nil {
		return Key{}, fmt.Errorf("scan key: %w", err)
	}
	return k, nil
}

// ActiveKey returns the newest non-revoked key, which is the one that seals new
// events.
func (s *Store) ActiveKey(ctx context.Context, endpointID string) (Key, error) {
	return scanKey(s.pool.QueryRow(ctx, keySelect+`
		where endpoint_id = $1::uuid and revoked_at is null
		order by created_at desc limit 1`, endpointID))
}

// ListKeys returns every key registered on an endpoint, newest first.
func (s *Store) ListKeys(ctx context.Context, endpointID string) ([]Key, error) {
	rows, err := s.pool.Query(ctx, keySelect+`
		where endpoint_id = $1::uuid order by created_at desc`, endpointID)
	if err != nil {
		return nil, fmt.Errorf("list keys: %w", err)
	}
	defer rows.Close()

	var out []Key
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// EndpointByTokenHash authenticates a read request. The token itself never
// reaches the database, only its digest.
func (s *Store) EndpointByTokenHash(ctx context.Context, hash []byte) (Endpoint, Key, error) {
	const q = `
		select k.endpoint_id::text, k.kid, k.public_key, k.token_sha256, k.created_at, k.revoked_at,
		       e.id::text, e.slug, e.name, e.retention_days, e.max_bytes,
		       e.bytes_used, e.events_used, e.evicted_events,
		       e.verify, e.verify_secret, e.verify_token, e.created_at, e.disabled_at
		  from endpoint_key k
		  join endpoint e on e.id = k.endpoint_id
		 where k.token_sha256 = $1 and k.revoked_at is null and e.disabled_at is null`

	var k Key
	var ep Endpoint
	err := s.pool.QueryRow(ctx, q, hash).Scan(
		&k.EndpointID, &k.KID, &k.PublicKey, &k.TokenSHA256, &k.CreatedAt, &k.RevokedAt,
		&ep.ID, &ep.Slug, &ep.Name, &ep.RetentionDays, &ep.MaxBytes,
		&ep.BytesUsed, &ep.EventsUsed, &ep.EvictedEvents,
		&ep.Verify, &ep.VerifySecret, &ep.VerifyToken, &ep.CreatedAt, &ep.DisabledAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Endpoint{}, Key{}, ErrNotFound
	}
	if err != nil {
		return Endpoint{}, Key{}, fmt.Errorf("authenticate token: %w", err)
	}
	ep.ActiveKID = &k.KID
	return ep, k, nil
}

// InsertEventParams is one sealed webhook.
type InsertEventParams struct {
	EndpointID string
	KID        string
	Ciphertext []byte
	SizeBytes  int
	Status     string
	Meta       []byte
}

// InsertEvent stores the ciphertext and bumps the endpoint counters in the same
// statement, so quota accounting cannot drift from the rows.
func (s *Store) InsertEvent(ctx context.Context, p InsertEventParams) (string, error) {
	if len(p.Meta) == 0 {
		p.Meta = []byte(`{}`)
	}
	status := p.Status
	if status == "" {
		status = "stored"
	}

	var id string
	err := s.pool.QueryRow(ctx, `
		with ins as (
			insert into event (endpoint_id, kid, ciphertext, size_bytes, status, meta)
			values ($1::uuid, $2, $3, $4, $5, $6::jsonb)
			returning id::text, size_bytes
		), bump as (
			update endpoint e
			   set bytes_used = e.bytes_used + (select size_bytes from ins),
			       events_used = e.events_used + 1
			 where e.id = $1::uuid
		)
		select id from ins`,
		p.EndpointID, p.KID, p.Ciphertext, p.SizeBytes, status, string(p.Meta),
	).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("insert event: %w", err)
	}
	return id, nil
}

// FetchParams selects a page of events for one endpoint.
type FetchParams struct {
	EndpointID      string
	Cursor          *string
	Since           *time.Time
	Limit           int
	Lag             time.Duration
	IncludeRejected bool
}

// FetchEvents returns up to Limit events after Cursor in id order.
//
// The received_at bound keeps the API Lag behind now: an id can be assigned
// before its transaction commits, and without the bound a reader could advance
// its cursor past a row that becomes visible a moment later.
func (s *Store) FetchEvents(ctx context.Context, p FetchParams) ([]Event, bool, error) {
	rows, err := s.pool.Query(ctx, `
		select id::text, received_at, coalesce(kid, ''), alg, ciphertext, size_bytes, status, meta
		  from event
		 where endpoint_id = $1::uuid
		   and received_at < now() - make_interval(secs => $2)
		   and ($3::text is null or id > $3::uuid)
		   and ($4::boolean or status = 'stored')
		   and ($5::timestamptz is null or received_at >= $5)
		 order by id
		 limit $6`,
		p.EndpointID, p.Lag.Seconds(), p.Cursor, p.IncludeRejected, p.Since, p.Limit+1)
	if err != nil {
		return nil, false, fmt.Errorf("fetch events: %w", err)
	}
	defer rows.Close()

	var out []Event
	for rows.Next() {
		var ev Event
		if err := rows.Scan(&ev.ID, &ev.ReceivedAt, &ev.KID, &ev.Alg,
			&ev.Ciphertext, &ev.SizeBytes, &ev.Status, &ev.Meta); err != nil {
			return nil, false, fmt.Errorf("scan event: %w", err)
		}
		out = append(out, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}

	hasMore := len(out) > p.Limit
	if hasMore {
		out = out[:p.Limit]
	}
	return out, hasMore, nil
}

// Watermark returns the oldest id still stored, which lets a consumer detect
// that it fell out of the retention window. nil means the endpoint is empty
// (or everything was already reclaimed).
//
// The id order comes from the (endpoint_id, id) index rather than min(): there
// is no min() aggregate for uuid, and an ordered LIMIT 1 is a single index probe.
func (s *Store) Watermark(ctx context.Context, endpointID string) (*string, error) {
	var oldest *string
	err := s.pool.QueryRow(ctx, `
		select (select id::text from event
		         where endpoint_id = $1::uuid
		         order by id
		         limit 1)`, endpointID).Scan(&oldest)
	if err != nil {
		return nil, fmt.Errorf("watermark: %w", err)
	}
	return oldest, nil
}

// Newest returns the newest id the read API would serve, so a new consumer can
// attach at the tail instead of replaying history it cannot decrypt. nil when
// the endpoint is empty, or when every stored event is still inside the read
// lag.
func (s *Store) Newest(ctx context.Context, endpointID string, lag time.Duration) (*string, error) {
	var newest *string
	err := s.pool.QueryRow(ctx, `
		select (select id::text from event
		         where endpoint_id = $1::uuid
		           and received_at < now() - make_interval(secs => $2)
		         order by id desc
		         limit 1)`, endpointID, lag.Seconds()).Scan(&newest)
	if err != nil {
		return nil, fmt.Errorf("newest: %w", err)
	}
	return newest, nil
}

// Stats returns hourly buckets for the last window, oldest first.
func (s *Store) Stats(ctx context.Context, endpointID string, window time.Duration) ([]Bucket, error) {
	rows, err := s.pool.Query(ctx, `
		select date_trunc('hour', received_at) as bucket,
		       count(*),
		       count(*) filter (where status = 'rejected'),
		       coalesce(sum(size_bytes), 0)
		  from event
		 where endpoint_id = $1::uuid
		   and received_at > now() - make_interval(secs => $2)
		 group by 1
		 order by 1`,
		endpointID, window.Seconds())
	if err != nil {
		return nil, fmt.Errorf("stats: %w", err)
	}
	defer rows.Close()

	var out []Bucket
	for rows.Next() {
		var b Bucket
		if err := rows.Scan(&b.Start, &b.Events, &b.Rejected, &b.Bytes); err != nil {
			return nil, fmt.Errorf("scan bucket: %w", err)
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

const reapTail = `
	), agg as (
		select count(*)::bigint as n, coalesce(sum(size_bytes), 0)::bigint as b from del
	)
	update endpoint e
	   set bytes_used = greatest(e.bytes_used - agg.b, 0),
	       events_used = greatest(e.events_used - agg.n, 0)
	  from agg
	 where e.id = $1::uuid
	returning agg.n, agg.b`

// DeleteOlderThan removes one batch of events past the age policy.
func (s *Store) DeleteOlderThan(ctx context.Context, endpointID string, age time.Duration, batch int) (int64, int64, error) {
	return s.reap(ctx, `
		with victims as (
			select id from event
			 where endpoint_id = $1::uuid
			   and received_at < now() - make_interval(secs => $2)
			 order by id
			 limit $3
		), del as (
			delete from event where id in (select id from victims) returning size_bytes
		`+reapTail, endpointID, age.Seconds(), batch)
}

// EvictOldest removes the oldest events regardless of age, for the size policy.
// It never refuses an event: history is cheaper to lose than to amplify
// provider retries with a 5xx.
func (s *Store) EvictOldest(ctx context.Context, endpointID string, batch int) (int64, int64, error) {
	const evictTail = `
		), agg as (
			select count(*)::bigint as n, coalesce(sum(size_bytes), 0)::bigint as b from del
		)
		update endpoint e
		   set bytes_used = greatest(e.bytes_used - agg.b, 0),
		       events_used = greatest(e.events_used - agg.n, 0),
		       evicted_events = e.evicted_events + agg.n
		  from agg
		 where e.id = $1::uuid
		returning agg.n, agg.b`

	return s.reap(ctx, `
		with victims as (
			select id from event
			 where endpoint_id = $1::uuid
			 order by id
			 limit $2
		), del as (
			delete from event where id in (select id from victims) returning size_bytes
		`+evictTail, endpointID, batch)
}

func (s *Store) reap(ctx context.Context, query string, args ...any) (int64, int64, error) {
	var rows, bytes int64
	if err := s.pool.QueryRow(ctx, query, args...).Scan(&rows, &bytes); err != nil {
		return 0, 0, fmt.Errorf("reap: %w", err)
	}
	return rows, bytes, nil
}
