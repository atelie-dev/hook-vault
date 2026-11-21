package store

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	"github.com/atelie-dev/hook-vault/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
)

// migrationLockID serialises concurrent migrations from several instances.
// Any stable int64 works; this one is arbitrary and must never change.
const migrationLockID int64 = 8454372123

// Migrate applies every embedded migration that the database has not seen yet.
// Each migration runs in its own transaction, so a failure leaves the schema at
// the last complete version.
func (s *Store) Migrate(ctx context.Context) error {
	if _, err := s.pool.Exec(ctx, `
		create table if not exists schema_migration (
			version    integer primary key,
			applied_at timestamptz not null default now()
		)`); err != nil {
		return fmt.Errorf("create schema_migration: %w", err)
	}

	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire migration connection: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, `select pg_advisory_lock($1)`, migrationLockID); err != nil {
		return fmt.Errorf("acquire migration lock: %w", err)
	}
	defer func() {
		// The context may already be cancelled; the lock dies with the session
		// anyway, but releasing early is tidier.
		_, _ = conn.Exec(context.WithoutCancel(ctx), `select pg_advisory_unlock($1)`, migrationLockID)
	}()

	applied, err := s.appliedMigrations(ctx, conn)
	if err != nil {
		return err
	}

	files, err := fs.Glob(migrations.FS, "*.sql")
	if err != nil {
		return fmt.Errorf("list migrations: %w", err)
	}
	sort.Strings(files)

	for _, name := range files {
		version, err := migrationVersion(name)
		if err != nil {
			return err
		}
		if applied[version] {
			continue
		}

		body, err := migrations.FS.ReadFile(name)
		if err != nil {
			return fmt.Errorf("read %s: %w", name, err)
		}

		tx, err := conn.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin %s: %w", name, err)
		}
		if _, err := tx.Exec(ctx, string(body)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("apply %s: %w", name, err)
		}
		if _, err := tx.Exec(ctx, `insert into schema_migration (version) values ($1)`, version); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("record %s: %w", name, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit %s: %w", name, err)
		}
	}

	return nil
}

func (s *Store) appliedMigrations(ctx context.Context, conn *pgxpool.Conn) (map[int]bool, error) {
	rows, err := conn.Query(ctx, `select version from schema_migration`)
	if err != nil {
		return nil, fmt.Errorf("read schema_migration: %w", err)
	}
	defer rows.Close()

	applied := make(map[int]bool)
	for rows.Next() {
		var version int
		if err := rows.Scan(&version); err != nil {
			return nil, fmt.Errorf("scan schema_migration: %w", err)
		}
		applied[version] = true
	}
	return applied, rows.Err()
}

func migrationVersion(name string) (int, error) {
	base := strings.TrimSuffix(name, ".sql")
	prefix := base
	if idx := strings.IndexByte(base, '_'); idx >= 0 {
		prefix = base[:idx]
	}
	version, err := strconv.Atoi(prefix)
	if err != nil {
		return 0, fmt.Errorf("migration %q must start with a number, e.g. 0001_init.sql", name)
	}
	return version, nil
}

// RequirePostgres18 refuses to run on a server without the native uuidv7()
// function. The event id is the read cursor, so a wrong database version is a
// correctness problem, not a compatibility nuance.
func (s *Store) RequirePostgres18(ctx context.Context) error {
	var version int
	if err := s.pool.QueryRow(ctx, `select current_setting('server_version_num')::int`).Scan(&version); err != nil {
		return fmt.Errorf("read PostgreSQL version: %w", err)
	}
	if version < 180000 {
		return fmt.Errorf("hook-vault requires PostgreSQL 18 or newer (native uuidv7()), connected server reports %d", version)
	}
	return nil
}

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("store: not found")

// ErrTokenInUse is returned when a key is already registered on another
// endpoint: one key pair owns exactly one endpoint, so a leaked token can never
// read two archives.
var ErrTokenInUse = errors.New("store: token is already registered on another endpoint")
