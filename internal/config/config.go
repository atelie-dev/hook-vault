// Package config resolves runtime settings from flags and environment
// variables, and refuses configurations that cannot be safe.
package config

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// Config is the resolved runtime configuration.
type Config struct {
	IngestAddr      string
	AdminAddr       string
	DatabaseURL     string
	PublicURL       string
	AdminToken      string
	MaxBodyBytes    int64
	ReadLag         time.Duration
	ReaperInterval  time.Duration
	ShutdownTimeout time.Duration
	LogLevel        string
}

// Defaults are the values a single-host operator gets without configuring
// anything: public ingest on all interfaces, admin on loopback only.
const (
	DefaultIngestAddr   = ":8080"
	DefaultAdminAddr    = "127.0.0.1:8081"
	DefaultMaxBodyBytes = 1 << 20 // 1 MiB, above Stripe's cap and far below GitHub's
	DefaultReadLag      = 2 * time.Second
	DefaultReaper       = 60 * time.Second
	DefaultShutdown     = 15 * time.Second
)

// Load parses arguments and environment variables.
//
// Flags win over the environment. Environment variables carry the HOOKVAULT_
// prefix so they can sit in the same env file as anything else.
func Load(args []string) (*Config, error) {
	fs := flag.NewFlagSet("hook-vault serve", flag.ContinueOnError)

	cfg := &Config{}
	fs.StringVar(&cfg.IngestAddr, "ingest-addr", envOr("HOOKVAULT_INGEST_ADDR", DefaultIngestAddr),
		"address for the public ingest and read API listener")
	fs.StringVar(&cfg.AdminAddr, "admin-addr", envOr("HOOKVAULT_ADMIN_ADDR", DefaultAdminAddr),
		"address for the control-plane listener (panel and management API)")
	fs.StringVar(&cfg.DatabaseURL, "database-url", envOr("HOOKVAULT_DATABASE_URL", ""),
		"PostgreSQL 18+ connection string")
	fs.StringVar(&cfg.PublicURL, "public-url", envOr("HOOKVAULT_PUBLIC_URL", ""),
		"externally visible base URL, used to print ingest URLs (e.g. https://hooks.example.com)")
	fs.StringVar(&cfg.AdminToken, "admin-token", envOr("HOOKVAULT_ADMIN_TOKEN", ""),
		"bearer token protecting the control plane; required when admin-addr is not loopback")
	fs.Int64Var(&cfg.MaxBodyBytes, "max-body-bytes", envInt("HOOKVAULT_MAX_BODY_BYTES", DefaultMaxBodyBytes),
		"largest accepted webhook body")
	fs.DurationVar(&cfg.ReadLag, "read-lag", envDuration("HOOKVAULT_READ_LAG", DefaultReadLag),
		"how far behind now the read API stays, so an in-flight insert is never skipped by a cursor")
	fs.DurationVar(&cfg.ReaperInterval, "reaper-interval", envDuration("HOOKVAULT_REAPER_INTERVAL", DefaultReaper),
		"how often retention policies are enforced")
	fs.DurationVar(&cfg.ShutdownTimeout, "shutdown-timeout", envDuration("HOOKVAULT_SHUTDOWN_TIMEOUT", DefaultShutdown),
		"grace period for in-flight requests on shutdown")
	fs.StringVar(&cfg.LogLevel, "log-level", envOr("HOOKVAULT_LOG_LEVEL", "info"),
		"log level: debug, info, warn or error")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}

	cfg.PublicURL = strings.TrimRight(cfg.PublicURL, "/")
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) validate() error {
	if c.DatabaseURL == "" {
		return fmt.Errorf("database-url is required (or HOOKVAULT_DATABASE_URL)")
	}
	if c.IngestAddr == "" {
		return fmt.Errorf("ingest-addr must not be empty")
	}
	if c.AdminAddr == "" {
		return fmt.Errorf("admin-addr must not be empty")
	}
	if c.IngestAddr == c.AdminAddr {
		return fmt.Errorf("ingest-addr and admin-addr must differ: the whole point of two listeners is that only one of them is public")
	}
	if c.MaxBodyBytes < 1024 || c.MaxBodyBytes > 32<<20 {
		return fmt.Errorf("max-body-bytes must be between 1 KiB and 32 MiB, got %d", c.MaxBodyBytes)
	}
	if c.ReadLag < 0 || c.ReadLag > time.Minute {
		return fmt.Errorf("read-lag must be between 0 and 1m, got %s", c.ReadLag)
	}
	if c.ReaperInterval < time.Second {
		return fmt.Errorf("reaper-interval must be at least 1s, got %s", c.ReaperInterval)
	}
	if c.AdminToken == "" && !isLoopback(c.AdminAddr) {
		return fmt.Errorf("admin-addr %q is not loopback, so admin-token is required", c.AdminAddr)
	}
	return nil
}

func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func envOr(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int64) int64 {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return fallback
	}
	var out int64
	if _, err := fmt.Sscan(v, &out); err != nil {
		return fallback
	}
	return out
}

func envDuration(key string, fallback time.Duration) time.Duration {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}
