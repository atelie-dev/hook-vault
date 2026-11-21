<!-- Context: project-intelligence/navigation | Priority: critical | Version: 1.0 | Updated: 2026-11-21 -->

# Project Intelligence — hook-vault

**Purpose**: index of what to read, in the order that saves time.
**Last Updated**: 2026-11-21

## Quick Routes

| File | Description | Priority |
|------|-------------|----------|
| `.opencode/context/project-intelligence/technical-domain.md` | Stack, the three contracts, API/CLI/panel behaviour, testing, deliberate gaps, and the gotchas that cost time | critical |
| `AGENTS.md` (root) | Numbered invariants — breaking one is a security bug, not a refactor | critical |
| `README.md` (root) | Threat model ("encrypted at rest, not end-to-end"), API reference, storage policy | critical |

## Deep Dives

| File | When to load |
|------|--------------|
| `docs/consumer-guide.md` | Any consumer-facing change: decrypt snippets, `fetch` formats, per-project devenv, token recovery |
| `internal/vault/key.go` + `key_test.go` | Crypto change — the PyNaCl vector is the contract with every consumer |
| `internal/webui/static/keygen.js` | Panel key generation — the WebCrypto twin of `vault`, byte-identical derivation |
| `internal/store/store.go` | Schema/query change: every SQL statement lives here, including the cursor and the reaper |
| `internal/httpapi/{ingest,read,admin,panel}.go` | Data plane vs control plane behaviour, auth, and the session cookie |
| `internal/webui/templates/*.html` | Panel UI — `create.html` carries the keygen flow and the profile→verify-token coupling |
| `migrations/0001_init.sql` | Schema, constraints and the reasoning comments |
| `internal/timespec/timespec.go` | The `since` grammar shared by the CLI and the read API |

**Deployment lives in another repo**: `atelie-server` → `modules/hook-vault.nix`
(systemd unit, LoadCredential, Caddy vhosts), `infra/cloudflare-token/` (the
fleet DNS-01 token), and `PLANNED.md` for the 2026-11-21 ops entries.

## Update Triggers

- New CLI verb or flag, or a change in output formats → `technical-domain.md`
  (CLI section) + `docs/consumer-guide.md`
- Schema or retention change → `technical-domain.md` + `migrations/`
- New panel route → `technical-domain.md` (panel section) + a test that renders it
- A bug that cost real time → add it under "Gotchas paid for in blood", with the
  symptom, not just the fix
- A contract change (crypto, cursor, retention) → bump the version here **and**
  in `AGENTS.md`; consumers may have implemented it
