# AGENTS.md — hook-vault

An encrypted webhook inbox in Go. Read `README.md` first: it carries the threat
model, and the threat model is the product.

**Project intelligence** — what to read in which order, the three contracts, and
the traps that already cost time:
`.opencode/context/project-intelligence/navigation.md` (start there, then
`technical-domain.md`).

## Build and test

```bash
CGO_ENABLED=0 go build ./...        # always CGO off: static binary, no libsodium
go vet ./...
go test ./...                        # unit tests, no database
HOOKVAULT_TEST_DATABASE_URL='host=/tmp port=5432 user=postgres dbname=hookvault_test' go test ./...
```

Integration tests **drop and recreate the public schema**. Never point
`HOOKVAULT_TEST_DATABASE_URL` at a database you care about.

`nix develop` provides Go, PostgreSQL 18, golangci-lint, jq and curl.

## Invariants — breaking these is a security bug, not a refactor

1. **The server never holds anything that can decrypt.** The private key arrives
   nowhere: not in a request, not in the database, not in an environment
   variable. `endpoint_key.public_key` is the only key material stored.
2. **The API token is derived, never stored.** Only `SHA-256(token)` is in the
   database. The `Endpoint` and `Key` DTOs must not gain a token or secret
   field; `verify_secret` and `verify_token` are write-only.
3. **Uuidv7 ids come from PostgreSQL** (`default uuidv7()`), never from Go. Two
   clocks means an id smaller than a cursor can arrive later, which is silently
   lost work.
4. **The read API keeps the `--read-lag` bound.** Removing it reintroduces the
   race where a reader advances past a row whose insert has not committed.
5. **Retention evicts, never rejects.** A 5xx on quota turns one lost batch into
   an amplified retry storm.
6. **A failed signature is stored as evidence** (`status='rejected'`), answered
   with 401, and hidden from the default read.
7. **No user accounts, ever.** The control plane has one service credential
   (`--admin-token`); the panel exchanges it for a stateless cookie on login.
   SSO belongs in a proxy in front of it (oauth2-proxy, Cloudflare Access) or
   in the network (loopback, VPN). Adding a user or session table here means
   the threat model in the README is a lie.
8. **The panel never receives key material.** Key generation and token
   derivation happen in the browser (WebCrypto); the server sees only
   `public_key` and `token_sha256`. If a "decrypt in the panel" feature is ever
   added, it must decrypt client-side too — a server-side decryption path is a
   security bug, not a feature.

## Layout

```
cmd/hook-vault/       subcommands: serve, migrate, keygen, fetch, open
internal/vault/       sealed box + HKDF token derivation (the crypto contract)
internal/store/       all SQL; the only place that knows the schema
internal/httpapi/     data plane (ingest, read) and control plane (management)
internal/retention/   age and size sweeps
internal/webui/       embedded panel: templates, CSS and keygen.js
migrations/           embedded SQL, applied by `serve` and `migrate`
```

## Conventions

- `store` returns `ErrNotFound` / `ErrTokenInUse`; handlers map those to status
  codes and never leak SQL errors to clients.
- Ciphertext crosses the API as **unpadded base64url**; `alg` names the scheme
  and `kid` names the key, so new schemes are additive.
- `meta` is the only plaintext in `event`. It is a whitelist (source, event id,
  delivery id, content type, user agent) and must never carry the body or a
  header that may hold credentials.
- Verification profiles share code where the provider does: GitHub and Meta both
  send `X-Hub-Signature-256`, so there is one HMAC path.
- The crypto contract is pinned by a PyNaCl-generated vector in
  `internal/vault/key_test.go`. If that test changes, every consumer breaks.

## When adding a migration

New file in `migrations/`, numeric prefix, applied in lexical order and each in
its own transaction. Never edit an applied migration: existing installs will not
re-run it.
