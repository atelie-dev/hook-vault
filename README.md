# hook-vault

**An encrypted webhook inbox.** Providers POST to it, it stores the payloads in
PostgreSQL sealed with a key it does not hold, and consumers read them back as a
cursor-paginated log of ciphertext.

It exists because two things are easy to find and the combination is not: a
self-hosted webhook collector (usually plaintext, usually Redis) and a webhook
dispatcher (Svix, Outpost — sending, not receiving). Nothing open source stores
third-party webhooks so that the server, its database, its dumps and its backups
are all useless to whoever reads them.

```
provider ──TLS──▶ ingest ──seal(pk)──▶ PostgreSQL ──▶ GET /v1/events?cursor=…
                   │                                      │
                   └─ verifies the provider signature     └─ consumer opens it
                      and never keeps the plaintext          with the secret key
```

## What the server can and cannot do

Be precise about this, because "end-to-end encrypted" is easy to claim and easy
to get wrong. Inbound webhooks come from third parties that will not encrypt
anything, so this server necessarily sees each body once, at ingest.

| | Server (running) | Database, dumps, snapshots, backups | Stolen API token |
|---|---|---|---|
| Read a stored payload | **no** | **no** | **no** |
| Forge an ingest | yes, with the provider secret | yes, with the provider secret | yes |
| Delete history | yes | yes | no |
| Learn which products send what | yes (metadata only) | yes (metadata only) | yes |

The honest claim is **encrypted at rest, not end-to-end** — the plaintext exists
in process memory between TLS termination and sealing. An attacker who can read
that memory or replace the binary during ingest defeats it. Everyone else,
including whoever ends up with a `pg_dump`, a ZFS snapshot or the offsite restic
archive, gets opaque blobs.

What that buys you is real: backups stop being a liability, a database
restore no longer means a plaintext copy of every customer event, and a leaked
read token leaks ciphertext.

## Quick start

Four recipes, each self-contained: start the service, register an endpoint, give
a second consumer access, and rotate a key.

### Start the service

```bash
# Go 1.26+ to build from source (dictated by the dependencies, not by the code).
# PostgreSQL 18+ is required: the cursor is the native uuidv7().
go build -o bin/hook-vault ./cmd/hook-vault

bin/hook-vault serve \
  --database-url 'postgres://hookvault@localhost/hookvault?sslmode=disable' \
  --ingest-addr :8080 \
  --admin-addr 127.0.0.1:8081 \
  --public-url https://hooks.example.com
```

Every flag has a `HOOKVAULT_*` environment variable; the database URL is the only
one without a default. `serve` migrates on startup, so the database only has to
exist and be empty, then runs both listeners and the retention sweeper.
`--public-url` is used only to render `ingest_url` in responses.

### Register an endpoint

An endpoint is one provider pointed at one inbox. Each endpoint gets its own key
pair, so `keygen` runs **once per endpoint** — not once per installation:

```bash
bin/hook-vault keygen
```

`keygen` prints five things:

```
secret_key:   32-byte base64 — keep it offline, it is the only way back in
public_key:   register this on the endpoint; the server cannot derive the secret from it
kid:          stable id derived from the public key
token:        the read API bearer token, derived from the secret (HKDF)
token_sha256: what the server stores; register this, never the token
```

The token is what identifies the endpoint — presenting it is how the server knows
which archive to read — so the two are bound to each other:

- **A key pair belongs to exactly one endpoint.** Registering the same
  `token_sha256` on a second endpoint is refused with `409 token_in_use`, which
  bounds the blast radius of a leaked token to a single endpoint's history.
- **One endpoint can have several key pairs.** That is how a second consumer
  joins and how a key is rotated — the old key keeps opening the events it
  sealed, which are tagged with its `kid`.

Three endpoints read by one service means three secrets inside that service.
`keygen --secret <secret>` is not a new key: it reprints the values for a secret
you already have, which is how you recover `token` and `token_sha256` after a
restore.

Then create it:

```bash
curl -X POST http://127.0.0.1:8081/v1/endpoints -H 'content-type: application/json' -d '{
  "name": "github prod",
  "verify": "github",
  "verify_secret": "<the secret you set in GitHub>",
  "retention_days": 30,
  "max_bytes": 1073741824,
  "public_key": "<public_key from keygen>",
  "token_sha256": "<token_sha256 from keygen>"
}'
```

The response is where the generated `slug` shows up:

```json
{
  "endpoint": {
    "id": "01a1fc71-0c78-7dc8-a451-3cabc41c8861",
    "slug": "bf5gk5ydrbdm2zl7kg5yt6o7vu",
    "name": "github prod",
    "ingest_url": "https://hooks.example.com/in/bf5gk5ydrbdm2zl7kg5yt6o7vu",
    "retention_days": 30,
    "max_bytes": 1073741824,
    "bytes_used": 0,
    "events_used": 0,
    "evicted_events": 0,
    "verify": "github",
    "active_kid": "kh5sikhlk2z",
    "created_at": "2026-11-21T04:49:48.675Z",
    "disabled_at": null
  },
  "key": {
    "kid": "kh5sikhlk2z",
    "public_key": "Na578D0r1oE2mDC88bX81qxemS2wjjdtn0YxFASYskk",
    "active": true,
    "created_at": "2026-11-21T04:49:48.675Z",
    "revoked_at": null
  }
}
```

**The slug** is generated server-side when the request omits it: 128 bits from
`crypto/rand`, base32 lower-case (`a-z2-7`), 26 characters. It is *not* an
authentication mechanism — the provider signature is — it exists so background
scanners do not find endpoints and so a URL leaking into a log does not name the
product. Send your own `slug` (12–64 characters, lowercase alphanumerics) when a
readable path is worth more than an unguessable one; uniqueness is enforced by
the database. It is the last segment of `ingest_url` and it is what `GET /v1/me`
returns, so a consumer never has to remember it.

`verify_secret` is write-only: it never comes back in any response.

Point the provider at `ingest_url` and read it back:

```bash
curl "https://hooks.example.com/v1/events?limit=100" \
  -H "authorization: Bearer hv1_…" | jq -r '.events[0].ct' | bin/hook-vault open
```

### Add a second consumer

Another reader on the same endpoint. `keygen` again, register the **new** public
key on the **same** endpoint, and revoke nothing:

```bash
curl -X POST http://127.0.0.1:8081/v1/endpoints/<endpoint id>/keys \
  -H 'content-type: application/json' -d '{
  "public_key": "<public_key from the second keygen>",
  "token_sha256": "<token_sha256 from the second keygen>"
}'
```

The new consumer starts at the **tail**, not at the beginning: everything already
stored was sealed for somebody else's key and it could not decrypt any of it.

```bash
curl http://127.0.0.1:8081/v1/me -H "authorization: Bearer <new token>" \
  | jq -r '.cursor.newest'    # pass this as ?cursor= on the first read
```

Both consumers keep working, indefinitely. That is the whole difference from a
rotation: no `DELETE`.

### Rotate a key

The same registration plus a revoke, and the order is what matters:

1. `keygen` for the new key and register it on the same endpoint, exactly as
   above. New events are now sealed for the new key.
2. **Let the old consumer drain first.** Events already stored are sealed to the
   old key: the new consumer can download them but never open them. Anything the
   old consumer has not read before its key is revoked is effectively lost.
3. Revoke the old key:

   ```bash
   curl -X DELETE http://127.0.0.1:8081/v1/endpoints/<endpoint id>/keys/<old kid>
   ```

4. Keep the old `secret_key` for as long as retention holds events tagged with
   its `kid`. It is the only thing that still opens them.

| | Add a consumer | Rotate |
|---|---|---|
| `POST /v1/endpoints/{id}/keys` | yes | yes |
| `DELETE /v1/endpoints/{id}/keys/{kid}` | no | yes, after draining |
| old token | keeps working | dies on the next request |
| old secret | still needed for its own events | still needed for its `kid` |

An endpoint carrying several keys is what makes rotation safe: an event records
the `kid` that sealed it, so revoking a key stops it from authenticating new
reads without orphaning a byte of history.

## Two listeners

One binary, two `http.ServeMux`, two addresses:

| Listener | Routes | Reachable by |
|---|---|---|
| ingest (`:8080`) | `POST /in/{slug}`, `GET /in/{slug}` (Meta handshake), `GET /v1/events`, `GET /v1/me`, `/healthz` | the internet |
| control plane (`:8081`) | endpoint and key management, statistics, `/v1/events` for operators | nobody but you |

The split is a product decision, not a deployment detail: only one of these is
meant to face the internet, and the binary knows nothing about Caddy, nginx,
Cloudflare or Tailscale. Bind the control plane to loopback or put it behind a
VPN; if it listens beyond loopback, `--admin-token` is mandatory and the process
refuses to start without it.

The read API is safe to expose because it can only return ciphertext and it
requires a token derived from a key the server never sees.

## Authentication

hook-vault has no user accounts, no sessions and no login. That is deliberate:
it is one process over one database, and the credential that actually matters —
the read token — is derived from a key the server never sees, so there is nothing
a user model could protect that the token does not already bound.

What exists:

| Surface | Credential |
|---|---|
| `POST /in/{slug}` | the provider signature (`X-Hub-Signature-256`, `Stripe-Signature`, …) |
| `GET /v1/events`, `GET /v1/me` | a bearer token derived from the endpoint's secret key |
| control plane | one `--admin-token`, a service credential, not a person |

What does not exist: per-user access, roles, or an audit trail of who changed
what.

The panel logs in with that same admin token: it is checked once and exchanged
for a stateless HttpOnly cookie (an HMAC of a nonce, keyed by the token). There
is no session store and no way to enumerate sessions; logging out drops the
cookie, and restarting the server does not log anyone out.

If more than one person needs the control plane, put a real

| | |
|---|---|
| **oauth2-proxy** | SSO (Google, GitHub, OIDC) in front of the control-plane listener; injects `X-Admin-Token` upstream so the app keeps its single service credential |
| **Cloudflare Access** | the gate runs at the edge, nothing in the app changes |
| **Tailscale / WireGuard** | the network is the gate — bind the control plane to loopback or a private interface |

Gate the **control plane only**. The ingest path must stay reachable without a
login: providers do not authenticate, and they do not follow a redirect to an SSO
page. Its authentication is the HMAC over the raw body, which is also why
`verify: "none"` is only reasonable for endpoints you control end to end.

The two-listener split exists so that this stays a proxy and network decision
rather than an application feature.

## How a payload is sealed

`crypto_box_seal` — X25519 + XSalsa20-Poly1305, an ephemeral sender key per
message, 48 bytes of overhead. Implemented with `golang.org/x/crypto/nacl/box`,
which is byte-compatible with libsodium, so a payload sealed here opens with
`sodium-native`, `PyNaCl`, `sodium_crypto_box_seal_open`, or `libsodium` itself.
This repository pins that compatibility with a test vector generated by PyNaCl.

The token comes from the same secret, under a separate HKDF domain:

```
secret_key (32 bytes, never leaves the consumer)
  ├─ X25519 keypair           → public_key, registered on the endpoint
  └─ HKDF-SHA256(secret, info="hook-vault.auth.v1", 32)
       → token = "hv1_" + base64url_raw(...)
       → server stores SHA-256(token)
```

Deriving rather than reusing the key is the point: a bearer token travels on
every request and lands in proxy logs. A leaked token must not be the thing that
opens the archive, and `kid` is what identifies the caller.

A `kid` is `"k" + base32_lower(SHA-256(public_key))[:10]`. Every event records
the `kid` that sealed it, so rotating a key never orphans history: register the
new public key, keep the old secret, and old events still open.

See [docs/consumer-guide.md](docs/consumer-guide.md) for decryption snippets.

## API

All ciphertext is **unpadded base64url**. Python and Java need padding added
before decoding; Node, Go and PHP do not.

### Data plane

| Method | Path | Notes |
|---|---|---|
| `POST` | `/in/{slug}` | the provider endpoint; `X-HookVault-Event-Id` in the response |
| `GET` | `/in/{slug}?hub.mode=subscribe&hub.verify_token=…&hub.challenge=…` | Meta subscription handshake, echoes the challenge |
| `GET` | `/v1/events?cursor=&limit=&include_rejected=` | bearer token; `limit` ≤ 1000, default 100 |
| `GET` | `/v1/me` | key id, storage counters, both ends of the log (`cursor.oldest`, `cursor.newest`) |

`GET /v1/events` returns:

```json
{
  "events": [
    {
      "id": "01a1fc71-7463-724b-8018-64547812afb1",
      "received_at": "2026-11-21T04:49:48.676Z",
      "kid": "kh5sikhlk2z",
      "alg": "x25519-xsalsa20poly1305-sealed",
      "ct": "h5E…",
      "size": 110,
      "status": "stored",
      "meta": {"source": "github", "event": "issues", "delivery": "dlv-1"}
    }
  ],
  "next_cursor": "01a1fc71-7463-724b-8018-64547812afb1",
  "has_more": false,
  "oldest_cursor": "01a1fc71-7463-724b-8018-64547812afb1",
  "lag_seconds": 2
}
```

The consumer holds the cursor; the server keeps no per-reader state. `meta` is
the only plaintext: the source profile and two provider ids, whitelisted so the
panel and filters work without decrypting anything. Never the body, never the
headers.

### Cursor semantics

The cursor is the event id: a `uuidv7` generated by PostgreSQL, so it is
time-ordered and `id > cursor ORDER BY id` is one index range scan.

Three details make it correct rather than merely convenient:

1. **The database generates the id** (`default uuidv7()`), never the application.
   Two clocks means an id smaller than the cursor can arrive later, and with a
   client-held cursor that event is lost.
2. **The read API lags `now()` by `--read-lag`** (default 2s). An id is assigned
   before its transaction commits; without the lag a reader could advance past a
   row that becomes visible a moment later.
3. **`oldest_cursor` is always returned.** When retention deletes history, a
   consumer whose cursor is older than that has a gap and can say so instead of
   silently believing it is up to date.

A consumer joining an existing endpoint should not start at `oldest_cursor`:
those events are sealed for a key it does not hold. `GET /v1/me` returns
`cursor.newest` for exactly this, so a new reader attaches at the tail with one
request instead of replaying history it cannot read.

### Control plane

| Method | Path | Notes |
|---|---|---|
| `POST` | `/v1/endpoints` | creates the endpoint and its first key in one statement |
| `GET` | `/v1/endpoints` | |
| `GET` | `/v1/endpoints/{id}` | endpoint plus its keys |
| `PATCH` | `/v1/endpoints/{id}` | policy, verification, disable; `0` clears a limit |
| `POST` | `/v1/endpoints/{id}/keys` | register a rotated key or a second reader; `409` if the key already belongs to another endpoint |
| `DELETE` | `/v1/endpoints/{id}/keys/{kid}` | revoke; history stays readable |
| `GET` | `/v1/endpoints/{id}/stats?window=24h` | hourly buckets |

Registering a key takes `public_key` and `token_sha256`, never the token itself,
so the control plane cannot mint a readable credential even if it is compromised.

## Verification profiles

The provider signature is the only authentication available on the ingest side:
GitHub and Meta will not send a bearer token.

| Profile | Header | Scheme |
|---|---|---|
| `github` | `X-Hub-Signature-256` | `sha256=<hex HMAC-SHA256 of the raw body>` |
| `meta` | `X-Hub-Signature-256` | same as GitHub, plus the `hub.challenge` handshake |
| `stripe` | `Stripe-Signature` | `t=<unix>,v1=<hex>`, signed payload `t + "." + body`, ±5 min |
| `generic-hmac` | `X-HookVault-Signature` | `sha256=<hex>` |

A failed verification is **stored as evidence** with `status: "rejected"` and
answered with `401`, then hidden from the default read. Dropping it silently
would make a misconfigured secret look like a network problem.

The signature covers the raw body, so nothing in front of this service may
rewrite it: no body-modifying WAF, no decompression, no re-serialization.

## Storage policy

Per endpoint, both optional, enforced by a sweeper every `--reaper-interval`:

- `retention_days` — delete events older than this;
- `max_bytes` — delete the oldest events until the endpoint fits.

The size policy **evicts, never rejects**. A `5xx` because a disk is full turns
one lost batch into an amplification event: the provider retries, more bodies
arrive, nothing fits. Eviction is recorded (`evicted_events`) and surfaced in the
panel, so running against a quota is visible instead of silent.

Counters (`bytes_used`, `events_used`) are maintained by the write path in the
same statement as the insert, and decremented by the reaper, so no read ever
scans the event table.

## Operating notes

- `max-body-bytes` defaults to 1 MiB. Stripe's cap is well under it; raise it for
  GitHub's larger deliveries.
- The ingest path is one indexed lookup, one seal, one insert. A 200 means
  "durably stored", so the only correct failure after accepting a body is a 5xx
  that makes the provider retry.
- Duplicates are expected: providers retry. `meta.delivery` carries the provider
  id when there is one; dedupe on the consumer side.
- Backups are free: it is one database, and `pg_dumpall` covers it. The dump
  contains only ciphertext.

## Status

v0.2.0 — ingest, verification, sealed storage, cursor read API, retention, key
management and a control-plane panel with in-browser key generation
(WebCrypto; see [Authentication](#authentication) for what that does and does
not change). Not yet: consumer-controlled acknowledgement, monthly
partitioning, in-panel decryption.

Deliberately out of scope: user accounts (see [Authentication](#authentication)),
retries, fan-out, transformations, acting as a queue. This is an append-only
log. If you need to push events to consumers, put Svix or Hookdeck Outpost in
front of it.

## License

MIT.
