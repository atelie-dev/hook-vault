# Connecting to hook-vault

One binary, two listeners, two network postures. Knowing which one you are
talking to is the whole of connecting:

| Surface | Serves | Credential |
|---|---|---|
| data plane | ingest (`/in/*`) and the read API (`/v1/events`, `/v1/events/stream`, `/v1/me`) | provider signature for ingest, a bearer token for reads |
| control plane | endpoint management (`/v1/endpoints*`) and the panel | one admin token, exchanged by the panel for a cookie |

Reads are safe to expose because they can only return ciphertext: the key that
opens it never reaches the server. The control plane is different — it is the
management surface, so it belongs on a private network.

## The reference deployment

| Surface | URL | Reached from |
|---|---|---|
| ingest + read | `https://webhooks.atelie.dev.br` | anywhere; this is the public data plane |
| control plane | `https://hookvault.svc.atelie.dev.br` | the tailnet only |

`webhooks.atelie.dev.br` is the host every consumer, human or agent, points at.
`hookvault.svc.atelie.dev.br` exists for operators: the panel and the management
API. `/v1/events` is **not** served there — the read API lives on the data plane,
which has no tailnet requirement and needs the endpoint's token instead.

The deployment itself (Caddy vhosts, the tailnet gate, the systemd unit) lives in
another repository, `atelie-server/modules/hook-vault.nix`. Nothing in this
binary knows about Tailscale; the split is the product decision, the gate is the
deployment's.

## The tailnet gate, precisely

`*.svc.atelie.dev.br` is a **public DNS wildcard** that resolves to the node's
tailnet address, so no MagicDNS is involved: the name resolves anywhere and only
routes on the tailnet. Two layers decide access:

1. the **Tailscale ACL**, which is what keeps an unapproved device from reaching
   the node at all;
2. **Caddy**, which aborts any request whose `client_ip` falls outside
   `100.64.0.0/10` — a backstop for an ACL that is too generous, not the gate.

TLS is the `*.svc.atelie.dev.br` wildcard certificate (DNS-01), so never reach for
`-k` or `--insecure`: a certificate error there is a misconfiguration, not the
way in.

Off the tailnet the failure is at the network layer: the name resolves and the
CGNAT address is unroutable, so `curl` times out, or reaches Caddy by some other
path and gets `curl: (52) Empty reply from server` from the `abort`. Neither is a
credential problem; check `tailscale status` before touching the token.

## Discovery: `/llms.txt`

The data plane serves one markdown document written for a reader that arrives
with no context — a person in a shell, or an agent given only a URL:

```bash
curl -sS https://webhooks.atelie.dev.br/llms.txt
```

It carries the route table, the auth model, the event shape, the cursor rules,
the CLI environment and a devenv snippet. The binary embeds it (`go:embed`) and
renders it with `--public-url`, so it cannot drift from the version answering
the request. Point an agent at this URL instead of at the repository.

## Health checks

```bash
curl -sS https://webhooks.atelie.dev.br/healthz
# {"status":"ok"}

curl -sS https://webhooks.atelie.dev.br/v1/me \
  -H "authorization: Bearer $HOOKVAULT_TOKEN"
# endpoint, kid, storage counters, cursor.oldest/newest, ingest_url
```

`/healthz` only proves the process and the database are alive. `/v1/me` is the
check that matters for a consumer: it proves the URL, the token and the database
together, and it is where a new reader learns `cursor.newest` to attach at the
tail.

With the CLI, the same check without curl:

```bash
hook-vault fetch --limit=1 --format jsonl >/dev/null && echo ok
```

## Credentials

One key pair is one endpoint. Put a project's key outside its repository:

```bash
install -d -m 700 ~/.config/hook-vault
install -m 600 ~/Downloads/<project>.key ~/.config/hook-vault/<project>.key
```

The CLI derives the token from that file, so a single credential both
authenticates the read and opens the payloads. Registration on the server needs
`public_key` and `token_sha256` from `hook-vault keygen` — never the secret, never
the token. A consumer that must not hold the key at all (a CI job asserting that
events arrive) uses a token file instead and sees ciphertext only.

## Environment contract

| Variable | Used by | Effect |
|---|---|---|
| `HOOKVAULT_URL` | `fetch` | base URL of the data plane |
| `HOOKVAULT_KEY_FILE` | `fetch` | secret key file; derives the token **and** decrypts |
| `HOOKVAULT_KEY_VALUE` | `fetch` | the same value inline, for `op run` |
| `HOOKVAULT_TOKEN_FILE` | `fetch` | token only: ciphertext plus a reason |
| `HOOKVAULT_TOKEN_VALUE` | `fetch` | the same value inline |
| `HOOK_VAULT_SECRET` | `open` | the one verb that kept the old prefix; prefer `--secret` |

Flags win over the environment, and setting a file and a value at the same level
is an error rather than a silent pick. The `curl` examples use
`$HOOKVAULT_TOKEN` as a plain shell variable — the CLI reads only the `*_FILE`
and `*_VALUE` names above. The full dev-shell recipe — devenv, its
flake input, the missing-key warning and a `hook-vault-check` script — is in
[consumer-guide.md](consumer-guide.md#set-once-per-project-devenv--direnv).

## Reading

```bash
hook-vault fetch                                          # one page, human on a TTY
hook-vault fetch --format jsonl | jq -c '{id, payload}'   # one object per line
hook-vault fetch --since=10m                              # window, server-resolved
hook-vault fetch --watch --cursor-file .hookvault.cursor  # follow, resumable
```

```bash
curl -N https://webhooks.atelie.dev.br/v1/events/stream \
  -H "authorization: Bearer $HOOKVAULT_TOKEN"              # SSE: frame id is the cursor
```

`--watch` without a starting point attaches at the newest event; the backlog is a
one-shot `fetch` without `--watch`. Details, formats and decryption snippets:
[consumer-guide.md](consumer-guide.md).

## When it does not work

| Symptom | Cause |
|---|---|
| `401 unauthorized` | token from another endpoint, revoked, or malformed (must be `hv1_…`) |
| `404 unknown_endpoint` | the slug in the ingest URL, not authentication |
| `curl: (52)` or timeout on `*.svc` | you are off the tailnet, or the ACL does not include this device |
| `hook-vault: read key file: … no such file` | `HOOKVAULT_KEY_FILE` points at a file the shell cannot read |
| event opens with one key, fails with another | check its `kid`: a rotated key only opens its own history |
| `next_cursor` unchanged and no events | the cursor is at the tail, or retention removed the window |
