# Consuming hook-vault

Three steps: get the ciphertext, pick the right secret key, open the sealed box.
The last step has no server in it, and that is the point.

## 1. Read a page

```bash
curl "https://hooks.example.com/v1/events?limit=100" \
  -H "authorization: Bearer hv1_…"
```

```json
{"events": [{"id": "01a1…", "kid": "kh5sikhlk2z", "ct": "h5E…", "status": "stored"}],
 "next_cursor": "01a1…", "has_more": false, "oldest_cursor": "01a1…"}
```

Store `next_cursor` and pass it as `?cursor=` on the next call. Stop when it
comes back unchanged or `has_more` is false.

`ct` is **unpadded** base64url. Python and Java require you to pad it:

```python
ct = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
```

## 2. Pick the key

Each event carries the `kid` that sealed it. A rotated key still opens its own
history, so keep every secret you have ever registered, keyed by `kid`. Never
re-encrypt or migrate old events — just use the matching secret.

If a consumer only ever has one key, ignore `kid`.

## 3. Open the box

The construction is libsodium's `crypto_box_seal`: the ciphertext begins with the
ephemeral public key, then a box with a nonce derived from `blake2b-24(ephemeral
pk ‖ recipient pk)`. Any libsodium-compatible implementation opens it.

### Python (PyNaCl)

```python
import base64
from nacl.public import PrivateKey, SealedBox

secret = base64.urlsafe_b64decode(secret_b64 + "=" * (-len(secret_b64) % 4))
plaintext = SealedBox(PrivateKey(secret)).decrypt(ciphertext)
```

`SealedBox` derives the public key from the secret, so `public_key` is not needed.

### Node (sodium-native)

```javascript
const sodium = require('sodium-native')

const ct = Buffer.from(event.ct, 'base64url')
const pk = Buffer.from(publicKeyB64, 'base64url')
const sk = Buffer.from(secretB64, 'base64url')

const plaintext = Buffer.alloc(ct.length - sodium.crypto_box_SEALBYTES)
if (!sodium.crypto_box_seal_open(plaintext, ct, pk, sk)) {
  throw new Error(`cannot open event ${event.id} with kid ${event.kid}`)
}
```

In Node 20+, `require('node:crypto').diffieHellman()` and the X25519 key objects
can do the same by hand, but you would be reimplementing the nonce derivation and
the HSalsa20 step. Use `sodium-native`; it is the same code as the server's.

### Go

```go
import "golang.org/x/crypto/nacl/box"

var pk, sk [32]byte
copy(pk[:], publicKey)
copy(sk[:], secret)

plaintext, ok := box.OpenAnonymous(nil, ciphertext, &pk, &sk)
if !ok {
    return fmt.Errorf("cannot open event with kid %s", ev.KID)
}
```

### PHP

```php
$keypair = sodium_crypto_box_keypair_from_secretkey_and_publickey($sk, $pk);
$plaintext = sodium_crypto_box_seal_open($ct, $keypair);
```

## Read and decrypt in one command

`hook-vault fetch` pulls a page from the read API and, when given the secret
key, decrypts each event on the way out. One credential file is enough: the
token derives from the key.

```bash
hook-vault fetch --url https://hooks.example.com --key-file ~/.hookvault.key
```

### Two formats, chosen by where stdout goes

| `--format` | Output |
|---|---|
| `auto` (default) | `human` on a terminal, `jsonl` in a pipe |
| `human` | one block per event: coloured status, id, local timestamp, meta, key id, and the payload pretty-printed when it is JSON. Honours `NO_COLOR` |
| `jsonl` | one JSON object per line |

```
▌01a1fd3c-936a-7ba2-811a-f3c02030e108  2026-11-21 05:32:47  stored
  meta {"source":"meta","event":"whatsapp_business_account"}
  kid  kzr7kmv5imf
  {
    "object": "whatsapp_business_account",
    "entry": [{ "id": "1" }]
  }
```

```json
{"id":"01a1fd3c-…","received_at":"…","kid":"kzr7kmv5imf","status":"stored","meta":{"source":"meta","content_type":"application/json"},"decrypted":true,"payload":{"object":"whatsapp_business_account","entry":[{"id":"1"}]}}
```

The jsonl schema is stable on purpose: `decrypted` is always present, and an
event you cannot open carries `ct` plus `reason`. `payload` is **data when the
producer said so** — embedded JSON when the content-type is JSON and the body
parses, otherwise a JSON string. `--raw-payload` turns that off and always emits
the string, which is what a pipeline that hashes or re-seals bodies wants. The
embedded case is compacted, so the one-line-per-event invariant holds even when
the producer sent pretty-printed JSON.

### Watch mode

`--watch` keeps paging and emits events as they arrive. With no cursor it starts
at the tail (`/v1/me` → `cursor.newest`), so it does not replay the retention
window:

```bash
hook-vault fetch --url https://hooks.example.com --key-file ~/.hookvault.key \
  --watch --format jsonl | jq -c '{id, payload}'
```

`--cursor-file` makes a restart resume exactly where it stopped; `--interval`
sets the idle poll (default 5s). A rejected token ends the loop, a network blip
only logs and retries, and Ctrl-C exits with the cursor already saved.

By default `--watch` starts at the **tail**. To replay everything still stored
and then keep following, add `--from-start`:

```bash
hook-vault fetch --url https://hooks.example.com --key-file ~/.hookvault.key \
  --watch --from-start --format jsonl
```

`--from-start` means "ignore cursors": it refuses to combine with `--cursor` or
`--cursor-file`, so a restarted pipeline cannot silently replay history it had
already processed. If what you want is the backlog *once*, run without `--watch`
(the one-shot read already begins at the oldest stored event).

### A time window instead of the whole log

`--since` takes a duration, the kubectl word forms, or an absolute timestamp:

```bash
hook-vault fetch … --since=10m            # the last ten minutes
hook-vault fetch … --since=2hours         # 1h30m and 2days work too
hook-vault fetch … --since=2026-11-21T08:00:00Z
hook-vault fetch … --since=0              # everything still stored
```

The window is resolved by the server, against the same clock that stamped
`received_at` — so "the last ten minutes" does not drift with your laptop's
clock. The CLI validates the value locally only to fail fast with a readable
message; it never filters events itself, and CLI and server are expected to be
the same version.

`--since` composes with `--watch` (start inside the window, then follow) and is
mutually exclusive with `--cursor`, `--cursor-file` and `--from-start`: only one
of them can define where to begin.

### Flags that matter

| Flag | Env | Effect |
|---|---|---|
| `--key-file` | `HOOKVAULT_KEY_FILE` | secret key file; derives the token and decrypts. The whole point |
| `--key` | `HOOKVAULT_KEY_VALUE` | the same, inline — for `op run` injection |
| `--token-file` | `HOOKVAULT_TOKEN_FILE` | token only — ciphertext plus a reason, no decryption |
| `--token` | `HOOKVAULT_TOKEN_VALUE` | the same, inline |
| `--cursor-file` | | read and write a cursor file, so repeated runs resume |
| `--cursor` | | start after a specific event id |
| `--format` | | `auto` (default), `human`, `jsonl` |
| `--raw-payload` | | never interpret the payload: always a string, never embedded JSON |
| `--watch` / `--interval` | | page forever; idle poll interval |
| `--from-start` | | with `--watch`, begin at the oldest stored event instead of the tail |
| `--since` | | time window: `10m`, `2hours`, RFC3339, or `0` for everything |
| `--include-rejected` | | also list events that failed signature verification |

A flag always wins over the environment; setting both sources at the same level
(a file and a value) is an error, not a silent choice. The summary goes to
stderr (`next_cursor=… has_more=… events=…`), keeping stdout clean for payloads.

If the event was sealed for another key — a rotation you have not completed —
the CLI says so by `kid` instead of failing the whole page, and the key file
being group/world-readable earns a warning on stderr.

### Set once per project (devenv / direnv)

Both flags are environment variables too, so a project's dev shell can pre-set
them and `hook-vault fetch` needs no arguments at all:

```nix
# devenv.nix — the product repo
{ pkgs, inputs, ... }:
{
  packages = [ inputs.hook-vault.packages.${pkgs.stdenv.hostPlatform.system}.default ];
  env.HOOKVAULT_URL = "https://webhooks.atelie.dev.br";
  enterShell = ''
    export HOOKVAULT_KEY_FILE="$HOME/.config/hook-vault/medax.key"
  '';
}
```

Keep the key outside the repository, readable only by you:

```bash
install -d -m 700 ~/.config/hook-vault
install -m 600 ~/Downloads/hook-vault.key ~/.config/hook-vault/medax.key
```

One key pair is one endpoint, so the file is per project — that is the
guardrail, not an inconvenience: a project's leaked key exposes that project's
archive and nothing else. `HOOKVAULT_TOKEN_FILE` exists for contexts that must
not hold the secret key at all (a CI job that only asserts events arrive).

If your secrets live in a vault that injects environment variables (1Password
`op run`, direnv with `op inject`, a container secret store), skip the file and
hand over the value:

```bash
op run --env-file=.env -- hook-vault fetch
```

with the environment holding `HOOKVAULT_URL` and `HOOKVAULT_KEY_VALUE`. On a
machine where secrets can live on disk, the `*_FILE` variant is still the
better one: a value in the environment is visible to anything running as the
same user, and to child processes.

## Regenerating the token

The token is `"hv1_" + base64url(HKDF-SHA256(ikm=secret, salt=empty, info="hook-vault.auth.v1", L=32))`.
It is deterministic, so a consumer that loses its token can recompute it from the
secret instead of rotating keys:

```bash
hook-vault keygen --secret <secret_key>
```

## What to do when decryption fails

| Symptom | Cause |
|---|---|
| opens with one key, fails with another | the event's `kid` tells you which one |
| `cannot open` on a `rejected` event | expected: it was stored as evidence, not delivered |
| base64 error | missing padding (Python, Java) |
| works locally, fails in production | a proxy rewrote the body before hashing, or the secret is not the one registered |
