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
