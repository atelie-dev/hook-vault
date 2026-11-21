// hook-vault panel: browser-side key generation and token recovery.
//
// Everything here runs in the browser. The server receives the public key and
// the SHA-256 of the derived token — never the private key, never the token.
// That is the same contract as `hook-vault keygen`; this file is its browser
// rendering.
//
// Derivation is byte-identical to the Go implementation (internal/vault):
//
//	sk            : 32 bytes, the X25519 secret key
//	token         = "hv1_" + base64url(HKDF-SHA256(ikm=sk, salt=empty, info="hook-vault.auth.v1", 32))
//
// WebCrypto quirk #1: HKDF requires an importKey/deriveBits pair; the raw
// secret bytes are imported with algorithm "HKDF".
// WebCrypto quirk #2: an empty salt throws in some engines, so we pass 32 zero
// bytes — byte-identical to Go's nil salt, because HMAC zero-pads both to the
// block size.
// WebCrypto quirk #3: X25519 private keys export only as PKCS#8; the scalar is
// the trailing 32 bytes of that DER.
const INFO = 'hook-vault.auth.v1';
const PREFIX = 'hv1_';

const enc = new TextEncoder();

const b64url = (bytes) =>
  btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

const b64urlDecode = (text) =>
  Uint8Array.from(atob(text.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));

// deriveAll computes public key, secret key and API token from a key pair.
export async function deriveAll(pair) {
  const pk = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));

  const der = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
  const sk = der.slice(der.length - 32);

  const token = PREFIX + b64url(await deriveToken(sk));

  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(token)));

  return { pk, sk, token, tokenSha256: digest };
}

// deriveToken is the HKDF step, also used to recover a token from a secret.
export async function deriveToken(sk) {
  const base = await crypto.subtle.importKey('raw', sk, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new Uint8Array(32), // zero bytes, see comment above
        info: enc.encode(INFO),
      },
      base,
      256, // deriveBits counts BITS; 256 = the 32 bytes Go's hkdf produces
    ),
  );
}

// newPair generates a fresh X25519 key pair.
export async function newPair() {
  return crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveKey', 'deriveBits']);
}

// supported reports whether this browser can generate X25519 keys — some
// pre-2025 browsers ship WebCrypto without the secure curves, and the form
// must fall back to the offline keygen instead of failing on submit.
export async function supported() {
  try {
    const pair = await newPair();
    await crypto.subtle.exportKey('raw', pair.publicKey);
    return true;
  } catch {
    return false;
  }
}

export const api = { b64url, b64urlDecode, deriveAll, deriveToken, newPair, supported };
