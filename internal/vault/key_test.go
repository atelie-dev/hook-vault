package vault

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

// Vector produced by PyNaCl (libsodium) — the contract with every consumer is
// that a payload sealed on this server opens there, and vice versa.
const (
	libsodiumSecret = "w-Dag07_SU4zroW4K4zupxiiyeop2q2VJoxlOyVg8Gs"
	libsodiumPublic = "Na578D0r1oE2mDC88bX81qxemS2wjjdtn0YxFASYskk"
	libsodiumSealed = "G1xfVZktbXfM5TeQX4nd1SN4WXP-SZA5L_4ctIDqFDWGRj7vPZno4RSJbzAr4DA5Kqa5RqS82WN5Np7DoJA7r5fBuFRBCPcTKA"
	libsodiumPlain  = "hook-vault interop vector"
)

func decode(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decode %q: %v", s, err)
	}
	return raw
}

func TestOpenLibsodiumVector(t *testing.T) {
	secret := decode(t, libsodiumSecret)
	public := decode(t, libsodiumPublic)
	sealed := decode(t, libsodiumSealed)

	var pk, sk [32]byte
	copy(pk[:], public)
	copy(sk[:], secret)

	plaintext, err := Open(sealed, &pk, &sk)
	if err != nil {
		t.Fatalf("open libsodium ciphertext: %v", err)
	}
	if string(plaintext) != libsodiumPlain {
		t.Fatalf("plaintext = %q, want %q", plaintext, libsodiumPlain)
	}

	// Deriving from the raw secret must land on the same public key libsodium
	// computed, otherwise consumers cannot decrypt what we seal.
	key, err := FromSecret(secret)
	if err != nil {
		t.Fatalf("FromSecret: %v", err)
	}
	if !bytes.Equal(key.Public[:], public) {
		t.Fatalf("derived public key %x, want %x", key.Public, public)
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	key, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	payload := bytes.Repeat([]byte("payload "), 1000)
	sealed, err := SealTo(payload, &key.Public)
	if err != nil {
		t.Fatalf("SealTo: %v", err)
	}
	if len(sealed) != len(payload)+AnonymousOverhead {
		t.Fatalf("sealed length = %d, want %d", len(sealed), len(payload)+AnonymousOverhead)
	}
	if bytes.Contains(sealed, []byte("payload")) {
		t.Fatal("sealed box contains plaintext")
	}

	opened, err := Open(sealed, &key.Public, &key.Secret)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(opened, payload) {
		t.Fatal("opened payload differs from the original")
	}
}

func TestOpenWrongKeyFails(t *testing.T) {
	owner, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	intruder, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	sealed, err := SealTo([]byte("secret"), &owner.Public)
	if err != nil {
		t.Fatalf("SealTo: %v", err)
	}
	if _, err := Open(sealed, &intruder.Public, &intruder.Secret); err == nil {
		t.Fatal("opened a sealed box with the wrong key")
	}
	if _, err := Open(sealed[:AnonymousOverhead-1], &owner.Public, &owner.Secret); err == nil {
		t.Fatal("opened a truncated sealed box")
	}
}

func TestTokenIsDerivedAndDistinct(t *testing.T) {
	key, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if !strings.HasPrefix(key.Token, TokenPrefix) {
		t.Fatalf("token %q lacks prefix %q", key.Token, TokenPrefix)
	}
	if key.Token == EncodeSecret(key.Secret[:]) {
		t.Fatal("token must not be the secret key")
	}

	again, err := FromSecret(key.Secret[:])
	if err != nil {
		t.Fatalf("FromSecret: %v", err)
	}
	if again.Token != key.Token {
		t.Fatal("token derivation is not deterministic")
	}
	if again.KID != key.KID {
		t.Fatal("key id derivation is not deterministic")
	}

	other, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if other.Token == key.Token {
		t.Fatal("two keys share a token")
	}

	if got := len(HashToken(key.Token)); got != 32 {
		t.Fatalf("token hash length = %d, want 32", got)
	}
	if !TokensEqual(key.Token, again.Token) {
		t.Fatal("TokensEqual rejected identical tokens")
	}
	if TokensEqual(key.Token, other.Token) {
		t.Fatal("TokensEqual accepted different tokens")
	}
}

func TestParsePublicKey(t *testing.T) {
	key, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	encoded := EncodePublic(key.Public[:])

	for _, in := range []string{encoded, encoded + "=", strings.TrimSpace("  " + encoded + "\n")} {
		parsed, err := ParsePublicKey(in)
		if err != nil {
			t.Fatalf("ParsePublicKey(%q): %v", in, err)
		}
		if !bytes.Equal(parsed[:], key.Public[:]) {
			t.Fatalf("ParsePublicKey(%q) round trip mismatch", in)
		}
	}

	if _, err := ParsePublicKey("not-a-key"); err == nil {
		t.Fatal("ParsePublicKey accepted garbage")
	}
	if _, err := ParsePublicKey("AAAA"); err == nil {
		t.Fatal("ParsePublicKey accepted a short key")
	}
}
