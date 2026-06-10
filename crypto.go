package adp

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// base64url encoding without padding (RFC 4648 §5).
var b64 = base64.RawURLEncoding

// KeyPair holds a generated Ed25519 key pair plus the computed fingerprint.
type KeyPair struct {
	// PublicKey is the raw 32-byte Ed25519 public key.
	PublicKey ed25519.PublicKey
	// PrivateKey is the raw 64-byte Ed25519 private key (seed + pubkey).
	PrivateKey ed25519.PrivateKey
	// Fingerprint is the ADP-standard fingerprint string: "ed25519:" + base64url(SHA256(pubkey)).
	Fingerprint string
}

// GenerateKeyPair creates a new Ed25519 key pair and computes its fingerprint.
//
// The fingerprint is SHA-256 of the raw 32-byte public key, encoded as
// base64url without padding, and prefixed with "ed25519:".
func GenerateKeyPair() (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("adp: generate key pair: %w", err)
	}
	return &KeyPair{
		PublicKey:  pub,
		PrivateKey: priv,
		Fingerprint: ComputeFingerprint(pub),
	}, nil
}

// ComputeFingerprint returns the ADP-standard fingerprint for a raw Ed25519 public key.
//
// Format: "ed25519:" + base64url(SHA-256(raw_pubkey))
func ComputeFingerprint(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return "ed25519:" + b64.EncodeToString(h[:])
}

// Sign signs a message with the given Ed25519 private key and returns the
// base64url-encoded (without padding) signature.
//
// The message can be a string or []byte.
func Sign(priv ed25519.PrivateKey, message []byte) string {
	sig := ed25519.Sign(priv, message)
	return b64.EncodeToString(sig)
}

// Verify checks whether a base64url-encoded signature is valid for the given
// message and Ed25519 public key.
//
// The message can be a string or []byte.
func Verify(pub ed25519.PublicKey, message []byte, signature string) (bool, error) {
	sig, err := b64.DecodeString(signature)
	if err != nil {
		return false, fmt.Errorf("adp: decode signature: %w", err)
	}
	return ed25519.Verify(pub, message, sig), nil
}

// ExportKey encodes raw key bytes as a base64url string without padding.
func ExportKey(key []byte) string {
	return b64.EncodeToString(key)
}

// ImportKey decodes a base64url string (without padding) back to raw key bytes.
func ImportKey(encoded string) ([]byte, error) {
	key, err := b64.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("adp: import key: %w", err)
	}
	return key, nil
}

// ExportPublicKeySPKI wraps a raw 32-byte Ed25519 public key in an SPKI
// (SubjectPublicKeyInfo) DER structure and returns it as a base64url string.
//
// This is useful for the "full" field in agent.json identity.publicKey.
func ExportPublicKeySPKI(pub ed25519.PublicKey) string {
	spki := make([]byte, len(spkiPrefix)+len(pub))
	copy(spki, spkiPrefix)
	copy(spki[len(spkiPrefix):], pub)
	return b64.EncodeToString(spki)
}

// ExportPrivateKeyPKCS8 wraps a raw 32-byte Ed25519 private key seed in a PKCS#8
// DER structure and returns it as a base64url string.
func ExportPrivateKeyPKCS8(priv ed25519.PrivateKey) string {
	seed := priv.Seed()
	pkcs8 := make([]byte, len(pkcs8Prefix)+len(seed))
	copy(pkcs8, pkcs8Prefix)
	copy(pkcs8[len(pkcs8Prefix):], seed)
	return b64.EncodeToString(pkcs8)
}

// Ed25519 SPKI DER prefix (RFC 8410):
//
//	30 2a — SEQUENCE (42 bytes)
//	   30 05 — SEQUENCE (5 bytes)
//	      06 03 2b 65 70 — OID 1.3.101.112 (Ed25519)
//	   03 21 00 — BIT STRING (33 bytes, 0 unused bits)
var spkiPrefix = []byte{
	0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
	0x03, 0x21, 0x00,
}

// Ed25519 PKCS#8 DER prefix (RFC 8410):
//
//	30 2e — SEQUENCE (46 bytes)
//	   02 01 00 — INTEGER 0 (version)
//	   30 05 — SEQUENCE (5 bytes)
//	      06 03 2b 65 70 — OID 1.3.101.112 (Ed25519)
//	   04 22 — OCTET STRING (34 bytes)
//	      04 20 — OCTET STRING (32 bytes — the raw seed)
var pkcs8Prefix = []byte{
	0x30, 0x2e, 0x02, 0x01, 0x00,
	0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
	0x04, 0x22, 0x04, 0x20,
}
