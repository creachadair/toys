package dhs_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/creachadair/toys"
	"github.com/creachadair/toys/dhs"
)

var _ toys.DH = dhs.ECDH25519

func fromHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func keyPair(priv, pub []byte) toys.KeyPair {
	var out toys.KeyPair
	out.Private.Set(priv)
	out.Public.Set(pub)
	return out
}

func TestECDH25519(t *testing.T) {
	// Test vector from https://datatracker.ietf.org/doc/html/rfc7748#section-6.1
	privAlice := fromHex(t, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	pubAlice := fromHex(t, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
	privBob := fromHex(t, "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
	pubBob := fromHex(t, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
	want := fromHex(t, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

	alice := keyPair(privAlice, pubAlice)
	bob := keyPair(privBob, pubBob)

	aliceGot, err := dhs.ECDH25519.ComputeKey(alice, bob.Public)
	if err != nil {
		t.Errorf("ComputeKey for Alice: %v", err)
	}
	bobGot, err := dhs.ECDH25519.ComputeKey(bob, alice.Public)
	if err != nil {
		t.Errorf("ComputeKey for Bob: %v", err)
	}
	if !bytes.Equal(aliceGot, want) {
		t.Errorf("Alice got %x, want %x", aliceGot, want)
	}
	if !bytes.Equal(bobGot, want) {
		t.Errorf("Bob got %x, want %x", bobGot, want)
	}
}
