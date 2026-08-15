// Package htest provides support for testing Noise handshakes.
package htest

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/creachadair/toys"
	"github.com/creachadair/toys/pattern"
	"github.com/creachadair/toys/state"
)

// MustCompile compiles the specified pattern config or logs a fatal error in t.
func MustCompile(t *testing.T, hc pattern.Config) pattern.Handshake {
	t.Helper()
	p, err := hc.Compile()
	if err != nil {
		t.Fatalf("Compile pattern: %v", err)
	}
	return p
}

// MustCompileText compiles the specified pattern config text or logs a fatal error in t.
func MustCompileText(t *testing.T, text string) pattern.Handshake {
	t.Helper()
	p, err := pattern.Compile(text)
	if err != nil {
		t.Fatalf("Compile config: %v", err)
	}
	return p
}

// NewHandshake compiles the specified handshake config or logs a fatal error in t.
func NewHandshake(t *testing.T, c state.HandshakeConfig) *state.Handshake {
	t.Helper()
	h, err := state.NewHandshake(c)
	if err != nil {
		t.Fatalf("Construct handshake: %v", err)
	}
	return h
}

// GenerateKeyPair generates a new key pair from config, or logs a fatal error in t.
func GenerateKeyPair(t *testing.T, config *toys.Config) toys.KeyPair {
	t.Helper()
	kp, err := config.DH().GenerateKeyPair()
	if err != nil {
		t.Fatalf("Generate key pair: %v", err)
	}
	return kp
}

// RunHandshake executes a complete handshake between initiator and responder,
// or logs a fatal error in t. On success, it returns the cipher states from
// the completed handshake on each side.
func RunHandshake(t *testing.T, initiator, responder *state.Handshake) (ia, ib, ra, rb *state.Cipher) {
	t.Helper()
	t.Logf("Running handshake for %q", initiator.ProtocolName())

	// Execute the handshake. In production use these would not be folded
	// together, but here we are running both sides of the exchange.
	// We simulate the "connection" by plumbing the output buffer from the
	// writer directly to the input of the reader, for each side.
	for i := 1; initiator.More(); i++ {
		t.Logf("-- begin step %d --", i)

		// Sanity check: Handshake parity should alternate.
		if oki, okr := initiator.IsWriteStep(), responder.IsWriteStep(); oki == okr {
			t.Errorf("IsWriteStep is %v for both initiator and responder", oki)
		}

		payload := fmt.Sprintf("payload-%d", i)
		if initiator.IsWriteStep() {
			// Write step: Initiator writes, responder reads.
			var msg bytes.Buffer
			var err error
			ia, ib, err = initiator.WriteMessage(&msg, []byte(payload))
			if err != nil {
				t.Fatalf("[initiator] write: %v", err)
			}
			t.Logf("[initiator] send data: %x", msg.Bytes())

			t.Logf("[responder] recv data: %x", msg.Bytes())
			var out bytes.Buffer
			ra, rb, err = responder.ReadMessage(&out, msg.Bytes())
			if err != nil {
				t.Fatalf("[responder] read: %v", err)
			}

			// Verify that we could decrypt the payload from the initiator.
			if s := out.String(); s != payload {
				t.Errorf("[responder] read payload: got %q, want %q", s, payload)
			}
		} else {
			// Read step: Responder writes, initiator reads.
			var msg bytes.Buffer
			var err error
			ra, rb, err = responder.WriteMessage(&msg, []byte(payload))
			if err != nil {
				t.Fatalf("[responder] write: %v", err)
			}
			t.Logf("[responder] send data: %x", msg.Bytes())

			t.Logf("[initiator] recv data: %x", msg.Bytes())
			var out bytes.Buffer
			ia, ib, err = initiator.ReadMessage(&out, msg.Bytes())
			if err != nil {
				t.Fatalf("[initiator] read: %v", err)
			}

			// Verify that we could decrypt the payload from the responder.
			if s := out.String(); s != payload {
				t.Errorf("[inititator] read payload: got %q, want %q", s, payload)
			}
		}
		t.Logf("-- done step %d --", i)
		if ih, rh := initiator.StateHash(), responder.StateHash(); !bytes.Equal(ih, rh) {
			t.Fatalf("Non-matching state hashes after step %d:\ninitiator: %x\nresponder: %x", i, ih, rh)
		}
	}

	// Reaching here without error, we should have two pairs of cipher keys.
	if ia == nil || ib == nil || ra == nil || rb == nil {
		t.Fatalf("After handshake: ia=%v ib=%v ra=%v rb=%v", ia, ib, ra, rb)
	}

	// The corresponding keys reported to initiator and responder should be equal.
	if a, b := ia.Key().Bytes(), ra.Key().Bytes(); !bytes.Equal(a, b) {
		t.Errorf("A keys for initiator and responder differ:\ninit: %q\nresp: %q", a, b)
	}
	if a, b := ib.Key().Bytes(), rb.Key().Bytes(); !bytes.Equal(a, b) {
		t.Errorf("B keys for initiator and responder differ:\ninit: %q\nresp: %q", a, b)
	}
	return
}
