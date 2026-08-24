// Package state defines types that manage the state of Noise handshakes,
// symmetric encryption, and cipher keys.
//
// # Overview
//
// Call [NewHandshake] to construct a [Handshake].
// Use the [Handshake.WriteMessage] and [Handshake.ReadMessage] methods to
// complete the handshake and obtain [Cipher] values to use for encrypting
// session traffic.
package state

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/creachadair/toys"
	"github.com/creachadair/toys/internal/keys"
	"github.com/creachadair/toys/pattern"
)

var (
	// ErrNoCipherKey is a sentinel error reported by [Cipher.EncryptWithData]
	// when no cipher key is present to perform encryption.
	ErrNoCipherKey = errors.New("no cipher key")

	// ErrNonceOverflow is a sentinel error reported by [Cipher.EncryptWithData]
	// when the current nonce exceeds the maximum usable value.
	ErrNonceOverflow = errors.New("nonce overflow")
)

// A Cipher carries a key and a nonce, and implements symmetric encryption and
// decryption using that key. Eacn succesful encryption or decryption operation
// increments the nonce.
type Cipher struct {
	cfg *toys.Config // must be non-nil when valid

	key   toys.CipherKey
	nonce toys.CipherNonce
}

// Config returns the [Config] value from which c was constructed.
// If it is nil, c is not valid for use.
func (c *Cipher) Config() *toys.Config { return c.cfg }

// init initializes c and sets its configuration. It returns c.
func (c *Cipher) init(cfg *toys.Config, key []byte) *Cipher {
	c.cfg, c.nonce = cfg, 0
	c.key.Set(key)
	return c
}

// Key returns the current cipher key. If no key is set, the result is invalid.
func (c *Cipher) Key() toys.CipherKey { return c.key }

// HasKey reports whether c contains a valid key.
func (c *Cipher) HasKey() bool { return c.cfg != nil && c.key.IsValid() }

// SetNonce updates the nonce to n.
func (c *Cipher) SetNonce(n toys.CipherNonce) { c.nonce = n }

// EncryptWithData encrypts plaintext and the specified additional data with
// the key. If c does not have a key, it reports [ErrNoCipherKey].
// In case of error, it returns the plaintext unmodified along with the error.
func (c *Cipher) EncryptWithData(data, plaintext []byte) ([]byte, error) {
	if !c.HasKey() {
		return plaintext, ErrNoCipherKey
	} else if c.nonce == toys.MaxCipherNonce {
		return plaintext, ErrNonceOverflow
	}
	ctext := make([]byte, 0, len(plaintext)+16)
	nonce := c.nonce
	ctext, err := c.cfg.Cipher().Encrypt(ctext, c.key, nonce, data, plaintext)
	if err != nil {
		return plaintext, err
	}
	c.nonce++ // N.B. after succeeding
	return ctext, nil
}

// DecryptWithData decrypts ciphertext and validates the specified additional
// data with the key. If c does not have a key, it reports [ErrNoCipherKey].
// In case of error, it returns the ciphertext unmodified along with the error.
func (c *Cipher) DecryptWithData(data, ciphertext []byte) ([]byte, error) {
	if !c.HasKey() {
		return ciphertext, ErrNoCipherKey
	} else if c.nonce == toys.MaxCipherNonce {
		return ciphertext, ErrNonceOverflow
	}
	ptext := make([]byte, 0, len(ciphertext))
	nonce := c.nonce
	ptext, err := c.cfg.Cipher().Decrypt(ptext, c.key, nonce, data, ciphertext)
	if err != nil {
		return ciphertext, err
	}
	c.nonce++ // N.B. after succeeding
	return ptext, nil
}

// Rekey rekeys c without modifying the current nonce. It reports
// [ErrNoCipherKey] if c does not contain a key. Otherwise, any error reported
// is from the underlying [Cipher.Rekey] implementation.
func (c *Cipher) Rekey() error {
	if !c.HasKey() {
		return ErrNoCipherKey
	}
	newKey, err := c.cfg.Cipher().Rekey(c.key)
	if err != nil {
		return err
	}
	c.key = newKey
	return nil
}

// A Symmetric couples a [Cipher] with a state hash and a chaining key, to
// allow rotating encryption keys based on the current state.
type Symmetric struct {
	cfg *toys.Config // must be non-nil when valid

	cstate    Cipher
	chainKey  []byte // exactly hf.HashSize() bytes
	stateHash []byte // exactly hf.HashSize() bytes
}

// Config returns the [Config] value from which s was constructed.
// If it is nil, s is not valid for use.
func (s *Symmetric) Config() *toys.Config { return s.cfg }

// init initializes s with the specified config and protocol name, and returns
// s.  Any previous state is discarded.
func (s *Symmetric) init(cfg *toys.Config, protocolName []byte) *Symmetric {
	s.cfg = cfg
	h := make([]byte, s.cfg.Hash().HashSize())
	if len(protocolName) > len(h) {
		h = s.cfg.Hash().Digest(h[:0], protocolName)
	} else {
		copy(h, protocolName)
	}
	s.cstate.init(s.cfg, nil)
	s.chainKey = bytes.Clone(h)
	s.stateHash = h
	return s
}

// MixKey updates the chain key of s with data, and derives and installs a new
// cipher key from the updated result.
func (s *Symmetric) MixKey(data []byte) {
	ck, tempKey := keys.HKDF2(s.cfg.Hash(), s.chainKey, data)
	s.chainKey = ck
	s.cstate.init(s.cfg, tempKey[:toys.CipherKeySize])
}

// MixHash updates the state hash of s with data.
func (s *Symmetric) MixHash(data []byte) {
	next := append(s.stateHash, data...)
	s.stateHash = s.cfg.Hash().Digest(s.stateHash[:0], next)
}

// MixKeyAndHash updates the chain key of s with data, and derives and installs
// a new cipher key from the updated result. In addition, it updates the state
// hash with a separate key derived from the updated chain key.
func (s *Symmetric) MixKeyAndHash(data []byte) {
	ck, hashKey, tempKey := keys.HKDF3(s.cfg.Hash(), s.chainKey, data)
	s.chainKey = ck
	s.MixHash(hashKey)
	if len(tempKey) > 32 { // should be 32 or 64 exactly
		tempKey = tempKey[:32]
	}
	s.cstate.init(s.cfg, tempKey)
}

// HandshakeHash appends the current state hash of s to dst, and returns the
// resulting slice.
func (s *Symmetric) HandshakeHash(dst []byte) []byte { return append(dst, s.stateHash...) }

// EncryptAndHash encrypts the specified plaintext, mixes the resulting
// ciphertext into the state hash, and returns the ciphertext.
// If s does not have a cipher key, the plaintext is mixed and returned unchanged.
// Any other error in encryption does not modify the state of s.
// In case of error, plaintext is returned along with the error.
func (s *Symmetric) EncryptAndHash(plaintext []byte) ([]byte, error) {
	ctext, err := s.cstate.EncryptWithData(s.stateHash, plaintext)
	if err != nil && !errors.Is(err, ErrNoCipherKey) {
		return plaintext, err
	}
	s.MixHash(ctext)
	return ctext, nil
}

// DecryptAndHash decrypts the specified ciphertext, mixes the ciphertext into
// the state hash, and returns the resulting plaintext.
// If s does not have a cipher key, the ciphertext is mixed and returned unchanged.
// Any other error in decryption does not modify the state of s.
// In case of error, ciphertext is returned along with the error.
func (s *Symmetric) DecryptAndHash(ciphertext []byte) ([]byte, error) {
	ptext, err := s.cstate.DecryptWithData(s.stateHash, ciphertext)
	if err != nil && !errors.Is(err, ErrNoCipherKey) {
		return ciphertext, err
	}
	s.MixHash(ciphertext)
	return ptext, nil
}

// Split initializes and returns a pair of [Cipher] values derived from the
// current state of s. The caller assumes ownership of the results.
func (s *Symmetric) Split() (A, B *Cipher) {
	akey, bkey := keys.HKDF2(s.cfg.Hash(), s.chainKey, nil)
	A = new(Cipher).init(s.cfg, akey[:toys.CipherKeySize])
	B = new(Cipher).init(s.cfg, bkey[:toys.CipherKeySize])
	return
}

// A Handshake represents the state of a Noise handshake.
// Use [Handshake.ReadMessage] and [Handshake.WriteMessage] to
// advance the state of the handshake. Once complete, the final
// state digest can be obtained via [Handshake.StateHash].
type Handshake struct {
	cfg *toys.Config // must be non-nil when valid

	pattern   pattern.Handshake // read-only
	pc        int               // offset of the next unprocessed row of pattern
	a, b      *Cipher           // transport keys, once complete
	symmetric Symmetric
	protoName []byte

	isResponder     bool
	prologue        []byte
	psk             toys.CipherKey
	localStatic     toys.KeyPair
	remoteStatic    toys.PublicKey
	localEphemeral  toys.KeyPair
	remoteEphemeral toys.PublicKey
}

// Config returns the [Config] value from which h was constructed.
// If it is nil, h is not valid for use.
func (h *Handshake) Config() *toys.Config { return h.cfg }

// ProtocolName reports the protocol name for the handshake used by h.
func (h *Handshake) ProtocolName() string { return string(h.protoName) }

// StateHash reports the current state hash of the handshake.
func (h *Handshake) StateHash() []byte {
	return h.symmetric.HandshakeHash(make([]byte, 0, h.cfg.Hash().HashSize()))
}

// More reports whether there is a handshake step still to execute.
func (h *Handshake) More() bool { return h.pc < h.pattern.Len() }

// TransportKeys returns the transport keys generated by a completed
// handshake. If h is not complete, it returns nil, nil.
func (h *Handshake) TransportKeys() (A, B *Cipher) { return h.a, h.b }

// IsWriteStep reports whether the next handshake step is a write for the
// configured party.
func (h *Handshake) IsWriteStep() bool { return (h.pc%2 == 0) != h.isResponder }

func (h *Handshake) init() *Handshake {
	h.symmetric.init(h.cfg, h.protoName)
	h.symmetric.MixHash(h.prologue)

	// 5.3: Call MixHash once for each public key listed in the pre-messages
	// from the handshake pattern, with the specified public key as input.  If
	// both initiator and responder have pre-messages, the initiator's public
	// keys are hashed first. f multiple public keys are listed in either
	// party's pre-message, the public keys are hashed in the order that they
	// are listed.
	//
	// Note that per 7.1, a pre-message with two tokens must be "e, s", so the
	// ephemeral key goes first.
	istatic, rstatic := h.localStatic.Public, h.remoteStatic
	iephem, rephem := h.localEphemeral.Public, h.remoteEphemeral
	if h.isResponder {
		istatic, rstatic = rstatic, istatic
		iephem, rephem = rephem, iephem
	}
	if h.pattern.Initiator.HasEphemeral() && iephem.IsValid() {
		h.symmetric.MixHash(iephem.Bytes())
	}
	if h.pattern.Initiator.HasStatic() && istatic.IsValid() {
		h.symmetric.MixHash(istatic.Bytes())
	}
	if h.pattern.Responder.HasEphemeral() && rephem.IsValid() {
		h.symmetric.MixHash(rephem.Bytes())
	}
	if h.pattern.Responder.HasStatic() && rstatic.IsValid() {
		h.symmetric.MixHash(rstatic.Bytes())
	}
	return h
}

// WriteMessage processes the next message pattern of h into w, and then if
// payload is non-empty, encrypts (if possible) and writes it to w also.
func (h *Handshake) WriteMessage(w io.Writer, payload []byte) error {
	row := h.pattern.Pattern(h.pc)
	h.pc++
	isLast := h.pc >= h.pattern.Len()

	for _, tok := range row {
		switch tok {
		case toys.E:
			if h.localEphemeral.IsValid() {
				panic("protocol error: local ephemeral key already set")
			}
			kp, err := h.cfg.DH().GenerateKeyPair()
			if err != nil {
				return fmt.Errorf("generate ephemeral keypair: %w", err)
			}
			h.localEphemeral = kp
			if _, err := w.Write(kp.Public.Bytes()); err != nil {
				return fmt.Errorf("write public key: %w", err)
			}
			h.symmetric.MixHash(kp.Public.Bytes())

		case toys.S:
			ek, err := h.symmetric.EncryptAndHash(h.localStatic.Public.Bytes())
			if err != nil {
				return fmt.Errorf("encrypt static: %w", err)
			}
			if _, err := w.Write(ek); err != nil {
				return fmt.Errorf("write public key: %w", err)
			}

		case toys.EE:
			key, err := h.cfg.DH().ComputeKey(h.localEphemeral, h.remoteEphemeral)
			if err != nil {
				return fmt.Errorf("compute ee DH: %w", err)
			}
			h.symmetric.MixKey(key)

		case toys.ES:
			var key []byte
			var err error
			if h.isResponder {
				key, err = h.cfg.DH().ComputeKey(h.localStatic, h.remoteEphemeral)
			} else {
				key, err = h.cfg.DH().ComputeKey(h.localEphemeral, h.remoteStatic)
			}
			if err != nil {
				return fmt.Errorf("compute es DH: %w", err)
			}
			h.symmetric.MixKey(key)

		case toys.SE:
			var key []byte
			var err error
			if h.isResponder {
				key, err = h.cfg.DH().ComputeKey(h.localEphemeral, h.remoteStatic)
			} else {
				key, err = h.cfg.DH().ComputeKey(h.localStatic, h.remoteEphemeral)
			}
			if err != nil {
				return fmt.Errorf("compute se DH: %w", err)
			}
			h.symmetric.MixKey(key)

		case toys.SS:
			key, err := h.cfg.DH().ComputeKey(h.localStatic, h.remoteStatic)
			if err != nil {
				return fmt.Errorf("compute ss DH: %w", err)
			}
			h.symmetric.MixKey(key)

		case toys.PSK:
			h.symmetric.MixKeyAndHash(h.psk.Bytes())

		default:
			panic(fmt.Sprintf("invalid handshake token %q", tok))
		}
	}

	// TODO(creachadair): SHOULD we skip this if payload is empty?  I think
	// probably so, since on decryption an empty input is not valid, so we
	// should not write anything (even an authenticator) for an empty payload.
	if len(payload) != 0 {
		enc, err := h.symmetric.EncryptAndHash(payload)
		if err != nil {
			return fmt.Errorf("encrypt payload: %w", err)
		}
		defer clear(enc)
		if _, err := w.Write(enc); err != nil {
			return fmt.Errorf("write payload: %w", err)
		}
	}

	if isLast {
		h.a, h.b = h.symmetric.Split()
	}
	return nil
}

// ReadMessage processes message as the input to the next message pattern of h,
// and writes the decrypted payload (if any) to w.
func (h *Handshake) ReadMessage(w io.Writer, message []byte) error {
	row := h.pattern.Pattern(h.pc)
	h.pc++
	isLast := h.pc >= h.pattern.Len()
	ds := h.cfg.DH().OutputSize()

	for _, tok := range row {
		switch tok {
		case toys.E:
			if h.remoteEphemeral.IsValid() {
				panic("protocol error: remote ephemeral key already set")
			} else if len(message) < ds {
				return fmt.Errorf("truncated message (%d < %d bytes)", len(message), ds)
			}
			h.remoteEphemeral.Set(message[:ds])
			h.symmetric.MixHash(h.remoteEphemeral.Bytes())
			message = message[ds:]

		case toys.S:
			if h.remoteStatic.IsValid() {
				panic("protocol error: remote static key already set")
			}
			want := ds
			if h.symmetric.cstate.HasKey() {
				want += 16
			}
			if len(message) < want {
				return fmt.Errorf("truncated message (%d < %d bytes)", len(message), want)
			}
			dk, err := h.symmetric.DecryptAndHash(message[:want])
			if err != nil {
				return fmt.Errorf("decrypt static key: %w", err)
			}
			h.remoteStatic.Set(dk)
			message = message[want:]

		case toys.EE:
			key, err := h.cfg.DH().ComputeKey(h.localEphemeral, h.remoteEphemeral)
			if err != nil {
				return fmt.Errorf("compute ee DH: %w", err)
			}
			h.symmetric.MixKey(key)

		case toys.ES:
			var key []byte
			var err error
			if h.isResponder {
				key, err = h.cfg.DH().ComputeKey(h.localStatic, h.remoteEphemeral)
			} else {
				key, err = h.cfg.DH().ComputeKey(h.localEphemeral, h.remoteStatic)
			}
			if err != nil {
				return fmt.Errorf("compute es DH: %w", err)
			}
			h.symmetric.MixKey(key)

		case toys.SE:
			var key []byte
			var err error
			if h.isResponder {
				key, err = h.cfg.DH().ComputeKey(h.localEphemeral, h.remoteStatic)
			} else {
				key, err = h.cfg.DH().ComputeKey(h.localStatic, h.remoteEphemeral)
			}
			if err != nil {
				return fmt.Errorf("compute se DH: %w", err)
			}
			h.symmetric.MixKey(key)

		case toys.SS:
			key, err := h.cfg.DH().ComputeKey(h.localStatic, h.remoteStatic)
			if err != nil {
				return fmt.Errorf("compute ss DH: %w", err)
			}
			h.symmetric.MixKey(key)

		case toys.PSK:
			h.symmetric.MixKeyAndHash(h.psk.Bytes())

		default:
			panic(fmt.Sprintf("invalid handshake token %q", tok))
		}
	}

	if len(message) != 0 {
		dec, err := h.symmetric.DecryptAndHash(message)
		if err != nil {
			return fmt.Errorf("decrypt payload: %w", err)
		}
		defer clear(dec)
		if _, err := w.Write(dec); err != nil {
			return fmt.Errorf("write payload: %w", err)
		}
	}

	if isLast {
		h.a, h.b = h.symmetric.Split()
	}
	return nil
}

// NewHandshake initializes a new empty handshake with the specified parameters.
func NewHandshake(hc HandshakeConfig) (*Handshake, error) {
	if hc.Noise == nil {
		return nil, errors.New("missing noise config")
	} else if !hc.Pattern.IsValid() {
		return nil, errors.New("invalid handshake pattern")
	}
	pat := hc.Pattern

	// Check constraints.
	var errs []error
	fail := func(msg string, args ...any) {
		errs = append(errs, fmt.Errorf(msg, args...))
	}
	if hc.Responder {
		if pat.RespNeedsStatic && !hc.LocalStatic.IsValid() {
			fail("responder requires a static key")
		}
		if pat.Initiator.HasStatic() && !hc.RemoteStatic.IsValid() {
			fail("responder requires initiator static key")
		}
		if pat.Initiator.HasEphemeral() && !hc.RemoteEphemeral.IsValid() {
			fail("responder requires initiator ephemeral key")
		}
	} else {
		if pat.InitNeedsStatic && !hc.LocalStatic.IsValid() {
			fail("initiator requires a static key")
		}
		if pat.Responder.HasStatic() && !hc.RemoteStatic.IsValid() {
			fail("initiator requires responder static key")
		}
		if pat.Responder.HasEphemeral() && !hc.RemoteEphemeral.IsValid() {
			fail("initiator requires responder ephemeral key")
		}
	}
	if pat.NeedsPSK && !hc.PreSharedKey.IsValid() {
		fail("handshake requires a pre-shared key")
	}
	if len(errs) != 0 {
		return nil, errors.Join(errs...)
	}

	return (&Handshake{
		cfg: hc.Noise,

		pattern:     pat,
		isResponder: hc.Responder,
		prologue:    hc.Prologue,
		psk:         hc.PreSharedKey,

		protoName: toys.ProtocolName{
			Handshake: pat.Label,
			DH:        hc.Noise.DH().Label(),
			Cipher:    hc.Noise.Cipher().Label(),
			Hash:      hc.Noise.Hash().Label(),
		}.Bytes(),

		localStatic:     hc.LocalStatic,
		remoteStatic:    hc.RemoteStatic,
		localEphemeral:  hc.LocalEphemeral,
		remoteEphemeral: hc.RemoteEphemeral,
	}).init(), nil
}

// HandshakeConfig specifies the configuration for a handshake (see [NewHandshake]).
type HandshakeConfig struct {
	// The algorithm definitions to use. It must be non-nil.
	Noise *toys.Config

	// The handshake pattern to use (required).
	Pattern pattern.Handshake

	// If true, configure the handshake state for a responder.
	// Otherwise, it defaults to the initiator role.
	Responder bool

	// If non-empty, shared prologue data. Note that both parties must agree
	// on the contents of the prologue for authentication to succeed.
	Prologue []byte

	// A pre-shared encryption key. Both parties must agree on the value of this
	// key for authentication to succeed. This is ignored unless the handshake
	// pattern requires it.
	PreSharedKey toys.CipherKey

	// The local party's static key pair.
	// This is optional unless it is required by the handshake pattern.
	LocalStatic toys.KeyPair

	// The remote party's static public key.
	// This is optional unless it is required by the handshake pattern.
	RemoteStatic toys.PublicKey

	// The local party's ephemeral key pair (optional).
	LocalEphemeral toys.KeyPair

	// The remote party's ephemeral public key (optional).
	RemoteEphemeral toys.PublicKey
}
