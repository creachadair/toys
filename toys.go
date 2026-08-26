// Package toys implements the [Noise Protocol Framework].
//
// This is an experimental implementation intended for learning purposes, and
// is not suitable for production use.
//
// [Noise Protocol Framework]: https://noiseprotocol.org/noise.html
package toys

import (
	"errors"
	"fmt"
	"strings"

	"github.com/creachadair/toys/internal/parse"
)

// DH defines the implementation of Diffie-Hellman operations.
type DH interface {
	// Label reports the label to use for the concrete implementation in a Noise
	// protocol name.
	Label() string

	// OutputSize reports the size in bytes of DH keys and outputs.
	// It must be constant greater than or equal to 32.
	OutputSize() int

	// GenerateKeyPair generates a new Diffie-Hellman key pair.
	// The resulting public value must be exactly OutputSize bytes.
	GenerateKeyPair() (KeyPair, error)

	// ComputeKey performs the Diffie-Hellman computation on public using the
	// specified key pair. The implmentation is responsible for validating the
	// structure of the inputs, and reporting an error if they are invalid.
	// The resulting output (on success) must be exactly OutputSize bytes.
	ComputeKey(kp KeyPair, public PublicKey) ([]byte, error)
}

// Cipher defines a symmetric encryption implementation.
type Cipher interface {
	// Label reports the label to use for the concrete implementation in a Noise
	// protocol name.
	Label() string

	// Encrypt encrypts plaintext with ek, using an AEAD construction with ad as
	// the additional data, and appends the ciphertext to dst, which may be nil.
	// On success, Encrypt appends exactly len(plaintext)+16 bytes, and returns
	// the resulting slice.
	Encrypt(dst []byte, ek CipherKey, nonce CipherNonce, ad, plaintext []byte) ([]byte, error)

	// Decrypt decrypts ciphertext with dk, using an AEAD construction expecting
	// ad as the additional data, and appends the plaintext to dst.
	Decrypt(dst []byte, dk CipherKey, nonce CipherNonce, ad, ciphertext []byte) ([]byte, error)

	// Rekey returns a new [CipherKey] as a pseudorandom function of old.
	Rekey(old CipherKey) (CipherKey, error)
}

// Hash defines a collision-resistant cryptographic hash function.
type Hash interface {
	// Label reports the label to use for the concrete implementation in a Noise
	// protocol name.
	Label() string

	// HashSize reports the size in bytes of the hash output.
	// It must be either 32 or 64.
	HashSize() int

	// BlockSize reports the size in bytes of the hash's processing block.
	BlockSize() int

	// Digest appends a cryptographic digest of the specified input to dst, and
	// returns the resulting slice.  It must append exactly HashSize bytes.
	Digest(dst, input []byte) []byte
}

// A Config carries the concrete implementations of the required interfaces for
// the Noise protocol. Each of the fields must be non-nil.
type Config struct {
	dh     DH
	cipher Cipher
	hash   Hash
}

// DH returns the [DH] implementation associated with c.
func (c Config) DH() DH { return c.dh }

// Cipher returns the [Cipher] implementation associated with c.
func (c Config) Cipher() Cipher { return c.cipher }

// HashFunction returns the [Hash] implementation associated with c.
func (c Config) Hash() Hash { return c.hash }

// NewConfig constructs a [Config] using the specified implementations.
//
// All the parameters must be non-nil, the hash length must be 32 or 64,
// the DH output size must be at least 32 bytes, and the labels for each
// of the parameters must be valid for use in a Noise protocol name.
// If any of these constraints is violated, NewConfig will panic.
func NewConfig(dh DH, cipher Cipher, hf Hash) *Config {
	if dh == nil || cipher == nil || hf == nil {
		panic("missing required parameter")
	} else if hs := hf.HashSize(); hs != 32 && hs != 64 {
		panic(fmt.Sprintf("hash size %d is not 32 or 64", hs))
	} else if os := dh.OutputSize(); os < 32 {
		panic(fmt.Sprintf("output size %d is less than 32 bytes", os))
	} else if n := dh.Label(); !isValidAlgorithmName(n) {
		panic(fmt.Sprintf("invalid DH label: %q", n))
	} else if n := cipher.Label(); !isValidAlgorithmName(n) {
		panic(fmt.Sprintf("invalid cipher label: %q", n))
	} else if n := hf.Label(); !isValidAlgorithmName(n) {
		panic(fmt.Sprintf("invalid hash label: %q", n))
	}
	return &Config{dh: dh, cipher: cipher, hash: hf}
}

// DefaultCipherRekey is a default implementation of the [Cipher.Rekey] method
// that may be used when the cipher definition does not provide a more specific
// algorithm. See 4.2 "Cipher Functions" in the Noise spec.
func DefaultCipherRekey(c Cipher, old CipherKey) (CipherKey, error) {
	var zeroes [CipherKeySize]byte
	var buf [CipherKeySize + 16]byte
	var out CipherKey

	nkey, err := c.Encrypt(buf[:0], old, MaxCipherNonce, nil, zeroes[:])
	if err != nil {
		return out, err
	}
	return out.Set(nkey[:CipherKeySize]), nil
}

func isValidAlgorithmName(s string) bool {
	return s != "" && !strings.ContainsFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '/')
	})
}

// A ProtocolName is the parsed representation of a Noise protocol name.
type ProtocolName struct {
	Handshake string // the name of the handshake pattern (including modifiers)
	DH        string // the name of the DH algorithm
	Cipher    string // the name of the Cipher algorithm
	Hash      string // the name of the Hash algorithm
}

// String returns the composed protocol name of p.
func (p ProtocolName) String() string { return string(p.Bytes()) }

// Bytes returns the composed protocol name of p, in the format to be sent on
// the wire.
func (p ProtocolName) Bytes() []byte {
	return fmt.Appendf(nil, "Noise_%s_%s_%s_%s", p.Handshake, p.DH, p.Cipher, p.Hash)
}

// ParseProtocolName parses the string representation of a Noise [protocol name].
//
// Grammar:
//
//	proto     = 'Noise_' handshake '_' dh '_' cipher '_' hash
//	handshake = <hword>
//	dh        = <aword>
//	cipher    = <aword>
//	hash      = <aword>
//	<hword>   = [A-Z][+A-Za-z0-9]*
//	<aword>   = [A-Za-z0-9/]+(\+[A-Za-z0-9/]+)*
//
// [protocol name]: https://noiseprotocol.org/noise.html#protocol-names-and-modifiers
func ParseProtocolName(s string) (ProtocolName, error) {
	parts := strings.SplitN(s, "_", 5)
	if len(parts) != 5 {
		return ProtocolName{}, errors.New("invalid protocol syntax")
	} else if parts[0] != "Noise" {
		return ProtocolName{}, errors.New("missing Noise prefix")
	} else if _, _, err := parse.PatternName(parts[1]); err != nil {
		return ProtocolName{}, fmt.Errorf("handshake name: %w", err)
	} else if _, err := parse.Algorithm(parts[2]); err != nil {
		return ProtocolName{}, fmt.Errorf("DH name: %w", err)
	} else if _, err := parse.Algorithm(parts[3]); err != nil {
		return ProtocolName{}, fmt.Errorf("cipher name: %w", err)
	} else if _, err := parse.Algorithm(parts[4]); err != nil {
		return ProtocolName{}, fmt.Errorf("hash name: %w", err)
	}
	return ProtocolName{
		Handshake: parts[1], DH: parts[2], Cipher: parts[3], Hash: parts[4],
	}, nil
}
