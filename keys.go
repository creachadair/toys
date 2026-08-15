package toys

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
)

// CipherKey is a symmetric encryption key. It must be exactly [CipherKeySize] bytes.
type CipherKey struct {
	data  [CipherKeySize]byte
	isSet bool
}

// Set replaces the contents of p with a copy of the given key, and returns *p.
// If len(key) == 0, the key is cleared; otherwise Set panics if len(key) is
// not exactly [CipherKeySize].
func (c *CipherKey) Set(key []byte) CipherKey {
	clear(c.data[:])
	if len(key) == 0 {
		c.isSet = false
	} else if len(key) != CipherKeySize {
		panic(fmt.Sprintf("key is %d bytes, want %d", len(key), CipherKeySize))
	} else {
		copy(c.data[:], key)
		c.isSet = true
	}
	return *c
}

// Bytes returns a slice of the current contents of p.  The caller must not
// modify the contents of the slice. It returns nil if p is invalid.
func (c CipherKey) Bytes() []byte {
	if !c.isSet {
		return nil
	}
	return c.data[:]
}

// IsValid reports whether c is valid.
func (c CipherKey) IsValid() bool { return c.isSet }

// CipherKeySize is the required size in bytes of symmetric keys used by a [Cipher].
const CipherKeySize = 32

// CipherNonce is a symmetric encryption nonce.
type CipherNonce uint64

// MaxCipherNonce is the maximum possible encryption nonce.
const MaxCipherNonce = math.MaxUint64

// Append appends the little-endian encoding of n to dst and returns the resulting slice.
func (n CipherNonce) Append(dst []byte) []byte {
	return binary.LittleEndian.AppendUint64(dst, uint64(n))
}

// PublicKey is an opaque encoding of a public key.
type PublicKey struct{ data []byte }

// Set replaces the contents of p with a copy of the given key, and returns *p.
func (p *PublicKey) Set(key []byte) PublicKey { clear(p.data); p.data = bytes.Clone(key); return *p }

// Bytes returns a slice of the current contents of p.  The caller must not
// modify the contents of the slice.
func (p PublicKey) Bytes() []byte { return p.data }

// IsValid reports whether p is valid, meaning that key material is present.
// It does not validate whether the key is cryptographically functional.
func (p PublicKey) IsValid() bool { return len(p.data) != 0 }

// PrivateKey is an opaque encoding of a private key.
type PrivateKey struct{ data []byte }

// Set replaces the contents of p with a copy of the given key, and returns *p.
func (p *PrivateKey) Set(key []byte) PrivateKey { clear(p.data); p.data = bytes.Clone(key); return *p }

// Bytes returns a slice of the current contents of p.  The caller must not
// modify the contents of the slice.
func (p PrivateKey) Bytes() []byte { return p.data }

// IsValid reports whether p is valid, meaning that key material is present.
// It does not validate whether the key is cryptographically functional.
func (p PrivateKey) IsValid() bool { return len(p.data) != 0 }

// KeyPair contains the encodings of a public/private key pair.
// The size and representation of the key material is implementation-defined.
type KeyPair struct {
	Public  PublicKey
	Private PrivateKey
}

// IsValid reports whether kp is valid. This check is purely syntactic; it does
// not validate any cryptographic relationship between the keys.
func (kp KeyPair) IsValid() bool { return kp.Public.IsValid() && kp.Private.IsValid() }
