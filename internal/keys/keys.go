// Package keys provides support functions for key generation and manipulation.
package keys

import (
	"crypto/rand"
	"fmt"

	"github.com/creachadair/toys"
)

// hashHMAC implements the HMAC construction using a [toys.Hash].
type hashHMAC struct {
	hf         toys.Hash
	ikey, okey []byte // of block size, key with ipad/opad XOR applied
}

// newHashHMAC initializes a new hashFunctionHMAC for hf and key.
func newHashHMAC(hf toys.Hash, key []byte) hashHMAC {
	// TODO(creachadair): This presumes the block size is always at least as
	// large as the hash output, which is true for all the algorithms anyone
	// cares about, but in theory might not be.

	bs := hf.BlockSize()
	hkey := make([]byte, 2*bs) // 1 for key^ipad, 1 for key^opad
	if len(key) > bs {
		hf.Digest(hkey[:0], key) // N.B. not append, we still want the whole length
	} else {
		copy(hkey, key)
	}
	ikey, okey := hkey[:bs:bs], hkey[bs:len(hkey):len(hkey)] // clip
	copy(okey, ikey)
	for i := range ikey {
		ikey[i] ^= 0x36
	}
	for i := range okey {
		okey[i] ^= 0x5c
	}
	return hashHMAC{hf: hf, ikey: ikey, okey: okey}
}

func (h hashHMAC) computeHMAC(input []byte) []byte {
	hs := h.hf.HashSize()

	// Allocate a scratch buffer for intermediate computations.
	// The first HashSize bytes hold the intermediate hash output, the rest is for
	// concatenating the key material with the hash input.
	//
	// tmp: [ ...hashsize... | ikey ... input ... ]
	//                        ^------- vi -------^
	tmp := make([]byte, hs, hs+len(h.ikey)+len(input))

	// HMAC(input) = H(okey || H(ikey || input))
	v1 := append(append(tmp[hs:hs], h.ikey...), input...) // ikey || input
	inner := h.hf.Digest(tmp[:0], v1)                     // H(ikey || input)
	v2 := append(append(tmp[hs:hs], h.okey...), inner...) // okey || inner
	outer := h.hf.Digest(nil, v2)                         // H(okey || inner); N.B. nil so caller does not alias tmp
	return outer
}

// HKDF2 constructs a pair of derived keys from inputKey using chainKey.
// The chainKey must be exactly hf.HashSize() bytes.
// The inputKey must be empty, the length of the target DH output, or 32 bytes.
func HKDF2(hf toys.Hash, chainKey, inputKey []byte) (k1, k2 []byte) {
	k1, k2, _ = hkdfInternal(hf, chainKey, inputKey, false)
	return
}

// HKDF3 constructs a triple of derived keys from inputKey and chainKey.
// The chainKey must be exactly hf.HashSize() bytes.
// The inputKey must be empty, the length of the target DH output, or 32 bytes.
func HKDF3(hf toys.Hash, chainKey, inputKey []byte) (k1, k2, k3 []byte) {
	return hkdfInternal(hf, chainKey, inputKey, true)
}

func hkdfInternal(hf toys.Hash, chainKey, inputKey []byte, want3 bool) (k1, k2, k3 []byte) {
	if len(chainKey) != hf.HashSize() {
		panic(fmt.Sprintf("chain key is %d bytes, want %d", len(chainKey), hf.HashSize()))
	}
	tempKey := newHashHMAC(hf, chainKey).computeHMAC(inputKey)
	kmac := newHashHMAC(hf, tempKey)
	k1 = kmac.computeHMAC([]byte{1})
	k2 = kmac.computeHMAC(append(k1, 2))
	if want3 {
		k3 = kmac.computeHMAC(append(k2, 3))
	}
	return
}

// GenerateCipherKey generates a random cipher key.
func GenerateCipherKey() toys.CipherKey {
	var data [toys.CipherKeySize]byte
	rand.Read(data[:])
	return new(toys.CipherKey).Set(data[:])
}
