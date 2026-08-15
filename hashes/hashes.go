// Package hashes provides implementations of the [toys.Hash] interface.
package hashes

import (
	"crypto/sha256"

	"github.com/creachadair/toys"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
)

// SHA256 implements [toys.Hash] using SHA2-256.
var SHA256 sha256Hash

type sha256Hash struct{}

func (sha256Hash) Label() string  { return "SHA256" }
func (sha256Hash) HashSize() int  { return sha256.Size }
func (sha256Hash) BlockSize() int { return sha256.BlockSize }

func (sha256Hash) Digest(dst, input []byte) []byte {
	sum := sha256.Sum256(input)
	return append(dst, sum[:]...)
}

// BLAKE2s implements [toys.Hash] using BLAKE2s.
var BLAKE2s blake2sHash

type blake2sHash struct{}

func (blake2sHash) Label() string  { return "BLAKE2s" }
func (blake2sHash) HashSize() int  { return blake2s.Size }
func (blake2sHash) BlockSize() int { return blake2s.BlockSize }

func (blake2sHash) Digest(dst, input []byte) []byte {
	sum := blake2s.Sum256(input)
	return append(dst, sum[:]...)
}

var (
	_ toys.Hash = SHA256
	_ toys.Hash = BLAKE2s
)

// BLAKE2b implements [toys.Hash] using BLAKE2b 512.
var BLAKE2b blake2bHash

type blake2bHash struct{}

func (blake2bHash) Label() string  { return "BLAKE2b" }
func (blake2bHash) HashSize() int  { return blake2b.Size }
func (blake2bHash) BlockSize() int { return blake2b.BlockSize }

func (blake2bHash) Digest(dst, input []byte) []byte {
	sum := blake2b.Sum512(input)
	return append(dst, sum[:]...)
}
