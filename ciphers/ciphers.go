// Package ciphers provides implementations of the [toys.Cipher] interface.
package ciphers

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"

	"github.com/creachadair/toys"
	"golang.org/x/crypto/chacha20poly1305"
)

// ChaCha20Poly1305 implements [toys.Cipher] using the ChaCha20Poly1305 AEAD.
var ChaCha20Poly1305 chachaCipher

type chachaCipher struct{}

func (chachaCipher) Label() string { return "ChaChaPoly" }

func (chachaCipher) Encrypt(dst []byte, ek toys.CipherKey, nonce toys.CipherNonce, ad, plaintext []byte) ([]byte, error) {
	c, err := chacha20poly1305.New(ek.Bytes())
	if err != nil {
		return nil, err
	}
	// 12.3: The 96-bit nonce is formed by encoding 32 bits of zeros followed by little-endian encoding of n
	var nbuf [12]byte
	nonce.Append(nbuf[4:4])
	return c.Seal(dst, nbuf[:], plaintext, ad), nil
}

func (chachaCipher) Decrypt(dst []byte, dk toys.CipherKey, nonce toys.CipherNonce, ad, ciphertext []byte) ([]byte, error) {
	c, err := chacha20poly1305.New(dk.Bytes())
	if err != nil {
		return nil, err
	}
	// 12.3: The 96-bit nonce is formed by encoding 32 bits of zeros followed by little-endian encoding of n
	var nbuf [12]byte
	nonce.Append(nbuf[4:4])
	return c.Open(dst, nbuf[:], ciphertext, ad)
}

func (c chachaCipher) Rekey(old toys.CipherKey) (toys.CipherKey, error) {
	return toys.DefaultCipherRekey(c, old)
}

// AESGCM implements [toys.Cipher] using the AES Galois Counter Mode AEAD.
var AESGCM aesGCMCipher

type aesGCMCipher struct{}

func (aesGCMCipher) Label() string { return "AESGCM" }

func (aesGCMCipher) Encrypt(dst []byte, ek toys.CipherKey, nonce toys.CipherNonce, ad, plaintext []byte) ([]byte, error) {
	c, err := aes.NewCipher(ek.Bytes())
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}
	// 12.4: The 96-bit nonce is formed by encoding 32 bits of zeros followed by big-endian encoding of n.
	var nbuf [12]byte
	binary.BigEndian.AppendUint64(nbuf[4:4], uint64(nonce))
	return aead.Seal(dst, nbuf[:], plaintext, ad), nil
}

func (aesGCMCipher) Decrypt(dst []byte, dk toys.CipherKey, nonce toys.CipherNonce, ad, ciphertext []byte) ([]byte, error) {
	c, err := aes.NewCipher(dk.Bytes())
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}
	// 12.4: The 96-bit nonce is formed by encoding 32 bits of zeros followed by big-endian encoding of n.
	var nbuf [12]byte
	binary.BigEndian.AppendUint64(nbuf[4:4], uint64(nonce))
	return aead.Open(dst, nbuf[:], ciphertext, ad)
}

func (c aesGCMCipher) Rekey(old toys.CipherKey) (toys.CipherKey, error) {
	return toys.DefaultCipherRekey(c, old)
}
