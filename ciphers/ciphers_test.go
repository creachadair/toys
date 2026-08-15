package ciphers_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/creachadair/toys"
	"github.com/creachadair/toys/ciphers"
)

var (
	_ toys.Cipher = ciphers.ChaCha20Poly1305
	_ toys.Cipher = ciphers.AESGCM
)

func fromHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestChaCha20Poly1305(t *testing.T) {
	// Test vector from https://www.rfc-editor.org/info/rfc8439/#appendix-A.5
	key := fromHex(t, "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0")
	plaintext := fromHex(t,
		"496e7465726e65742d4472616674732061726520647261667420646f63756d656e74732076616c696420666f722061206d6178696d756d206f6620736978206d6f6e74687320616e64206d617920626520757064617465642c207265706c616365642c206f72206f62736f6c65746564206279206f7468657220646f63756d656e747320617420616e792074696d652e20497420697320696e617070726f70726961746520746f2075736520496e7465726e65742d447261667473206173207265666572656e6365206d6174657269616c206f7220746f2063697465207468656d206f74686572207468616e206173202fe2809c776f726b20696e2070726f67726573732e2fe2809d",
	)
	additional := fromHex(t, "f33388860000000000004e91")
	tag := fromHex(t, "eead9d67890cbb22392336fea1851f38")
	const nonce = 0x0807060504030201
	ciphertext := fromHex(t, // N.B. without tag
		"64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb24c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c8559797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523eaf4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a1049e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29a6ad5cb4022b02709b",
	)

	ek := new(toys.CipherKey).Set(key)

	t.Run("Encrypt", func(t *testing.T) {
		got, err := ciphers.ChaCha20Poly1305.Encrypt(nil, ek, nonce, additional, plaintext)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		gotPayload, gotTag := got[:len(got)-16], got[len(got)-16:]

		if !bytes.Equal(gotPayload, ciphertext) {
			t.Errorf("Ciphertext:\ngot:  %x\nwant: %x", gotPayload, ciphertext)
		}
		if !bytes.Equal(gotTag, tag) {
			t.Errorf("Tag: got %x, want %x", gotTag, tag)
		}
	})

	t.Run("Decrypt", func(t *testing.T) {
		input := append(ciphertext, tag...)
		got, err := ciphers.ChaCha20Poly1305.Decrypt(nil, ek, nonce, additional, input)
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Errorf("Plaintext:\ngot:  %x\nwant: %x", got, plaintext)
		}
	})
}

func TestAESGCM(t *testing.T) {
	tests := []struct {
		name          string
		keyHex        string
		nonce         uint64
		plaintextHex  string
		ciphertextHex string
		tagHex        string
	}{{
		name:          "EmptyMessage",
		keyHex:        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		nonce:         0,
		plaintextHex:  "",
		ciphertextHex: "",
		tagHex:        "f05d76ae4ab99fe5a6f69b3148c2363d",
	}, {
		name:          "Hello",
		keyHex:        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		nonce:         0,
		plaintextHex:  "48656c6c6f",
		ciphertextHex: "46d9d9b2da",
		tagHex:        "1f72f2cfae32ce010545f30308338af0",
	}, {
		name:          "SecretMessage/Short",
		keyHex:        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		nonce:         0,
		plaintextHex:  "54686973206973206120736563726574206d657373616765",
		ciphertextHex: "5ad4dcad9545f09d6988da507b5ef4edf22e33205be0074a",
		tagHex:        "41e10cf00fa6b751500940a44376ae18",
	}, {
		name:          "SecretMessage/Long",
		keyHex:        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		nonce:         0,
		plaintextHex:  "4f70656e41445020656e6372797074696f6e207465737420776974682061206c6f6e676572206d657373616765",
		ciphertextHex: "41ccd0b0f468d39d6dc6ca47615ce5f0bd2d76274df2140ff7f7c7ebe59e7d3a213181d958d2d56340b01092a4",
		tagHex:        "4888b64c93f10a197d29f1468a57983b",
	}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key := fromHex(t, tc.keyHex)
			plaintext := fromHex(t, tc.plaintextHex)
			ciphertext := fromHex(t, tc.ciphertextHex)
			tag := fromHex(t, tc.tagHex)
			nonce := toys.CipherNonce(tc.nonce)

			ek := new(toys.CipherKey).Set(key)

			// Encrypt.
			got, err := ciphers.AESGCM.Encrypt(nil, ek, nonce, nil, plaintext)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			gotPayload, gotTag := got[:len(got)-16], got[len(got)-16:]

			// Check payload and tag.
			if !bytes.Equal(gotPayload, ciphertext) {
				t.Errorf("Ciphertext:\ngot:  %x\nwant: %x", gotPayload, ciphertext)
			}
			if !bytes.Equal(gotTag, tag) {
				t.Errorf("Tag: got %x, want %x", gotTag, tag)
			}

			// Decrypt and round trip.
			dec, err := ciphers.AESGCM.Decrypt(nil, ek, nonce, nil, append(ciphertext, tag...))
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if !bytes.Equal(dec, plaintext) {
				t.Errorf("Plaintext:\ngot:  %x\nwant: %x", got, plaintext)
			}
		})
	}
}
