// Package dhs provides implementations of the [toys.DH] interface.
package dhs

import (
	"crypto/ecdh"
	"crypto/rand"

	"github.com/creachadair/toys"
	"golang.org/x/crypto/curve25519"
)

// ECDH25519 implements [toys.DH] using ECDH over Curve25519.
var ECDH25519 ecdh25519

type ecdh25519 struct{}

func (ecdh25519) Label() string   { return "25519" }
func (ecdh25519) OutputSize() int { return curve25519.PointSize }

func (ecdh25519) GenerateKeyPair() (out toys.KeyPair, _ error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return out, err
	}
	out.Private.Set(priv.Bytes())
	out.Public.Set(priv.PublicKey().Bytes())
	return
}

func (ecdh25519) ComputeKey(kp toys.KeyPair, public toys.PublicKey) ([]byte, error) {
	curve := ecdh.X25519()
	lpriv, err := curve.NewPrivateKey(kp.Private.Bytes())
	if err != nil {
		return nil, err
	}
	rpub, err := curve.NewPublicKey(public.Bytes())
	if err != nil {
		return nil, err
	}
	return lpriv.ECDH(rpub)
}
