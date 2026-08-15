package toys_test

import (
	"testing"
	"testing/cryptotest"

	"github.com/creachadair/toys"
	"github.com/creachadair/toys/ciphers"
	"github.com/creachadair/toys/dhs"
	"github.com/creachadair/toys/hashes"
	"github.com/creachadair/toys/internal/htest"
	"github.com/creachadair/toys/internal/keys"
	"github.com/creachadair/toys/pattern"
	"github.com/creachadair/toys/state"
	"github.com/google/go-cmp/cmp"
)

const nkPattern = `
 NK:
   <- s
   ...
   -> e, es
   <- e, ee
`

func TestConfigBasic(t *testing.T) {
	nk := htest.MustCompileText(t, nkPattern)
	t.Logf("Handshake pattern: %q", nk.Label)

	config := toys.NewConfig(dhs.ECDH25519, ciphers.ChaCha20Poly1305, hashes.SHA256)

	// Generate the static key pair required by the NK pattern.
	st := htest.GenerateKeyPair(t, config)
	h := htest.NewHandshake(t, state.HandshakeConfig{
		Noise:        config,
		Pattern:      nk,
		RemoteStatic: st.Public,
	})
	t.Logf("Protocol name: %q", h.ProtocolName())
}

func TestShakeHands(t *testing.T) {
	cryptotest.SetGlobalRandom(t, 20260821160929)

	ds := []toys.DH{dhs.ECDH25519}
	cs := []toys.Cipher{ciphers.ChaCha20Poly1305, ciphers.AESGCM}
	hs := []toys.Hash{hashes.SHA256, hashes.BLAKE2s, hashes.BLAKE2b}
	type testCase struct {
		name   string
		config *toys.Config
	}
	var tests []testCase
	for _, d := range ds {
		for _, c := range cs {
			for _, h := range hs {
				tests = append(tests, testCase{
					name:   d.Label() + "/" + c.Label() + "/" + h.Label(),
					config: toys.NewConfig(d, c, h),
				})
			}
		}
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("NN", func(t *testing.T) {
				nn := htest.MustCompile(t, pattern.Config{
					Label:    "NN",
					Messages: []toys.Message{{"e"}, {"e", "ee"}},
				})
				init := htest.NewHandshake(t, state.HandshakeConfig{
					Noise:   tc.config,
					Pattern: nn,
				})
				resp := htest.NewHandshake(t, state.HandshakeConfig{
					Noise:     tc.config,
					Pattern:   nn,
					Responder: true,
				})
				htest.RunHandshake(t, init, resp)
			})
			t.Run("NK", func(t *testing.T) {
				nk := htest.MustCompileText(t, nkPattern)
				st := htest.GenerateKeyPair(t, tc.config)
				init := htest.NewHandshake(t, state.HandshakeConfig{
					Noise:        tc.config,
					Pattern:      nk,
					RemoteStatic: st.Public, // required by pre-message
				})
				resp := htest.NewHandshake(t, state.HandshakeConfig{
					Noise:       tc.config,
					Pattern:     nk,
					Responder:   true,
					LocalStatic: st,
				})
				htest.RunHandshake(t, init, resp)
			})
			t.Run("NNpsk0", func(t *testing.T) {
				nnpsk0 := htest.MustCompileText(t, `
NNpsk0:
  -> psk, e
  <- e, ee`)
				psk := keys.GenerateCipherKey()
				init := htest.NewHandshake(t, state.HandshakeConfig{
					Noise:        tc.config,
					Pattern:      nnpsk0,
					PreSharedKey: psk,
				})
				resp := htest.NewHandshake(t, state.HandshakeConfig{
					Noise:        tc.config,
					Pattern:      nnpsk0,
					PreSharedKey: psk,
					Responder:    true,
				})
				htest.RunHandshake(t, init, resp)
			})
			t.Run("X1X1", func(t *testing.T) {
				x1x1 := htest.MustCompileText(t, `
X1X1:
  -> e
  <- e, ee, s
  -> es, s
  <- se`)
				init := htest.NewHandshake(t, state.HandshakeConfig{
					Noise:       tc.config,
					Pattern:     x1x1,
					LocalStatic: htest.GenerateKeyPair(t, tc.config),
				})
				resp := htest.NewHandshake(t, state.HandshakeConfig{
					Noise:       tc.config,
					Pattern:     x1x1,
					LocalStatic: htest.GenerateKeyPair(t, tc.config),
					Responder:   true,
				})
				htest.RunHandshake(t, init, resp)
			})
			t.Run("KKpsk2", func(t *testing.T) {
				kkpsk2 := htest.MustCompileText(t, `
KKpsk2:
  -> s
  <- s
  ...
  -> e, es, ss
  <- e, ee, se, psk`)
				isKey := htest.GenerateKeyPair(t, tc.config)
				rsKey := htest.GenerateKeyPair(t, tc.config)
				psk := keys.GenerateCipherKey()
				init := htest.NewHandshake(t, state.HandshakeConfig{
					Noise:        tc.config,
					Pattern:      kkpsk2,
					LocalStatic:  isKey,
					RemoteStatic: rsKey.Public,
					PreSharedKey: psk,
				})
				resp := htest.NewHandshake(t, state.HandshakeConfig{
					Noise:        tc.config,
					Pattern:      kkpsk2,
					LocalStatic:  rsKey,
					RemoteStatic: isKey.Public,
					PreSharedKey: psk,
					Responder:    true,
				})
				htest.RunHandshake(t, init, resp)
			})
		})
	}
}

func TestProtocolName(t *testing.T) {
	tests := []struct {
		input string
		want  toys.ProtocolName
	}{
		{"Noise_XXfallback_25519_ChaChaPoly_SHA256", toys.ProtocolName{
			Handshake: "XXfallback", DH: "25519", Cipher: "ChaChaPoly", Hash: "SHA256",
		}},
		{"Noise_IK_25519_ChaChaPoly_BLAKE2s", toys.ProtocolName{
			Handshake: "IK", DH: "25519", Cipher: "ChaChaPoly", Hash: "BLAKE2s",
		}},
	}
	for _, tc := range tests {
		got, err := toys.ParseProtocolName(tc.input)
		if err != nil {
			t.Errorf("ParseProtocolName %q: unexpected error: %v", tc.input, err)
		}
		if diff := cmp.Diff(got, tc.want); diff != "" {
			t.Errorf("Protocol (-got, +want):\n%s", diff)
		}
		if rt := got.String(); rt != tc.input {
			t.Errorf("String: got %q, want %q", rt, tc.input)
		}
	}
}
