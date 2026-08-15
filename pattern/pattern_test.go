package pattern_test

import (
	"strconv"
	"strings"
	"testing"

	"github.com/creachadair/mds/mapset"
	"github.com/creachadair/toys"
	"github.com/creachadair/toys/pattern"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	_ "embed"
)

//go:embed testdata/patterns.txt
var patternList string

func TestStandardPatterns(t *testing.T) {
	var np int
	var seen, repeat mapset.Set[string]
	for block := range strings.SplitSeq(strings.TrimSpace(patternList), "\n\n") {
		np++

		t.Run(strconv.Itoa(np), func(t *testing.T) {
			t.Logf("Input (%d bytes):\n%s\n", len(block), block)

			// Parse and compile the input pattern, then render it as a string and
			// parse and compile it again, to verify it round-trips to an equivalent pattern.

			h, err := pattern.Compile(block)
			if err != nil {
				t.Fatalf("Compile failed: %v", err)
			}
			if seen.Has(h.Label) {
				repeat.Add(h.Label)
			}
			seen.Add(h.Label)
			hs := h.String()
			t.Logf("Compiled (%d bytes):\n%s\n", len(hs), hs)

			h2, err := pattern.Compile(hs)
			if err != nil {
				t.Fatalf("Compile rendered: %v", err)
			}

			if diff := cmp.Diff(h2, h, cmp.AllowUnexported(pattern.Handshake{}), cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Parsed config (-got, +want):\n%s", diff)
			}
		})
	}
	if len(repeat) != 0 {
		t.Errorf("Repeated test cases: %q", repeat.Slice())
	}
}

func TestHanshake_Compile(t *testing.T) {
	tests := []pattern.Config{
		{
			Label:     "IK",
			Responder: toys.StaticOnly,
			Messages: []toys.Message{
				{"e", "es", "s", "ss"},
				{"e", "ee", "se"},
			},
		},
		{
			Label:     "Xpsk1",
			Responder: toys.StaticOnly,
			Messages: []toys.Message{
				{"e", "es", "s", "ss", "psk"},
			},
		},
		{
			Label:     "NK",
			Responder: toys.StaticOnly,
			Messages: []toys.Message{
				{"e", "es"},
				{"e", "ee"},
			},
		},
		{
			Label:     "XXfallback",
			Responder: toys.EphemeralOnly,
			Messages: []toys.Message{
				{"e", "ee", "s", "se"},
				{"s", "es"},
			},
		},
	}
	for i, tc := range tests {
		h, err := tc.Compile()
		if err != nil {
			t.Errorf("Input %d: compile failed: %v\ninput: %+v", i+1, err, tc)
			continue
		}
		t.Logf("Result %d label %q:\n%s", i+1, h.Label, h)
	}
}

func TestCompileErrors(t *testing.T) {
	tests := []struct {
		name    string
		input   pattern.Config
		wantErr string
	}{
		{"BadLabel/Empty", pattern.Config{}, `invalid handshake label ""`},
		{"BadLabel/Case", pattern.Config{Label: "bogus"}, "invalid handshake label"},
		{"BadLabel/Punct", pattern.Config{Label: ".x."}, `invalid handshake label ".x."`},

		{"BadMods", pattern.Config{
			Label: "Qok+loooool!+alsoOK",
		}, "invalid handshake label"},

		{"InvalidInit", pattern.Config{Label: "Q", Initiator: -1}, "initiator pre-message"},
		{"InvalidResp", pattern.Config{Label: "Q", Responder: 999}, "responder pre-message"},

		{"EmptyRules", pattern.Config{Label: "Q"}, "empty handshake messages"},
		{"EmptyPattern", pattern.Config{
			Label:    "Q",
			Messages: []toys.Message{{}},
		}, "rule 1: empty pattern"},
		{"InvalidToken", pattern.Config{
			Label:    "Q",
			Messages: []toys.Message{{toys.E, toys.S, "bogus"}},
		}, `rule 1: invalid token "bogus" (offset 2)`},

		// 7.3(1)
		{"Rep/E/Init", pattern.Config{
			Label:    "Q",
			Messages: []toys.Message{{"e", "e"}},
		}, "rule 1: initiator repeats ephemeral key"},
		{"Rep/E/Resp", pattern.Config{
			Label:    "Q",
			Messages: []toys.Message{{"s"}, {"e"}, {"e"}, {"e"}},
		}, "rule 4: responder repeats ephemeral key"},
		{"Rep/S/Init", pattern.Config{
			Label:    "Q",
			Messages: []toys.Message{{"s"}, {"s"}, {"s"}},
		}, "rule 3: initiator repeats static key"},
		{"Rep/S/Resp", pattern.Config{
			Label:    "Q",
			Messages: []toys.Message{{"e"}, {"s"}, {"s"}, {"s"}},
		}, "rule 4: responder repeats static key"},
		{"Rep/Pre/S/Init", pattern.Config{
			Label:     "Q",
			Initiator: toys.StaticOnly, // this counts as a send of s
			Messages:  []toys.Message{{"e", "s"}},
		}, "rule 1: initiator repeats static key"},
		{"Rep/Pre/S/Resp", pattern.Config{
			Label:     "Q",
			Responder: toys.EphemeralAndStatic, // this counts as a send of e & s
			Messages:  []toys.Message{{"e"}, {"s"}},
		}, "rule 2: responder repeats static key"},
		{"Rep/Pre/E/Init", pattern.Config{
			Label:     "Q",
			Initiator: toys.EphemeralOnly, // this counts as a send of e
			Messages:  []toys.Message{{"s"}, {"e"}, {"e"}},
		}, "rule 3: initiator repeats ephemeral key"},
		{"Rep/Pre/E/Resp", pattern.Config{
			Label:     "Q",
			Responder: toys.EphemeralOnly, // this counts as a send of e
			Messages:  []toys.Message{{"s"}, {"s", "e"}},
		}, "rule 2: responder repeats ephemeral key"},

		// 7.3(2)
		{"DH/EE/Init", pattern.Config{
			Label:    "Q",
			Messages: []toys.Message{{"s", "e", "ee"}},
		}, "rule 1: initiator attempts DH on unknown ephemeral key"},
		{"DH/ES/Init", pattern.Config{
			Label:    "Q",
			Messages: []toys.Message{{"e", "es"}},
		}, "rule 1: initiator attempts DH on unknown static key"},
		{"DH/SE/Init", pattern.Config{
			Label:    "Q",
			Messages: []toys.Message{{"e", "se"}},
		}, "rule 1: initiator attempts DH on unknown ephemeral key"},
		{"DH/SS/Init", pattern.Config{
			Label:    "Q",
			Messages: []toys.Message{{"e", "ss"}},
		}, "rule 1: initiator attempts DH on unknown static key"},
		{"DH/EE/Resp", pattern.Config{
			Label:    "Q",
			Messages: []toys.Message{{"s"}, {"e", "ee"}},
		}, "rule 2: responder attempts DH on unknown ephemeral key"},
		{"DH/SE/Resp", pattern.Config{
			Label:    "Q",
			Messages: []toys.Message{{"e"}, {"se"}},
		}, "rule 2: responder attempts DH on unknown static key"},
		{"DH/ES/Resp", pattern.Config{
			Label:    "Q",
			Messages: []toys.Message{{"s"}, {"es"}},
		}, "rule 2: responder attempts DH on unknown ephemeral key"},
		{"DH/SS/Resp", pattern.Config{
			Label:    "Q",
			Messages: []toys.Message{{"e"}, {"ss"}},
		}, "rule 2: responder attempts DH on unknown static key"},

		// 7.3(3)
		{"RepDH/EE/Init", pattern.Config{
			Label:    "Q",
			Messages: []toys.Message{{"e"}, {"e"}, {"ee"}, {"ee"}, {"ee"}},
		}, "rule 5: initiator repeats DH ee operation"},
		{"RepDH/SE/Init", pattern.Config{
			Label:    "Q",
			Messages: []toys.Message{{"s"}, {"e"}, {"se", "se"}},
		}, "rule 3: initiator repeats DH se operation"},
		{"RepDH/ES/Init", pattern.Config{
			Label:    "Q",
			Messages: []toys.Message{{"e"}, {"s"}, {"es"}, {"es"}, {"es"}},
		}, "rule 5: initiator repeats DH es operation"},
		{"RepDH/SS/Init", pattern.Config{
			Label:    "Q",
			Messages: []toys.Message{{"s"}, {"s"}, {"ss", "ss"}},
		}, "rule 3: initiator repeats DH ss operation"},
		{"RepDH/EE/Resp", pattern.Config{
			Label:    "Q",
			Messages: []toys.Message{{"e"}, {"e", "ee"}, {"s"}, {"ee"}},
		}, "rule 4: responder repeats DH ee operation"},
		{"RepDH/SE/Resp", pattern.Config{
			Label:    "Q",
			Messages: []toys.Message{{"s"}, {"e", "se"}, {"se"}, {"se"}},
		}, "rule 4: responder repeats DH se operation"},
		{"RepDH/ES/Resp", pattern.Config{
			Label:    "Q",
			Messages: []toys.Message{{"e"}, {"s", "es"}, {"es"}, {"es"}},
		}, "rule 4: responder repeats DH es operation"},
		{"RepDH/SS/Resp", pattern.Config{
			Label:    "Q",
			Messages: []toys.Message{{"s"}, {"ss", "s"}, {"ss"}, {"ss"}},
		}, "rule 4: responder repeats DH ss operation"},

		// 9.3
		{"PSK/NoE/Init", pattern.Config{
			Label:    "Q",
			Messages: []toys.Message{{"s", "psk"}, {"s", "ss"}},
		}, "initiator sent psk but not e"},
		{"PSK/NoE/Resp", pattern.Config{
			Label:    "Q",
			Messages: []toys.Message{{"s", "e", "psk"}, {"s", "se", "psk"}},
		}, "responder sent psk but not e"},

		// 7.3(4)
		{"BadDH/SE/Init", pattern.Config{
			Label:    "Q",
			Messages: []toys.Message{{"se"}},
		}, "initiator computed se but not ee"},
		{"BadDH/SS/Init", pattern.Config{
			Label:    "Q",
			Messages: []toys.Message{{"e"}, {"s"}, {"ss"}},
		}, "initiator computed ss but not es"},
		{"BadDH/ES/Resp", pattern.Config{
			Label:    "Q",
			Messages: []toys.Message{{"e"}, {"es"}},
		}, "responder computed es but not ee"},
		{"BadDH/SS/Resp", pattern.Config{
			Label:    "Q",
			Messages: []toys.Message{{"s"}, {"ss", "e"}},
		}, "responder computed ss but not se"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.input.Compile()
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("Compile: got (%+v, %v), want error %q", got, err, tc.wantErr)
			}

			// For most of these test cases, we expect only a single error.
			// If we get more than one, log about it in case that wasn't intended.
			if me, ok := err.(interface {
				Unwrap() []error
			}); ok {
				if errs := me.Unwrap(); len(errs) > 1 {
					t.Logf("Warning: found %d errors, not just one", len(errs))
				}
			}
		})
	}
}

func TestParseName(t *testing.T) {
	tests := []struct {
		input string
		want  pattern.Name
	}{
		{"A", pattern.Name{Base: "A"}},
		{"A1", pattern.Name{Base: "A1"}},
		{"AB1C", pattern.Name{Base: "AB1C"}},
		{"ABpsk", pattern.Name{"AB", []string{"psk"}}},
		{"Apsk0", pattern.Name{"A", []string{"psk0"}}},
		{"AK9fallback+psk1", pattern.Name{"AK9", []string{"fallback", "psk1"}}},
	}
	for _, tc := range tests {
		got, err := pattern.ParseName(tc.input)
		if err != nil {
			t.Errorf("ParseName %q: unexpected error: %v", tc.input, err)
		}
		if diff := cmp.Diff(got, tc.want); diff != "" {
			t.Errorf("ParseName %q (-got, +want):\n%s", tc.input, diff)
		}
		if rt := got.String(); rt != tc.input {
			t.Errorf("String is %q, want %q", rt, tc.input)
		}
	}

	t.Run("Errors", func(t *testing.T) {
		tests := []struct {
			input, want string
		}{
			{"", "empty pattern name"},
			{"psk", "empty pattern name"},
			{"A+", "empty modifier"},
			{"ABfoo+OOF", `only letters and digits ("OOF")`},
			{"AB/xyz", `only letters and digits ("/xyz")`},
			{"ABok++ok", "empty modifier"},
			{"ABfoo+1bar", `"1bar" does not begin with a letter`},
		}
		for _, tc := range tests {
			got, err := pattern.ParseName(tc.input)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("ParseName %q: got (%v, %v), want %q", tc.input, got, err, tc.want)
			}
		}
	})
}
