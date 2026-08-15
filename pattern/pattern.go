// Package pattern defines the representation of Noise [handshake patterns].
//
// # Overview
//
// Construct a [Handshake] value either by parsing a textual description of the
// handshake pattern (via [Compile]; otherwise, construct a [Config] or parse
// one using [Parse], and call [Config.Compile].
//
// The compiled handshake pattern can then be used to instantiate a Noise
// handshake via [github.com/creachadair/toys/state.NewHandshake].
//
// [handshake patterns]: https://noiseprotocol.org/noise.html#handshake-patterns
package pattern

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/creachadair/toys"
	"github.com/creachadair/toys/internal/parse"
)

// Config describes a [Handshake].
type Config struct {
	Label     string          // handshake label (must be non-empty)
	Initiator toys.PreMessage // which initiator keys are known a priori by the responder
	Responder toys.PreMessage // which responder keys are known a priori by the initiator
	Messages  []toys.Message  // handshake message patterns (must be non-empty)
}

// Compile compiles hc into a [Handshake], or reports an error if the config is
// invalid.
func (hc Config) Compile() (out Handshake, _ error) {
	if _, err := ParseName(hc.Label); err != nil {
		return out, fmt.Errorf("invalid handshake label %q: %w", hc.Label, err)
	}
	if !hc.Initiator.IsValid() {
		return out, fmt.Errorf("initiator pre-message: %v", hc.Initiator)
	}
	if !hc.Responder.IsValid() {
		return out, fmt.Errorf("responder pre-message: %v", hc.Responder)
	}
	if len(hc.Messages) == 0 {
		return out, errors.New("empty handshake messages")
	}

	// Check validity conditions.
	// In each of these arrays, 0 == initiator, 1 == responder.
	const initiator = 0
	const responder = 1
	var label = [2]string{"initiator", "responder"}            // party names, for error messages
	var knows = [2]toys.PreMessage{hc.Responder, hc.Initiator} // what each party knows about the other
	var sentE = [2]bool{
		hc.Initiator.HasEphemeral(), // responder knows initiator's ephemeral key
		hc.Responder.HasEphemeral(), // initiator knows responder's ephemeral key
	}
	var sentS = [2]bool{
		hc.Initiator.HasStatic(), // responder knows initiator's static key
		hc.Responder.HasStatic(), // initiator knows responder's static key
	}
	var needS [2]bool                      // party requires a static key for this pattern
	var didEE, didSE, didES, didSS [2]bool // no repeated DH operations
	var hasPSK [2]bool                     // this party mentions one or more "psk" tokens

	// Accumulate diagnostics.
	var errs []error
	errf := func(i, j int, msg string, args ...any) {
		errs = append(errs, fmt.Errorf("rule %d: %s (offset %d)", i+1, fmt.Sprintf(msg, args...), j))
	}

	for i, pat := range hc.Messages {
		// Each pattern must be non-empty, except the first in a responder-initiated pattern.
		if len(pat) == 0 {
			if i == 0 && hc.Initiator != toys.NoKeys {
				continue // the initiator sent something in the pre-message, so this could be OK
			}
			return out, fmt.Errorf("rule %d: empty pattern", i+1)
		}
		who := i % 2
		for j, tok := range pat {
			// 7.3 Handshake pattern validity
			//
			// 1. Parties can only perform DH between private keys and public keys they possess.
			//
			// 2. Parties must not send their static public key or ephemeral
			//    public key more than once per handshake (i.e. including the
			//    pre-messages, there must be no more than one occurrence of "e", and
			//    one occurrence of "s", in the messages sent by any party).
			//
			// 3. Parties must not perform a DH calculation more than once per
			//    handshake (i.e. there must be no more than one occurrence of "ee",
			//    "es", "se", or "ss" per handshake).
			//
			// 4. After performing a DH between a remote public key (either static
			//    or ephemeral) and the local static key, the local party must not
			//    call ENCRYPT() unless it has also performed a DH between its
			//    local ephemeral key and the remote public key.
			switch tok {
			case toys.E:
				// 7.3(2)
				if sentE[who] {
					errf(i, j, "%s repeats ephemeral key", label[who])
				}
				sentE[who] = true
				knows[1-who] |= toys.EphemeralOnly

			case toys.S:
				// 7.3(2)
				if sentS[who] {
					errf(i, j, "%s repeats static key", label[who])
				}
				needS[who] = true // a static key must be provided
				sentS[who] = true
				knows[1-who] |= toys.StaticOnly // hence, the other party now knows our static key

			case toys.EE:
				// 7.3(1) For ephemeral keys, that means this party must have generated an
				// ephemeral key, and must know the ephemeral key of the other party.
				if !sentE[who] {
					errf(i, j, "%s attempts DH with no ephemeral key", label[who])
				}
				if !knows[who].HasEphemeral() {
					errf(i, j, "%s attempts DH on unknown ephemeral key", label[who])
				}
				// 7.3(3) Parties must not perform a DH calculation more than once per handshake.
				if didEE[who] {
					errf(i, j, "%s repeats DH ee operation", label[who])
				}
				didEE[who] = true

			case toys.SE:
				// 7.3(1) The initiator must know the responder's ephemeral key, and the responder must
				// know the initiator's static key.
				if who == initiator && !knows[who].HasEphemeral() {
					errf(i, j, "%s attempts DH on unknown ephemeral key", label[who])
				} else if who == responder && !knows[who].HasStatic() {
					errf(i, j, "%s attempts DH on unknown static key", label[who])
				}
				needS[initiator] = true // initiator has to have a static key for this to be possible
				// 7.3(3) Parties must not perform a DH calculation more than once per handshake.
				if didSE[who] {
					errf(i, j, "%s repeats DH se operation", label[who])
				}
				didSE[who] = true

			case toys.ES:
				// 7.3(1) The initiator must know the responder's static key, and the responder must
				// know the initiator's ephemeral key.
				if who == initiator && !knows[who].HasStatic() {
					errf(i, j, "%s attempts DH on unknown static key", label[who])
				} else if who == responder && !knows[who].HasEphemeral() {
					errf(i, j, "%s attempts DH on unknown ephemeral key", label[who])
				}
				needS[responder] = true // responder has to have a static key for this to be possible
				// 7.3(3) Parties must not perform a DH calculation more than once per handshake.
				if didES[who] {
					errf(i, j, "%s repeats DH es operation", label[who])
				}
				didES[who] = true

			case toys.SS:
				// 7.3(1) For static keys, that means this party must have a static key, and must know the
				// static key of the other party.
				if !knows[who].HasStatic() {
					errf(i, j, "%s attempts DH on unknown static key", label[who])
				}
				needS[who] = true // a static key must be provided
				// 7.3(3) Parties must not perform a DH calculation more than once per handshake.
				if didSS[who] {
					errf(i, j, "%s repeats DH ss operation", label[who])
				}
				didSS[who] = true

			case toys.PSK:
				// Record that there is a PSK token, so that the state constructor can check for it.
				// Multiple occurrences are OK.
				hasPSK[who] = true

			default:
				errf(i, j, "invalid token %q", tok)
				return out, errs[len(errs)-1]
			}

			// Note: These checks do not fully enforce 7.3(4), which implicates
			// dynamic use of the negotiated state for encryption, and thus cannot
			// be reliably inferred from the static definition of the handshake.
		}
	}
	// 9.3 requires that a party may not encrypt any data after processing a
	// "psk" token until it has sent an ephemeral key ("e"). We cannot enforce
	// that statically, but check that each participant did issue an "e", since
	// if it doesn't that is statically invalid.
	for who := 0; who <= 1; who++ {
		if hasPSK[who] && !sentE[who] {
			errs = append(errs, fmt.Errorf("%s sent psk but not e", label[who]))
		}
	}

	// Check the static parts of 7.3(4). A handshake that passes these checks
	// could still be misused (e.g., by sending a payload in the interval where
	// the condition is not yet satisfied), but an error here is a true failure.
	if ee := didEE[0] || didEE[1]; didSE[initiator] && !ee {
		errs = append(errs, errors.New("initiator computed se but not ee"))
	}
	if es := didES[0] || didES[1]; didSS[initiator] && !es {
		errs = append(errs, errors.New("initiator computed ss but not es"))
	}
	if ee := didEE[0] || didEE[1]; didES[responder] && !ee {
		errs = append(errs, errors.New("responder computed es but not ee"))
	}
	if se := didSE[0] || didSE[1]; didSS[responder] && !se {
		errs = append(errs, errors.New("responder computed ss but not se"))
	}

	if len(errs) != 0 {
		return out, errors.Join(errs...)
	}
	return Handshake{
		Label:           hc.Label,
		Initiator:       hc.Initiator,
		Responder:       hc.Responder,
		InitNeedsStatic: needS[initiator],
		RespNeedsStatic: needS[responder],
		NeedsPSK:        hasPSK[initiator] || hasPSK[responder],

		messages: hc.Messages,
	}, nil
}

// Handshake is a compiled handshake pattern.
type Handshake struct {
	Label           string          // including modifiers
	Initiator       toys.PreMessage // pre-messages sent by the initiator (if any)
	Responder       toys.PreMessage // pre-messages sent by the responder (if any)
	InitNeedsStatic bool            // whether initiator requires a static key pair
	RespNeedsStatic bool            // whether responder requires a static key pair
	NeedsPSK        bool            // whether a pre-shared key is required

	messages []toys.Message
}

// Len reports the number of message patterns in p.
func (p Handshake) Len() int { return len(p.messages) }

// Pattern returns the ith [toys.Message] in p.
// It will panic if i < 0 or i >= p.Len(). The caller must not mutate the
// returned slice.
func (p Handshake) Pattern(i int) toys.Message { return p.messages[i] }

func (p Handshake) String() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s:\n", p.Label)
	if p.Initiator != toys.NoKeys || p.Responder != toys.NoKeys {
		if p.Initiator != toys.NoKeys {
			fmt.Fprintf(&sb, "  -> %s\n", p.Initiator)
		}
		if p.Responder != toys.NoKeys {
			fmt.Fprintf(&sb, "  <- %s\n", p.Responder)
		}
		sb.WriteString("  ...\n") // end of pre-message section
	}
	for i, pat := range p.messages {
		if len(pat) == 0 {
			continue
		} else if i%2 == 0 {
			sb.WriteString("  -> ")
		} else {
			sb.WriteString("  <- ")
		}
		fmt.Fprintln(&sb, pat)
	}
	return sb.String()
}

// IsValid reports whether p is structually valid.
func (p Handshake) IsValid() bool { return p.Label != "" && len(p.messages) != 0 }

// Compile parses and compiles s as the text encoding of a Noise handshake
// pattern, returning a [Handshake] on success.  See also [Parse].
func Compile(s string) (Handshake, error) {
	cfg, err := Parse(s)
	if err != nil {
		return Handshake{}, err
	}
	return cfg.Compile()
}

// Parse parses s as the text encoding of a Noise handshake pattern.  On
// success, it returns a [Config]. The resulting config is grammatical, but may
// not be valid; call its Compile method to check.
func Parse(s string) (out Config, _ error) {
	type insn struct {
		who  string
		what []toys.Token
	}
	var cfg Config
	var insns []insn
	var hasPre bool
	translate := func(m toys.Message) toys.Message { return m }

	var ln int
	for line := range strings.SplitSeq(strings.TrimSpace(s), "\n") {
		ln++
		clean := strings.TrimSpace(line)
		if clean == "" {
			continue
		}

		// If we do not yet have a label, insist on that being first.
		if cfg.Label == "" {
			id, ok := strings.CutSuffix(clean, ":")
			if !ok {
				return out, fmt.Errorf("line %d: expected protocol label here", ln)
			} else if _, err := ParseName(id); err != nil {
				return out, fmt.Errorf("line %d: invalid protocol label %q: %w", ln, id, err)
			}
			cfg.Label = id
			continue
		}

		// The rest of the lines must have one of the following formats:
		//    -> a, b, c
		//    <- a, b, c
		//    ...
		//
		// where a, b, c, etc. are token spellings (note "..." here is literal).
		tag, tokens, ok := parsePatternLine(clean)
		if !ok {
			return out, fmt.Errorf("line %d: invalid pattern line %q", ln, clean)
		}
		switch tag {
		case "...":
			// End of the pre-message section. Make sure we did not already have
			// one, and that we got some instructions to process.
			if hasPre {
				return out, fmt.Errorf("line %d: repeated pre-message separator", ln)
			} else if len(insns) == 0 {
				return out, fmt.Errorf("line %d: no pre-message instructions", ln)
			}

			// Compile the pre-message instructions into bit flags, then reset the
			// instructions for the body.
			for _, in := range insns {
				var p toys.PreMessage
				for _, w := range in.what {
					switch w {
					case toys.E:
						p |= toys.EphemeralOnly
					case toys.S:
						p |= toys.StaticOnly
					default:
						return out, fmt.Errorf("invalid pre-message instruction %q", w)
					}
				}
				if in.who == "->" {
					cfg.Initiator |= p
				} else {
					cfg.Responder |= p
				}
				insns = nil
				hasPre = true
			}
		case "->", "<-":
			insns = append(insns, insn{who: tag, what: tokens})
		default:
			panic(fmt.Sprintf("unexpected instruction tag %q", tag))
		}
	}
	for _, in := range insns {
		switch in.who {
		case "->":
			cfg.Messages = append(cfg.Messages, in.what)
		case "<-":
			// If this is the first message in the handshake, this could be a
			// Bob-initiated flow (see 7.2).
			// For that to be possible, the initiator must have sent a non-empty
			// pre-message, in which case we can invert all the rules to
			// canonicalize so the initiator is on the "left".
			if len(cfg.Messages) == 0 {
				if cfg.Initiator == toys.NoKeys {
					return out, fmt.Errorf("line %d: Bob-initiated instruction with no pre-message", ln)
				}
				cfg.Initiator, cfg.Responder = cfg.Responder, cfg.Initiator
				translate = invert
			}
			cfg.Messages = append(cfg.Messages, translate(in.what))
		}
	}
	return cfg, nil
}

// invert returns a (possibly) copy of m with all its DH steps inverted.
func invert(m toys.Message) toys.Message {
	for _, t := range m {
		if t == toys.ES || t == toys.SE {
			cp := slices.Clone(m)
			for i, t := range cp {
				switch t {
				case toys.SE:
					cp[i] = toys.ES
				case toys.ES:
					cp[i] = toys.SE
				}
			}
			return cp
		}
	}
	return m
}

func parsePatternLine(s string) (tag string, _ []toys.Token, _ bool) {
	if s == "..." {
		return s, nil, true
	}
	rest, ok := strings.CutPrefix(s, "->")
	if ok {
		return "->", toTokens(splitAndClean(rest)), true
	}
	rest, ok = strings.CutPrefix(s, "<-")
	if ok {
		return "<-", toTokens(splitAndClean(rest)), true
	}
	return "", nil, false
}

func splitAndClean(s string) (out []string) {
	for w := range strings.SplitSeq(strings.TrimSpace(s), ",") {
		if cw := strings.TrimSpace(w); cw != "" {
			out = append(out, cw)
		}
	}
	return
}

func toTokens(ss []string) []toys.Token {
	out := make([]toys.Token, len(ss))
	for i, s := range ss {
		out[i] = toys.Token(s)
	}
	return out
}

// A Name is the parsed representation of a pattern name.
type Name struct {
	Base      string   // base pattern name (e.g., NN, IK)
	Modifiers []string // modifiers (optional)
}

func (n Name) String() string { return n.Base + strings.Join(n.Modifiers, "+") }

// ParseName parses the text representation of a handshake pattern name (8.1).
func ParseName(s string) (Name, error) {
	name, mods, err := parse.PatternName(s)
	if err != nil {
		return Name{}, err
	}
	return Name{Base: name, Modifiers: mods}, nil
}
