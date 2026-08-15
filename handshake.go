package toys

import (
	"fmt"
	"strings"
)

// A Token identifies a single operation in a message pattern (see [Message]).
type Token string

const (
	// E indicates the transmission of an ephemeral public key.
	// A sender generates and records a new key pair, and writes the public key to the output buffer.
	// A receiver reads the public key from the input buffer.
	E Token = "e"

	// S indicates the transmission of a static public key.
	// A sender writes the public key to the output buffer.
	// A receiver reads the public key from the input buffer.
	S Token = "s"

	// EE indicates application of the DH construction using the ephemeral keys
	// of both the initiator and responder.
	EE Token = "ee"

	// SE indicates application of the DH construction using the static key of
	// the initiator and the ephemeral key of the responder.
	SE Token = "se"

	// ES indicates application of the DH construction using the ephemeral key
	// of the initiator and the static key of the responder.
	ES Token = "es"

	// SS indicates application of the DH construction using the static keys
	// of both the initiator and responder.
	SS Token = "ss"

	// PSK indicates application of a pre-shared symmetric encryption key.
	// This requires a pre-shared key is defined, and causes it to be mixed into
	// both the encryption keys and the state hash.
	PSK Token = "psk"
)

// IsValid reports whether t is a valid [Token] value.
func (t Token) IsValid() bool {
	switch t {
	case E, S, EE, SE, ES, SS, PSK:
		return true
	}
	return false
}

// PreMessage is a pre-message pattern, indicating what metadata is known to
// the initiator or responder prior to the commencement of a handshake.
type PreMessage int

const (
	NoKeys             PreMessage = iota // no key information is known
	EphemeralOnly                        // only an ephemeral key is known (e)
	StaticOnly                           // only a static key is known (s)
	EphemeralAndStatic                   // both ephemeral and static keys are known (e, s)

	maxValidPreMessage = EphemeralAndStatic
)

// IsValid reports whether p is valid.
func (p PreMessage) IsValid() bool { return p >= NoKeys && p <= maxValidPreMessage }

// HasEphemeral reports whether p specifies an ephemeral key.
func (p PreMessage) HasEphemeral() bool { return p&EphemeralOnly != 0 }

// HasStatic reports whether p specifies a static key.
func (p PreMessage) HasStatic() bool { return p&StaticOnly != 0 }

func (p PreMessage) String() string {
	switch p {
	case NoKeys:
		return "(empty)"
	case EphemeralOnly:
		return "e"
	case StaticOnly:
		return "s"
	case EphemeralAndStatic:
		return "e, s"
	default:
		return fmt.Sprintf("(invalid:%d)", int(p))
	}
}

// A Message is a sequence of [Token] instructions.
type Message []Token

func (p Message) String() string {
	if len(p) == 0 {
		return ""
	} else if len(p) == 1 {
		return string(p[0])
	}
	var sb strings.Builder
	sb.WriteString(string(p[0]))
	for _, s := range p[1:] {
		sb.WriteString(", ")
		sb.WriteString(string(s))
	}
	return sb.String()
}
