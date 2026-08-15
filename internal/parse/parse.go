// Package parse parses string representations.
package parse

import (
	"errors"
	"fmt"
	"strings"

	"github.com/creachadair/mds/mstr"
)

func isUpper(c rune) bool { return c >= 'A' && c <= 'Z' }
func isLower(c rune) bool { return c >= 'a' && c <= 'z' }
func isDigit(c rune) bool { return c >= '0' && c <= '9' }

// PatternName parses the text representation of a handshake pattern name (8.1).
func PatternName(s string) (name string, mods []string, _ error) {
	end := strings.IndexFunc(s, func(r rune) bool { return !isUpper(r) && !isDigit(r) })
	if end < 0 {
		end = len(s)
	}
	if end == 0 {
		return "", nil, errors.New("empty pattern name")
	}

	mods = mstr.Split(s[end:], "+")
	for _, mod := range mods {
		if len(mod) == 0 {
			return "", nil, errors.New("empty modifier")
		} else if strings.ContainsFunc(mod, func(r rune) bool { return !isLower(r) && !isDigit(r) }) {
			return "", nil, fmt.Errorf("modifier allows only letters and digits (%q)", mod)
		} else if !isLower(rune(mod[0])) {
			return "", nil, fmt.Errorf("modifier %q does not begin with a letter", mod)
		}
	}
	return s[:end], mods, nil
}
