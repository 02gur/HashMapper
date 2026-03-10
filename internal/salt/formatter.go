// Package salt implements salt formatting utilities.
// It defines the common ways a salt is combined with a password before hashing.
package salt

import "fmt"

// Mode defines how a salt is combined with the password.
type Mode string

const (
	// ModeNone — no salt, password is used as-is.
	ModeNone Mode = "none"
	// ModeAppend — password + salt (e.g. "password" + "salt").
	ModeAppend Mode = "append"
	// ModePrepend — salt + password (e.g. "salt" + "password").
	ModePrepend Mode = "prepend"
	// ModeColonAppend — password:salt
	ModeColonAppend Mode = "colon_append"
	// ModeColonPrepend — salt:password
	ModeColonPrepend Mode = "colon_prepend"
	// ModeDollarAppend — password$salt
	ModeDollarAppend Mode = "dollar_append"
	// ModeDollarPrepend — salt$password
	ModeDollarPrepend Mode = "dollar_prepend"
	// ModeDotAppend — password.salt
	ModeDotAppend Mode = "dot_append"
	// ModeDotPrepend — salt.password
	ModeDotPrepend Mode = "dot_prepend"
	// ModeUnderscoreAppend — password_salt
	ModeUnderscoreAppend Mode = "underscore_append"
	// ModeUnderscorePrepend — salt_password
	ModeUnderscorePrepend Mode = "underscore_prepend"
	// ModePipeAppend — password|salt
	ModePipeAppend Mode = "pipe_append"
	// ModePipePrepend — salt|password
	ModePipePrepend Mode = "pipe_prepend"
)

// AllModes is the ordered list of every supported salt mode.
var AllModes = []Mode{
	ModeNone,
	ModeAppend,
	ModePrepend,
	ModeColonAppend,
	ModeColonPrepend,
	ModeDollarAppend,
	ModeDollarPrepend,
	ModeDotAppend,
	ModeDotPrepend,
	ModeUnderscoreAppend,
	ModeUnderscorePrepend,
	ModePipeAppend,
	ModePipePrepend,
}

// Format combines password and salt according to mode.
// If mode is unknown it falls back to ModeAppend.
func Format(password, saltVal []byte, mode Mode) []byte {
	p := string(password)
	s := string(saltVal)
	switch mode {
	case ModeNone:
		return password
	case ModeAppend:
		return []byte(p + s)
	case ModePrepend:
		return []byte(s + p)
	case ModeColonAppend:
		return []byte(p + ":" + s)
	case ModeColonPrepend:
		return []byte(s + ":" + p)
	case ModeDollarAppend:
		return []byte(p + "$" + s)
	case ModeDollarPrepend:
		return []byte(s + "$" + p)
	case ModeDotAppend:
		return []byte(p + "." + s)
	case ModeDotPrepend:
		return []byte(s + "." + p)
	case ModeUnderscoreAppend:
		return []byte(p + "_" + s)
	case ModeUnderscorePrepend:
		return []byte(s + "_" + p)
	case ModePipeAppend:
		return []byte(p + "|" + s)
	case ModePipePrepend:
		return []byte(s + "|" + p)
	default:
		return []byte(p + s)
	}
}

// ParseMode converts a string to a Mode, returning an error if unknown.
func ParseMode(s string) (Mode, error) {
	m := Mode(s)
	for _, known := range AllModes {
		if m == known {
			return m, nil
		}
	}
	return ModeNone, fmt.Errorf("unknown salt mode %q; valid modes: %v", s, AllModes)
}
