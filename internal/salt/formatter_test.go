package salt_test

import (
	"testing"

	"github.com/02gur/HashMapper/internal/salt"
)

func TestFormat(t *testing.T) {
	pass := []byte("password")
	s := []byte("salt")

	cases := []struct {
		mode salt.Mode
		want string
	}{
		{salt.ModeNone, "password"},
		{salt.ModeAppend, "passwordsalt"},
		{salt.ModePrepend, "saltpassword"},
		{salt.ModeColonAppend, "password:salt"},
		{salt.ModeColonPrepend, "salt:password"},
		{salt.ModeDollarAppend, "password$salt"},
		{salt.ModeDollarPrepend, "salt$password"},
		{salt.ModeDotAppend, "password.salt"},
		{salt.ModeDotPrepend, "salt.password"},
		{salt.ModeUnderscoreAppend, "password_salt"},
		{salt.ModeUnderscorePrepend, "salt_password"},
		{salt.ModePipeAppend, "password|salt"},
		{salt.ModePipePrepend, "salt|password"},
	}

	for _, c := range cases {
		t.Run(string(c.mode), func(t *testing.T) {
			got := string(salt.Format(pass, s, c.mode))
			if got != c.want {
				t.Errorf("Format(%q) = %q, want %q", c.mode, got, c.want)
			}
		})
	}
}

func TestFormatNilSalt(t *testing.T) {
	pass := []byte("password")
	got := string(salt.Format(pass, nil, salt.ModeAppend))
	if got != "password" {
		t.Errorf("expected \"password\", got %q", got)
	}
}

func TestParseMode(t *testing.T) {
	for _, m := range salt.AllModes {
		got, err := salt.ParseMode(string(m))
		if err != nil {
			t.Errorf("ParseMode(%q) returned error: %v", m, err)
		}
		if got != m {
			t.Errorf("ParseMode(%q) = %q, want %q", m, got, m)
		}
	}
}

func TestParseModeUnknown(t *testing.T) {
	_, err := salt.ParseMode("invalid_mode")
	if err == nil {
		t.Error("expected error for unknown mode, got nil")
	}
}

func TestAllModesCount(t *testing.T) {
	if len(salt.AllModes) < 13 {
		t.Errorf("expected at least 13 salt modes, got %d", len(salt.AllModes))
	}
}
