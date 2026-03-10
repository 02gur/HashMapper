package cracker_test

import (
	"context"
	"strings"
	"testing"

	"github.com/02gur/HashMapper/internal/algorithms"
	"github.com/02gur/HashMapper/internal/cracker"
	"github.com/02gur/HashMapper/internal/salt"
)

func algByID(t *testing.T, id string) *algorithms.Algorithm {
	t.Helper()
	a, ok := algorithms.Registry[id]
	if !ok {
		t.Fatalf("algorithm %q not found", id)
	}
	return a
}

// TestWordlistAttack checks a simple dictionary attack.
func TestWordlistAttack(t *testing.T) {
	// Target: MD5("password")
	target := "5f4dcc3b5aa765d61d8327deb882cf99"
	wordlist := strings.NewReader("notthis\nalsonotthis\npassword\nsomethingelse\n")

	cfg := cracker.Config{
		Target:     target,
		Algorithms: []*algorithms.Algorithm{algByID(t, "md5")},
		Workers:    2,
	}

	result, err := cracker.WordlistAttack(context.Background(), cfg, wordlist)
	if err != nil {
		t.Fatalf("WordlistAttack error: %v", err)
	}
	if result == nil {
		t.Fatal("expected a result, got nil")
	}
	if result.Plaintext != "password" {
		t.Errorf("Plaintext = %q, want %q", result.Plaintext, "password")
	}
}

// TestWordlistAttackNotFound checks that nil is returned when the hash is not in the list.
func TestWordlistAttackNotFound(t *testing.T) {
	target := "5f4dcc3b5aa765d61d8327deb882cf99"
	wordlist := strings.NewReader("abc\ndef\nghi\n")

	cfg := cracker.Config{
		Target:     target,
		Algorithms: []*algorithms.Algorithm{algByID(t, "md5")},
		Workers:    2,
	}

	result, err := cracker.WordlistAttack(context.Background(), cfg, wordlist)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Errorf("expected nil result, got plaintext %q", result.Plaintext)
	}
}

// TestWordlistAttackWithSalt checks salt-aware cracking.
func TestWordlistAttackWithSalt(t *testing.T) {
	// md5("passwordsalt") = md5 of appended salt
	md5alg := algByID(t, "md5")
	combined, err := md5alg.Compute([]byte("passwordsalt"), nil)
	if err != nil {
		t.Fatal(err)
	}

	wordlist := strings.NewReader("wrong\npassword\n")
	cfg := cracker.Config{
		Target:     combined,
		Algorithms: []*algorithms.Algorithm{md5alg},
		SaltValue:  "salt",
		SaltModes:  []salt.Mode{salt.ModeAppend},
		Workers:    2,
	}

	result, err := cracker.WordlistAttack(context.Background(), cfg, wordlist)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if result.Plaintext != "password" {
		t.Errorf("plaintext = %q, want %q", result.Plaintext, "password")
	}
}

// TestBruteForceAttack checks simple brute-force cracking.
func TestBruteForceAttack(t *testing.T) {
	// Target: MD5("ab")
	md5alg := algByID(t, "md5")
	target, _ := md5alg.Compute([]byte("ab"), nil)

	cfg := cracker.Config{
		Target:     target,
		Algorithms: []*algorithms.Algorithm{md5alg},
		Workers:    2,
	}

	result, err := cracker.BruteForceAttack(context.Background(), cfg, "abcde", 1, 2)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if result.Plaintext != "ab" {
		t.Errorf("plaintext = %q, want %q", result.Plaintext, "ab")
	}
}

// TestWordlistAttackTemplate verifies cracking with a nested template.
func TestWordlistAttackTemplate(t *testing.T) {
	// sha1(md5("password")) — compute the expected hash.
	md5alg := algByID(t, "md5")
	sha1alg := algByID(t, "sha1")
	inner, _ := md5alg.Compute([]byte("password"), nil)
	outer, _ := sha1alg.Compute([]byte(inner), nil)

	wordlist := strings.NewReader("wrong\npassword\n")
	cfg := cracker.Config{
		Target:   outer,
		Template: "sha1(md5(password))",
		Workers:  2,
	}

	result, err := cracker.WordlistAttack(context.Background(), cfg, wordlist)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if result.Plaintext != "password" {
		t.Errorf("plaintext = %q, want %q", result.Plaintext, "password")
	}
}

// TestBruteForceContextCancellation checks that a cancelled context stops the attack.
func TestBruteForceContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancelled immediately

	cfg := cracker.Config{
		Target:     "ffffffffffffffffffffffffffffffff",
		Algorithms: []*algorithms.Algorithm{algByID(t, "md5")},
		Workers:    2,
	}

	// Should return without hanging even though hash won't be found.
	result, err := cracker.BruteForceAttack(ctx, cfg, "abcdef0123456789", 1, 4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = result // nil is fine
}
