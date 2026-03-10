package template_test

import (
	"testing"

	tmpl "github.com/02gur/HashMapper/internal/template"
)

func exec(t *testing.T, expression, password, saltVal string) string {
	t.Helper()
	e := &tmpl.Executor{Password: []byte(password), Salt: []byte(saltVal)}
	result, err := e.Execute(expression)
	if err != nil {
		t.Fatalf("Execute(%q) error: %v", expression, err)
	}
	return result
}

// TestSimpleAlgorithm checks that a single-algorithm expression works.
func TestSimpleAlgorithm(t *testing.T) {
	// md5("password") should equal the known MD5 hash.
	got := exec(t, "md5(password)", "password", "")
	want := "5f4dcc3b5aa765d61d8327deb882cf99"
	if got != want {
		t.Errorf("md5(password) = %q, want %q", got, want)
	}
}

// TestNestedAlgorithm verifies two-layer nesting.
func TestNestedAlgorithm(t *testing.T) {
	// sha1(md5(password)) — compute expected manually.
	inner := exec(t, "md5(password)", "password", "")
	outer := exec(t, "sha1(password)", inner, "")
	nested := exec(t, "sha1(md5(password))", "password", "")
	if nested != outer {
		t.Errorf("sha1(md5(password)) = %q, want %q", nested, outer)
	}
}

// TestDeepNesting verifies three-level nesting.
func TestDeepNesting(t *testing.T) {
	a := exec(t, "md5(password)", "password", "")
	b := exec(t, "sha1(password)", a, "")
	c := exec(t, "sha256(password)", b, "")
	deep := exec(t, "sha256(sha1(md5(password)))", "password", "")
	if deep != c {
		t.Errorf("sha256(sha1(md5(password))) = %q, want %q", deep, c)
	}
}

// TestConcatWithSalt verifies password+salt concatenation.
func TestConcatWithSalt(t *testing.T) {
	// md5(password + salt) should equal md5("passwordsalt").
	combined := exec(t, "md5(password)", "passwordsalt", "")
	withSalt := exec(t, "md5(password+salt)", "password", "salt")
	if withSalt != combined {
		t.Errorf("md5(password+salt) = %q, want %q", withSalt, combined)
	}
}

// TestLiteralInTemplate verifies bare string literals in expressions.
func TestLiteralInTemplate(t *testing.T) {
	// md5("hello") must match known vector.
	got := exec(t, `md5("hello")`, "", "")
	want := "5d41402abc4b2a76b9719d911017c592"
	if got != want {
		t.Errorf(`md5("hello") = %q, want %q`, got, want)
	}
}

// TestBase64Wrapper verifies the base64 encoding function.
func TestBase64Wrapper(t *testing.T) {
	// base64(md5(password)) — the result should be non-empty base64.
	got := exec(t, "base64(md5(password))", "password", "")
	if got == "" {
		t.Error("base64(md5(password)) returned empty string")
	}
}

// TestHexWrapper verifies the hex encoding function.
func TestHexWrapper(t *testing.T) {
	// hex(password) = hex("pass") when password="pass"
	got := exec(t, "hex(password)", "pass", "")
	want := "70617373" // "pass" in hex
	if got != want {
		t.Errorf("hex(password) = %q, want %q", got, want)
	}
}

// TestUpperWrapper verifies the upper() encoding function.
func TestUpperWrapper(t *testing.T) {
	got := exec(t, "upper(md5(password))", "password", "")
	want := "5F4DCC3B5AA765D61D8327DEB882CF99"
	if got != want {
		t.Errorf("upper(md5(password)) = %q, want %q", got, want)
	}
}

// TestTemplateParseError verifies that malformed templates return errors.
func TestTemplateParseError(t *testing.T) {
	bad := []string{
		"md5(",         // unclosed paren
		"md5(password", // unclosed paren
		`md5("unterminated)`, // unterminated string
		"unknownfunc(password)", // unknown algorithm
	}
	for _, expr := range bad {
		e := &tmpl.Executor{Password: []byte("test"), Salt: nil}
		_, err := e.Execute(expr)
		if err == nil {
			t.Errorf("Execute(%q) expected error, got nil", expr)
		}
	}
}

// TestSHA1Template validates sha1 template.
func TestSHA1Template(t *testing.T) {
	got := exec(t, "sha1(password)", "password", "")
	want := "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
	if got != want {
		t.Errorf("sha1(password) = %q, want %q", got, want)
	}
}
