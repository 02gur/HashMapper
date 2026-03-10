// Package template implements a nested hash template parser and executor.
//
// Templates let users express multi-layer hash operations in a simple DSL, e.g.
//
//	md5(password)
//	sha256(md5(password))
//	sha1(password + salt)
//	md5(sha1(password + salt1) + salt2)
//	base64(sha256(password))
//
// Grammar (informal):
//
//	expr     = func_call | term
//	func_call = IDENT '(' args ')'
//	args     = expr ('+' expr)*
//	term     = 'password' | 'salt' | string_literal
//	IDENT    = [a-zA-Z0-9_]+
package template

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"

	"github.com/02gur/HashMapper/internal/algorithms"
)

// Executor evaluates a template expression given a password and optional salt.
type Executor struct {
	Password []byte
	Salt     []byte
}

// Execute parses and evaluates the template, returning the final hash string.
func (e *Executor) Execute(tmpl string) (string, error) {
	p := &parser{input: strings.TrimSpace(tmpl), pos: 0}
	node, err := p.parseExpr()
	if err != nil {
		return "", fmt.Errorf("template parse error: %w", err)
	}
	if p.pos < len(p.input) {
		return "", fmt.Errorf("template parse error: unexpected input at position %d: %q", p.pos, p.input[p.pos:])
	}
	result, err := e.evalNode(node)
	if err != nil {
		return "", fmt.Errorf("template eval error: %w", err)
	}
	return string(result), nil
}

// ─────────────────────────────────────────────────────────────────────────────
// AST nodes
// ─────────────────────────────────────────────────────────────────────────────

type nodeKind int

const (
	nodeFunc    nodeKind = iota // func_call: name + children (args)
	nodeConcat                  // '+' expression: list of children
	nodeVar                     // variable: "password" or "salt"
	nodeLiteral                 // string literal (double-quoted or bare)
)

type node struct {
	kind     nodeKind
	name     string   // for nodeFunc and nodeVar
	children []*node  // for nodeFunc (args) and nodeConcat
	value    string   // for nodeLiteral
}

// ─────────────────────────────────────────────────────────────────────────────
// Parser
// ─────────────────────────────────────────────────────────────────────────────

type parser struct {
	input string
	pos   int
}

func (p *parser) skipWS() {
	for p.pos < len(p.input) && (p.input[p.pos] == ' ' || p.input[p.pos] == '\t') {
		p.pos++
	}
}

func (p *parser) peek() byte {
	if p.pos >= len(p.input) {
		return 0
	}
	return p.input[p.pos]
}

func (p *parser) consume(b byte) error {
	p.skipWS()
	if p.pos >= len(p.input) || p.input[p.pos] != b {
		got := "<EOF>"
		if p.pos < len(p.input) {
			got = string(p.input[p.pos])
		}
		return fmt.Errorf("expected %q at position %d, got %q", b, p.pos, got)
	}
	p.pos++
	return nil
}

func (p *parser) parseExpr() (*node, error) {
	p.skipWS()
	left, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}
	p.skipWS()

	// Handle concatenation with '+'
	if p.peek() == '+' {
		concat := &node{kind: nodeConcat, children: []*node{left}}
		for p.peek() == '+' {
			p.pos++ // consume '+'
			p.skipWS()
			right, err := p.parsePrimary()
			if err != nil {
				return nil, err
			}
			concat.children = append(concat.children, right)
			p.skipWS()
		}
		return concat, nil
	}
	return left, nil
}

func (p *parser) parsePrimary() (*node, error) {
	p.skipWS()
	if p.pos >= len(p.input) {
		return nil, fmt.Errorf("unexpected end of input")
	}

	// String literal (double-quoted)
	if p.input[p.pos] == '"' {
		return p.parseStringLiteral()
	}

	// Identifier or keyword
	ident := p.parseIdent()
	if ident == "" {
		return nil, fmt.Errorf("unexpected character %q at position %d", p.input[p.pos], p.pos)
	}

	p.skipWS()

	// Function call?
	if p.peek() == '(' {
		p.pos++ // consume '('
		p.skipWS()

		var args []*node
		if p.peek() != ')' {
			arg, err := p.parseExpr()
			if err != nil {
				return nil, err
			}
			args = append(args, arg)
			p.skipWS()
			for p.peek() == ',' {
				p.pos++ // consume ','
				p.skipWS()
				arg, err = p.parseExpr()
				if err != nil {
					return nil, err
				}
				args = append(args, arg)
				p.skipWS()
			}
		}
		if err := p.consume(')'); err != nil {
			return nil, err
		}
		return &node{kind: nodeFunc, name: strings.ToLower(ident), children: args}, nil
	}

	// Variable reference
	lower := strings.ToLower(ident)
	if lower == "password" || lower == "pass" || lower == "p" {
		return &node{kind: nodeVar, name: "password"}, nil
	}
	if lower == "salt" || lower == "s" {
		return &node{kind: nodeVar, name: "salt"}, nil
	}

	// Bare literal
	return &node{kind: nodeLiteral, value: ident}, nil
}

func (p *parser) parseIdent() string {
	start := p.pos
	for p.pos < len(p.input) {
		r := rune(p.input[p.pos])
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' {
			p.pos++
		} else {
			break
		}
	}
	return p.input[start:p.pos]
}

func (p *parser) parseStringLiteral() (*node, error) {
	p.pos++ // consume opening '"'
	var buf strings.Builder
	for p.pos < len(p.input) {
		c := p.input[p.pos]
		if c == '"' {
			p.pos++
			return &node{kind: nodeLiteral, value: buf.String()}, nil
		}
		if c == '\\' && p.pos+1 < len(p.input) {
			p.pos++
			switch p.input[p.pos] {
			case 'n':
				buf.WriteByte('\n')
			case 't':
				buf.WriteByte('\t')
			case '"':
				buf.WriteByte('"')
			case '\\':
				buf.WriteByte('\\')
			default:
				buf.WriteByte('\\')
				buf.WriteByte(p.input[p.pos])
			}
		} else {
			buf.WriteByte(c)
		}
		p.pos++
	}
	return nil, fmt.Errorf("unterminated string literal")
}

// ─────────────────────────────────────────────────────────────────────────────
// Evaluator
// ─────────────────────────────────────────────────────────────────────────────

// evalNode evaluates a node and returns its byte-level result.
func (e *Executor) evalNode(n *node) ([]byte, error) {
	switch n.kind {
	case nodeLiteral:
		return []byte(n.value), nil

	case nodeVar:
		switch n.name {
		case "password":
			return e.Password, nil
		case "salt":
			return e.Salt, nil
		}
		return nil, fmt.Errorf("unknown variable %q", n.name)

	case nodeConcat:
		var buf []byte
		for _, child := range n.children {
			part, err := e.evalNode(child)
			if err != nil {
				return nil, err
			}
			buf = append(buf, part...)
		}
		return buf, nil

	case nodeFunc:
		return e.evalFunc(n.name, n.children)

	default:
		return nil, fmt.Errorf("unknown node kind %d", n.kind)
	}
}

// evalFunc dispatches function calls — either hash algorithms or encoding helpers.
func (e *Executor) evalFunc(name string, args []*node) ([]byte, error) {
	// Evaluate arguments first (all args are concatenated as the input).
	var input []byte
	for _, arg := range args {
		part, err := e.evalNode(arg)
		if err != nil {
			return nil, err
		}
		input = append(input, part...)
	}

	// Encoding functions (non-hash).
	switch name {
	case "base64":
		return []byte(base64.StdEncoding.EncodeToString(input)), nil
	case "base64url":
		return []byte(base64.URLEncoding.EncodeToString(input)), nil
	case "hex":
		return []byte(hex.EncodeToString(input)), nil
	case "upper":
		return []byte(strings.ToUpper(string(input))), nil
	case "lower":
		return []byte(strings.ToLower(string(input))), nil
	case "unhex":
		decoded, err := hex.DecodeString(string(input))
		if err != nil {
			return nil, fmt.Errorf("unhex: %w", err)
		}
		return decoded, nil
	}

	// Hash algorithm lookup.
	alg, ok := algorithms.Registry[name]
	if !ok {
		// Try common aliases.
		alg, ok = algorithmAlias(name)
	}
	if !ok {
		return nil, fmt.Errorf("unknown function or algorithm %q", name)
	}

	result, err := alg.Compute(input, e.Salt)
	if err != nil {
		return nil, fmt.Errorf("algorithm %q: %w", name, err)
	}
	return []byte(result), nil
}

// algorithmAlias resolves common shortened names.
func algorithmAlias(name string) (*algorithms.Algorithm, bool) {
	aliases := map[string]string{
		"md5":          "md5",
		"sha1":         "sha1",
		"sha256":       "sha256",
		"sha512":       "sha512",
		"sha224":       "sha224",
		"sha384":       "sha384",
		"sha3_256":     "sha3_256",
		"sha3_512":     "sha3_512",
		"keccak256":    "keccak_256",
		"keccak512":    "keccak_512",
		"blake2b":      "blake2b_512",
		"blake2s":      "blake2s_256",
		"ripemd160":    "ripemd160",
		"ntlm":         "ntlm",
		"whirlpool":    "whirlpool",
		"tiger":        "tiger192_3",
		"tiger192":     "tiger192_3",
		"tiger128":     "tiger128_3",
		"tiger160":     "tiger160_3",
	}
	if mapped, ok := aliases[name]; ok {
		if alg, ok2 := algorithms.Registry[mapped]; ok2 {
			return alg, true
		}
	}
	return nil, false
}
