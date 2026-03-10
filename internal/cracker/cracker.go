// Package cracker implements concurrent hash cracking via wordlist and brute-force attacks.
package cracker

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/02gur/HashMapper/internal/algorithms"
	"github.com/02gur/HashMapper/internal/salt"
	tmpl "github.com/02gur/HashMapper/internal/template"
)

// Result is returned when a hash is successfully cracked.
type Result struct {
	// Hash is the target hash that was cracked.
	Hash string
	// Plaintext is the cleartext that produced the hash.
	Plaintext string
	// Algorithm is the algorithm used.
	Algorithm *algorithms.Algorithm
	// Salt is the salt value that was used (may be empty).
	Salt string
	// SaltMode is the salt formatting mode applied.
	SaltMode salt.Mode
}

// Config holds the parameters for a cracking job.
type Config struct {
	// Target is the hash string to crack.
	Target string
	// Algorithms to attempt.  If nil, the identifier is used to auto-detect.
	Algorithms []*algorithms.Algorithm
	// SaltValue is the known salt (may be empty).
	SaltValue string
	// SaltModes is the list of salt formatting modes to try.
	// Defaults to all modes when empty.
	SaltModes []salt.Mode
	// Template is an optional nested hash expression (e.g. "md5(sha1(password))").
	// When set, Algorithm is ignored and the template drives the computation.
	Template string
	// Workers is the number of concurrent goroutines to use.
	Workers int
	// Progress receives the number of candidates tested so far (optional).
	Progress chan<- int64
}

// WordlistAttack runs a dictionary attack reading candidates from r.
// It returns the first matching Result, or nil if not found.
func WordlistAttack(ctx context.Context, cfg Config, r io.Reader) (*Result, error) {
	cfg = applyDefaults(cfg)

	lines := make(chan []byte, cfg.Workers*2)
	var result atomic.Pointer[Result]
	var tested int64

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	for i := 0; i < cfg.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case line, ok := <-lines:
					if !ok {
						return
					}
					if r := testCandidate(cfg, line); r != nil {
						if result.CompareAndSwap(nil, r) {
							cancel()
						}
					}
					n := atomic.AddInt64(&tested, 1)
					if cfg.Progress != nil && n%1000 == 0 {
						select {
						case cfg.Progress <- n:
						default:
						}
					}
				}
			}
		}()
	}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			break
		default:
		}
		word := make([]byte, len(scanner.Bytes()))
		copy(word, scanner.Bytes())
		lines <- word
	}
	close(lines)
	wg.Wait()

	if r := result.Load(); r != nil {
		return r, nil
	}
	return nil, nil
}

// WordlistAttackFile is a convenience wrapper that opens a file path.
func WordlistAttackFile(ctx context.Context, cfg Config, wordlistPath string) (*Result, error) {
	f, err := os.Open(wordlistPath)
	if err != nil {
		return nil, fmt.Errorf("open wordlist: %w", err)
	}
	defer f.Close() //nolint:errcheck
	return WordlistAttack(ctx, cfg, f)
}

// BruteForceAttack tries all combinations of charset up to maxLen characters.
func BruteForceAttack(ctx context.Context, cfg Config, charset string, minLen, maxLen int) (*Result, error) {
	if charset == "" {
		charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	}
	cfg = applyDefaults(cfg)

	candidates := make(chan []byte, cfg.Workers*4)
	var result atomic.Pointer[Result]
	var tested int64

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	for i := 0; i < cfg.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case candidate, ok := <-candidates:
					if !ok {
						return
					}
					if r := testCandidate(cfg, candidate); r != nil {
						if result.CompareAndSwap(nil, r) {
							cancel()
						}
					}
					n := atomic.AddInt64(&tested, 1)
					if cfg.Progress != nil && n%10000 == 0 {
						select {
						case cfg.Progress <- n:
						default:
						}
					}
				}
			}
		}()
	}

	// Generate candidates synchronously; generation is cheap vs. hashing.
	runes := []rune(charset)
	for length := minLen; length <= maxLen; length++ {
		if err := ctx.Err(); err != nil {
			break
		}
		generateCombinations(ctx, runes, length, candidates)
	}
	close(candidates)
	wg.Wait()

	if r := result.Load(); r != nil {
		return r, nil
	}
	return nil, nil
}

// generateCombinations produces all strings of exactly length runes from the charset.
func generateCombinations(ctx context.Context, charset []rune, length int, out chan<- []byte) {
	total := int(math.Pow(float64(len(charset)), float64(length)))
	for i := 0; i < total; i++ {
		if ctx.Err() != nil {
			return
		}
		buf := make([]rune, length)
		n := i
		for pos := length - 1; pos >= 0; pos-- {
			buf[pos] = charset[n%len(charset)]
			n /= len(charset)
		}
		candidate := []byte(string(buf))
		select {
		case <-ctx.Done():
			return
		case out <- candidate:
		}
	}
}

// testCandidate checks whether candidate (possibly combined with salt) matches
// the target hash according to cfg.
func testCandidate(cfg Config, candidate []byte) *Result {
	saltBytes := []byte(cfg.SaltValue)

	// Template mode
	if cfg.Template != "" {
		exec := &tmpl.Executor{Password: candidate, Salt: saltBytes}
		got, err := exec.Execute(cfg.Template)
		if err != nil {
			return nil
		}
		if strings.EqualFold(got, cfg.Target) {
			return &Result{
				Hash:      cfg.Target,
				Plaintext: string(candidate),
				SaltMode:  salt.ModeNone,
				Salt:      cfg.SaltValue,
			}
		}
		return nil
	}

	for _, alg := range cfg.Algorithms {
		for _, mode := range cfg.SaltModes {
			var input []byte
			if mode == salt.ModeNone || cfg.SaltValue == "" {
				input = candidate
			} else {
				input = salt.Format(candidate, saltBytes, mode)
			}

			var key []byte
			if alg.IsSalted {
				key = saltBytes
			}

			got, err := alg.Compute(input, key)
			if err != nil {
				continue
			}

			if strings.EqualFold(got, cfg.Target) {
				return &Result{
					Hash:      cfg.Target,
					Plaintext: string(candidate),
					Algorithm: alg,
					Salt:      cfg.SaltValue,
					SaltMode:  mode,
				}
			}
		}
	}
	return nil
}

// applyDefaults fills in zero-value fields of cfg.
func applyDefaults(cfg Config) Config {
	if cfg.Workers <= 0 {
		cfg.Workers = 4
	}
	if len(cfg.SaltModes) == 0 {
		if cfg.SaltValue == "" {
			cfg.SaltModes = []salt.Mode{salt.ModeNone}
		} else {
			cfg.SaltModes = salt.AllModes
		}
	}
	return cfg
}
