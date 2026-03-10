package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/02gur/HashMapper/internal/algorithms"
	"github.com/02gur/HashMapper/internal/cracker"
	"github.com/02gur/HashMapper/internal/identifier"
	"github.com/02gur/HashMapper/internal/salt"
	"github.com/spf13/cobra"
)

var crackCmd = &cobra.Command{
	Use:   "crack",
	Short: "Attempt to crack (reverse) a hash value",
	Long: `Attempt to recover the plaintext that produced a given hash.

Attack modes:
  --wordlist    dictionary attack (one candidate per line)
  --brute       exhaustive brute-force over a character set

Salt support (--salt + --salt-mode):
  Modes: none, append, prepend, colon_append, colon_prepend,
         dollar_append, dollar_prepend, dot_append, dot_prepend,
         underscore_append, underscore_prepend, pipe_append, pipe_prepend

  When --salt is given and --salt-mode is omitted, all modes are tried.

Nested templates (--template):
  Override the hash algorithm with an expression such as:
    md5(sha1(password))
    sha256(password + salt)
    base64(md5(sha1(password + "prefix") + salt))

Examples:
  hashmapper crack --hash 5f4dcc3b5aa765d61d8327deb882cf99 --wordlist words.txt
  hashmapper crack --hash <hash> --wordlist words.txt --salt abc --salt-mode append
  hashmapper crack --hash <hash> --brute --charset "0123456789" --minlen 4 --maxlen 6
  hashmapper crack --hash <hash> --wordlist words.txt --template "md5(sha1(password+salt))" --salt xyz`,
	RunE: runCrack,
}

func init() { //nolint:gochecknoinits
	f := crackCmd.Flags()
	f.String("hash", "", "Target hash to crack (required)")
	f.StringSlice("algorithm", nil, "Algorithm ID(s) to try (auto-detected when omitted)")
	f.String("wordlist", "", "Path to wordlist file for dictionary attack")
	f.Bool("brute", false, "Enable brute-force attack")
	f.String("charset", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", "Character set for brute-force")
	f.Int("minlen", 1, "Minimum candidate length for brute-force")
	f.Int("maxlen", 8, "Maximum candidate length for brute-force")
	f.String("salt", "", "Salt value")
	f.String("salt-mode", "", "Salt formatting mode (see help)")
	f.String("template", "", "Nested hash template expression")
	f.Int("workers", runtime.NumCPU(), "Number of concurrent worker goroutines")
	f.Bool("verbose", false, "Print progress every second")

	_ = crackCmd.MarkFlagRequired("hash")
	rootCmd.AddCommand(crackCmd)
}

func runCrack(cmd *cobra.Command, _ []string) error {
	f := cmd.Flags()
	target, _ := f.GetString("hash")
	algIDs, _ := f.GetStringSlice("algorithm")
	wordlist, _ := f.GetString("wordlist")
	bruteForce, _ := f.GetBool("brute")
	charset, _ := f.GetString("charset")
	minLen, _ := f.GetInt("minlen")
	maxLen, _ := f.GetInt("maxlen")
	saltVal, _ := f.GetString("salt")
	saltModeStr, _ := f.GetString("salt-mode")
	tmplExpr, _ := f.GetString("template")
	workers, _ := f.GetInt("workers")
	verbose, _ := f.GetBool("verbose")

	if wordlist == "" && !bruteForce {
		return fmt.Errorf("specify at least one attack mode: --wordlist <file> or --brute")
	}

	// Resolve algorithms.
	var algs []*algorithms.Algorithm
	if tmplExpr == "" {
		if len(algIDs) > 0 {
			for _, id := range algIDs {
				id = strings.ToLower(strings.TrimSpace(id))
				a, ok := algorithms.Registry[id]
				if !ok {
					return fmt.Errorf("unknown algorithm %q", id)
				}
				algs = append(algs, a)
			}
		} else {
			// Auto-detect.
			candidates := identifier.Identify(target)
			if len(candidates) == 0 {
				return fmt.Errorf("could not identify algorithm for hash %q; use --algorithm to specify", target)
			}
			fmt.Fprintf(os.Stderr, "Auto-detected %d possible algorithm(s):\n", len(candidates))
			for _, c := range candidates {
				fmt.Fprintf(os.Stderr, "  %-25s (%s)\n", c.Algorithm.ID, c.Algorithm.Name)
				algs = append(algs, c.Algorithm)
			}
		}
	}

	// Resolve salt mode(s).
	var saltModes []salt.Mode
	if saltModeStr != "" {
		m, err := salt.ParseMode(saltModeStr)
		if err != nil {
			return err
		}
		saltModes = []salt.Mode{m}
	}

	cfg := cracker.Config{
		Target:     target,
		Algorithms: algs,
		SaltValue:  saltVal,
		SaltModes:  saltModes,
		Template:   tmplExpr,
		Workers:    workers,
	}

	// Progress reporting.
	var progressCh chan int64
	if verbose {
		progressCh = make(chan int64, 4)
		cfg.Progress = progressCh
		go func() {
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			var last int64
			for {
				select {
				case n, ok := <-progressCh:
					if !ok {
						return
					}
					last = n
				case <-ticker.C:
					fmt.Fprintf(os.Stderr, "\r  tested: %d", last)
				}
			}
		}()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Fprintf(os.Stderr, "Cracking %s ...\n", target)

	var result *cracker.Result
	var err error

	if wordlist != "" {
		result, err = cracker.WordlistAttackFile(ctx, cfg, wordlist)
		if err != nil {
			return fmt.Errorf("wordlist attack: %w", err)
		}
	}

	if result == nil && bruteForce {
		result, err = cracker.BruteForceAttack(ctx, cfg, charset, minLen, maxLen)
		if err != nil {
			return fmt.Errorf("brute-force attack: %w", err)
		}
	}

	if progressCh != nil {
		close(progressCh)
		fmt.Fprintln(os.Stderr)
	}

	if result == nil {
		fmt.Println("[!] Hash not cracked.")
		os.Exit(1)
	}

	fmt.Println()
	fmt.Println("[+] Hash cracked!")
	fmt.Printf("    Hash      : %s\n", result.Hash)
	fmt.Printf("    Plaintext : %s\n", result.Plaintext)
	if result.Algorithm != nil {
		fmt.Printf("    Algorithm : %s (%s)\n", result.Algorithm.ID, result.Algorithm.Name)
	}
	if result.Salt != "" {
		fmt.Printf("    Salt      : %s\n", result.Salt)
		fmt.Printf("    Salt mode : %s\n", result.SaltMode)
	}
	return nil
}
