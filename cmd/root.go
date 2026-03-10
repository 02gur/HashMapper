// Package cmd implements the HashMapper command-line interface.
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// rootCmd is the base command when called without any sub-commands.
var rootCmd = &cobra.Command{
	Use:   "hashmapper",
	Short: "HashMapper — multi-layered hash identification and brute-force tool",
	Long: `HashMapper is a highly concurrent, multi-layered hash identification and
brute-force tool written in Go.

It supports 87+ algorithms, salt formatting, and deep nested template decryption.

Examples:
  # Identify a hash
  hashmapper identify 5f4dcc3b5aa765d61d8327deb882cf99

  # Crack a hash using a wordlist
  hashmapper crack --hash 5f4dcc3b5aa765d61d8327deb882cf99 --wordlist /usr/share/wordlists/rockyou.txt

  # Crack using brute-force
  hashmapper crack --hash 5f4dcc3b5aa765d61d8327deb882cf99 --brute --charset "abcdef0123456789" --maxlen 8

  # Crack with a salt
  hashmapper crack --hash <hash> --wordlist wordlist.txt --salt mysalt --salt-mode append

  # Crack using a nested template
  hashmapper crack --hash <hash> --wordlist wordlist.txt --template "md5(sha1(password+salt))" --salt mysalt`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main().
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
