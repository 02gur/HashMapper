package cmd

import (
	"fmt"
	"os"

	"github.com/02gur/HashMapper/internal/identifier"
	"github.com/spf13/cobra"
)

var identifyCmd = &cobra.Command{
	Use:   "identify <hash>",
	Short: "Identify the algorithm(s) used to produce a hash",
	Long: `Analyse a hash string and print the most likely algorithm(s).

The command inspects:
  • Hash length (in hex / encoded characters)
  • Character set (hex, base64, special prefixes)
  • Known format patterns ($2a$, $1$, pbkdf2_sha256$…)

Examples:
  hashmapper identify 5f4dcc3b5aa765d61d8327deb882cf99
  hashmapper identify --all aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		hash := args[0]
		all, _ := cmd.Flags().GetBool("all")

		var candidates []identifier.Candidate
		if all {
			candidates = identifier.Identify(hash)
		} else {
			candidates = identifier.IdentifyBest(hash)
		}

		if len(candidates) == 0 {
			fmt.Fprintln(os.Stderr, "No matching algorithms found.")
			os.Exit(1)
		}

		fmt.Printf("Hash   : %s\n", hash)
		fmt.Printf("Length : %d characters\n\n", len(hash))
		fmt.Printf("%-5s  %-25s  %-15s  %s\n", "Score", "ID", "Category", "Name")
		fmt.Printf("%-5s  %-25s  %-15s  %s\n", "-----", "-------------------------", "---------------", "----")
		for _, c := range candidates {
			fmt.Printf("%-5d  %-25s  %-15s  %s\n",
				c.Score,
				c.Algorithm.ID,
				string(c.Algorithm.Category),
				c.Algorithm.Name,
			)
		}
		return nil
	},
}

func init() { //nolint:gochecknoinits
	identifyCmd.Flags().Bool("all", false, "Show all candidates, not just the top-scoring ones")
	rootCmd.AddCommand(identifyCmd)
}
