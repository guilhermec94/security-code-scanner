package cmd

import (
	"errors"

	"github.com/guilhermec94/security-code-scanner/boot"
	"github.com/spf13/cobra"
)

var scanner = &cobra.Command{
	Use:   "scanner",
	Short: "Scan source code",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return errors.New("the path argument is required")
		}

		if len(args) < 2 {
			return errors.New("the output path argument is required")
		}

		if len(args) < 3 {
			return errors.New("the output format argument is required")
		}

		runCommand(args)
		return nil
	},
}

func runCommand(args []string) {
	engine := boot.Init(args[0], args[2])
	engine.RunSecurityChecks(args[1])
}

func init() {
	root.AddCommand(scanner)
}
