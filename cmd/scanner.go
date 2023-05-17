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
		sourcePath, _ := cmd.Flags().GetString("source")
		output, _ := cmd.Flags().GetString("output")
		outputFormat, _ := cmd.Flags().GetString("output-format")
		if len(sourcePath) == 0 {
			return errors.New("the source path argument is required")
		}

		if len(output) == 0 {
			return errors.New("the output path argument is required")
		}

		if len(outputFormat) == 0 {
			return errors.New("the output format argument is required")
		}

		runCommand(sourcePath, output, outputFormat)
		return nil
	},
}

func runCommand(sourcePath, output, outputFormat string) {
	engine := boot.Init(output, outputFormat)
	engine.RunSecurityChecks(sourcePath)
}

func init() {
	root.AddCommand(scanner)

	scanner.PersistentFlags().String("source", "", "set the source path")
	scanner.PersistentFlags().String("output", "", "set the output path")
	scanner.PersistentFlags().String("output-format", "", "set the output format")
}
