package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var cmd = &cobra.Command{
	Use:   "scanner",
	Short: "Scan source code",
	Run: func(cmd *cobra.Command, args []string) {
		runCommand(args)
	},
}

func runCommand(args []string) {
	fmt.Print("run")
}

func init() {
	root.AddCommand(cmd)
}
