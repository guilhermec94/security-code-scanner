package cmd

import (
	"github.com/guilhermec94/security-code-scanner/boot"
	"github.com/spf13/cobra"
)

var cmd = &cobra.Command{
	Use:   "scanner",
	Short: "Scan source code",
	Run: func(cmd *cobra.Command, args []string) {
		// arg 1 - path to source code
		// arg 2 - output type
		// arg 3 -
		runCommand(args)
	},
}

func runCommand(args []string) {
	engine := boot.Init()
	engine.RunSecurityChecks(args[0], args[1])
}

func init() {
	root.AddCommand(cmd)
}
