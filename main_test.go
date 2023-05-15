package main

import (
	"testing"

	"github.com/guilhermec94/security-code-scanner/boot"
)

func BenchmarkTool(b *testing.B) {
	engine := boot.Init("text")
	engine.RunSecurityChecks("/home/jimbob/projects/go/tsource", "test")
}
