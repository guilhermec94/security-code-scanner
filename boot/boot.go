package boot

import (
	"strings"

	"github.com/guilhermec94/security-code-scanner/pkg/engine"
	"github.com/guilhermec94/security-code-scanner/pkg/outputs"
	securityvalidations "github.com/guilhermec94/security-code-scanner/pkg/security-validations"
)

func Init(outputType string) engine.SCSEngine {
	outputChannel := make(chan securityvalidations.OuputData, 100)
	cSS := setupCrossSiteScriptingCheck(outputChannel)
	sD := setupSensitiveDataCheck(outputChannel)
	sqlI := setupSqlInjectionCheck(outputChannel)

	securityValidationsList := make([]engine.SecurityCodeCheck, 0)

	securityValidationsList = append(securityValidationsList, cSS)
	securityValidationsList = append(securityValidationsList, sD)
	securityValidationsList = append(securityValidationsList, sqlI)

	var outputFormat engine.AnalylsisOuputFormat
	switch strings.ToLower(outputType) {
	case "text":
		outputFormat = outputs.NewPlainTextOutput("/home/jimbob/projects/go/security-code-scanner", outputChannel)
	case "json":
		outputFormat = outputs.NewJSONOutput("/home/jimbob/projects/go/security-code-scanner", outputChannel)
	}

	return engine.NewSCSEngine(securityValidationsList, outputFormat, outputChannel)
}

func setupCrossSiteScriptingCheck(output chan<- securityvalidations.OuputData) engine.SecurityCodeCheck {
	checkConfig := securityvalidations.Config{
		NumberWorkers: 2,
		FileChannel:   make(chan string, 100),
		OutputChannel: output,
	}

	return securityvalidations.NewCrossSiteScriptingCheck(checkConfig)
}

func setupSensitiveDataCheck(output chan<- securityvalidations.OuputData) engine.SecurityCodeCheck {
	checkConfig := securityvalidations.Config{
		NumberWorkers: 2,
		FileChannel:   make(chan string, 100),
		OutputChannel: output,
	}

	return securityvalidations.NewSensitiveDataCheck(checkConfig)
}

func setupSqlInjectionCheck(output chan<- securityvalidations.OuputData) engine.SecurityCodeCheck {
	checkConfig := securityvalidations.Config{
		NumberWorkers: 2,
		FileChannel:   make(chan string, 100),
		OutputChannel: output,
	}

	return securityvalidations.NewSqlInjectionCheck(checkConfig)
}
