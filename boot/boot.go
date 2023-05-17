package boot

import (
	"strings"

	"github.com/guilhermec94/security-code-scanner/pkg/engine"
	"github.com/guilhermec94/security-code-scanner/pkg/logger"
	"github.com/guilhermec94/security-code-scanner/pkg/outputs"
	securityvalidations "github.com/guilhermec94/security-code-scanner/pkg/security_validations"
)

func Init(outputPath, outputType string) engine.SCSEngine {
	outputChannel := make(chan securityvalidations.OuputData, 100)
	log := logger.NewFileLogger("log.txt")

	// checks
	cSS := setupCrossSiteScriptingCheck(outputChannel, log)
	sD := setupSensitiveDataCheck(outputChannel, log)
	sqlI := setupSqlInjectionCheck(outputChannel, log)

	//security validations list
	securityValidationsList := make([]engine.SecurityValidation, 0)

	securityValidationsList = append(securityValidationsList, cSS)
	securityValidationsList = append(securityValidationsList, sD)
	securityValidationsList = append(securityValidationsList, sqlI)

	// set output format
	var outputFormat engine.AnalylsisOuputFormat
	switch strings.ToLower(outputType) {
	case "text":
		outputFormat = outputs.NewPlainTextOutput(outputPath, outputChannel, log)
	case "json":
		outputFormat = outputs.NewJSONOutput(outputPath, outputChannel, log)
	}

	return engine.NewSCSEngine(securityValidationsList, outputFormat, outputChannel, log)
}

func setupCrossSiteScriptingCheck(output chan<- securityvalidations.OuputData, logger logger.CustomFileLogger) engine.SecurityValidation {
	checkConfig := securityvalidations.Config{
		NumberWorkers: 2,
		FileChannel:   make(chan string, 100),
		OutputChannel: output,
	}

	return securityvalidations.NewCrossSiteScriptingValidation(checkConfig, logger)
}

func setupSensitiveDataCheck(output chan<- securityvalidations.OuputData, logger logger.CustomFileLogger) engine.SecurityValidation {
	checkConfig := securityvalidations.Config{
		NumberWorkers: 2,
		FileChannel:   make(chan string, 100),
		OutputChannel: output,
	}

	return securityvalidations.NewSensitiveDataValidation(checkConfig, logger)
}

func setupSqlInjectionCheck(output chan<- securityvalidations.OuputData, logger logger.CustomFileLogger) engine.SecurityValidation {
	checkConfig := securityvalidations.Config{
		NumberWorkers: 2,
		FileChannel:   make(chan string, 100),
		OutputChannel: output,
	}

	return securityvalidations.NewSqlInjectionValidation(checkConfig, logger)
}
