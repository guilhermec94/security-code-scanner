package boot

import (
	"strings"

	"github.com/guilhermec94/security-code-scanner/pkg/engine"
	"github.com/guilhermec94/security-code-scanner/pkg/logger"
	"github.com/guilhermec94/security-code-scanner/pkg/outputs"
	securityvalidations "github.com/guilhermec94/security-code-scanner/pkg/security-validations"
	"github.com/sirupsen/logrus"
)

func Init(outputPath, outputType string) engine.SCSEngine {
	outputChannel := make(chan securityvalidations.OuputData, 100)

	log := logger.GetInstance()

	cSS := setupCrossSiteScriptingCheck(outputChannel, log)
	sD := setupSensitiveDataCheck(outputChannel, log)
	sqlI := setupSqlInjectionCheck(outputChannel, log)

	securityValidationsList := make([]engine.SecurityCodeCheck, 0)

	securityValidationsList = append(securityValidationsList, cSS)
	securityValidationsList = append(securityValidationsList, sD)
	securityValidationsList = append(securityValidationsList, sqlI)

	var outputFormat engine.AnalylsisOuputFormat
	switch strings.ToLower(outputType) {
	case "text":
		outputFormat = outputs.NewPlainTextOutput(outputPath, outputChannel, log)
	case "json":
		outputFormat = outputs.NewJSONOutput(outputPath, outputChannel, log)
	}

	return engine.NewSCSEngine(securityValidationsList, outputFormat, outputChannel, log)
}

func setupCrossSiteScriptingCheck(output chan<- securityvalidations.OuputData, logger *logrus.Logger) engine.SecurityCodeCheck {
	checkConfig := securityvalidations.Config{
		NumberWorkers: 2,
		FileChannel:   make(chan string, 100),
		OutputChannel: output,
	}

	return securityvalidations.NewCrossSiteScriptingCheck(checkConfig, logger)
}

func setupSensitiveDataCheck(output chan<- securityvalidations.OuputData, logger *logrus.Logger) engine.SecurityCodeCheck {
	checkConfig := securityvalidations.Config{
		NumberWorkers: 2,
		FileChannel:   make(chan string, 100),
		OutputChannel: output,
	}

	return securityvalidations.NewSensitiveDataCheck(checkConfig, logger)
}

func setupSqlInjectionCheck(output chan<- securityvalidations.OuputData, logger *logrus.Logger) engine.SecurityCodeCheck {
	checkConfig := securityvalidations.Config{
		NumberWorkers: 2,
		FileChannel:   make(chan string, 100),
		OutputChannel: output,
	}

	return securityvalidations.NewSqlInjectionCheck(checkConfig, logger)
}
