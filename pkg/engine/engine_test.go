package engine_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/guilhermec94/security-code-scanner/pkg/engine"
	"github.com/guilhermec94/security-code-scanner/pkg/logger"
	"github.com/guilhermec94/security-code-scanner/pkg/outputs"
	securityvalidations "github.com/guilhermec94/security-code-scanner/pkg/security_validations"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func setupTest() engine.SCSEngine {
	outputChannel := make(chan securityvalidations.OuputData, 100)
	log := logger.NewFileLogger("log-engine.txt")

	// checks
	checkConfigCSS := securityvalidations.Config{
		NumberWorkers: 2,
		FileChannel:   make(chan string, 100),
		OutputChannel: outputChannel,
	}

	cSS := securityvalidations.NewCrossSiteScriptingValidation(checkConfigCSS, log)

	checkConfigSD := securityvalidations.Config{
		NumberWorkers: 2,
		FileChannel:   make(chan string, 100),
		OutputChannel: outputChannel,
	}

	sD := securityvalidations.NewSensitiveDataValidation(checkConfigSD, log)

	checkConfigSQLI := securityvalidations.Config{
		NumberWorkers: 2,
		FileChannel:   make(chan string, 100),
		OutputChannel: outputChannel,
	}

	sqlI := securityvalidations.NewSqlInjectionValidation(checkConfigSQLI, log)

	//security validations list
	securityValidationsList := make([]engine.SecurityValidation, 0)

	securityValidationsList = append(securityValidationsList, cSS)
	securityValidationsList = append(securityValidationsList, sD)
	securityValidationsList = append(securityValidationsList, sqlI)

	// set output format
	var outputFormat engine.AnalysisOuputFormat
	switch strings.ToLower("text") {
	case "text":
		outputFormat = outputs.NewPlainTextOutputFormat(".", outputChannel, log)
	case "json":
		outputFormat = outputs.NewJSONOutputFormat(".", outputChannel, log)
	}

	return engine.NewSCSEngine(securityValidationsList, outputFormat, outputChannel, log)
}

func cleanUpTest() {
	e := os.Remove("log-engine.txt")
	if e != nil {
		logrus.Fatal(e)
	}

	e = os.Remove("output.txt")
	if e != nil {
		logrus.Fatal(e)
	}
}

func TestEngine_RunSecurityChecks(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		// setup
		engine := setupTest()

		// call method
		absPath, err := filepath.Abs("../test_files")
		if err != nil {
			logrus.Fatal(err)
		}
		engine.RunSecurityChecks(absPath)

		// assert
		filog, err := os.Stat("log-engine.txt")
		if err != nil {
			logrus.Fatal(err)
		}

		fiout, err := os.Stat("output.txt")
		if err != nil {
			logrus.Fatal(err)
		}

		sizeLog := filog.Size()
		sizeOut := fiout.Size()
		assert.Nil(t, err)
		assert.Greater(t, sizeOut, int64(0))
		assert.Equal(t, int64(0), sizeLog)
		t.Cleanup(func() { cleanUpTest() })
	})

	t.Run("error", func(t *testing.T) {
		// setup
		engine := setupTest()

		// call method
		absPath, err := filepath.Abs("../test_files_test")
		if err != nil {
			logrus.Fatal(err)
		}
		engine.RunSecurityChecks(absPath)

		// assert
		filog, err := os.Stat("log-engine.txt")
		if err != nil {
			logrus.Fatal(err)
		}

		fiout, err := os.Stat("output.txt")
		if err != nil {
			logrus.Fatal(err)
		}

		sizeLog := filog.Size()
		sizeOut := fiout.Size()
		assert.Nil(t, err)
		assert.Greater(t, sizeLog, int64(0))
		assert.Equal(t, int64(0), sizeOut)
		t.Cleanup(func() { cleanUpTest() })
	})
}
