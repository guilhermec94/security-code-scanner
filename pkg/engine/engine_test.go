package engine_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/guilhermec94/security-code-scanner/pkg/engine"
	"github.com/guilhermec94/security-code-scanner/pkg/outputs"
	securityvalidations "github.com/guilhermec94/security-code-scanner/pkg/security-validations"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func setupTest() engine.SCSEngine {
	outputChannel := make(chan securityvalidations.OuputData, 100)
	log := logrus.New()
	logFile := "log-engine.txt"
	file, err := os.OpenFile(logFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		fmt.Println("Failed to create logfile" + logFile)
		panic(err)
	}
	log.SetOutput(file)

	// checks
	checkConfigCSS := securityvalidations.Config{
		NumberWorkers: 2,
		FileChannel:   make(chan string, 100),
		OutputChannel: outputChannel,
	}

	cSS := securityvalidations.NewCrossSiteScriptingCheck(checkConfigCSS, log)

	checkConfigSD := securityvalidations.Config{
		NumberWorkers: 2,
		FileChannel:   make(chan string, 100),
		OutputChannel: outputChannel,
	}

	sD := securityvalidations.NewSensitiveDataCheck(checkConfigSD, log)

	checkConfigSQLI := securityvalidations.Config{
		NumberWorkers: 2,
		FileChannel:   make(chan string, 100),
		OutputChannel: outputChannel,
	}

	sqlI := securityvalidations.NewSqlInjectionCheck(checkConfigSQLI, log)

	//security validations list
	securityValidationsList := make([]engine.SecurityValidation, 0)

	securityValidationsList = append(securityValidationsList, cSS)
	securityValidationsList = append(securityValidationsList, sD)
	securityValidationsList = append(securityValidationsList, sqlI)

	// set output format
	var outputFormat engine.AnalylsisOuputFormat
	switch strings.ToLower("text") {
	case "text":
		outputFormat = outputs.NewPlainTextOutput(".", outputChannel, log)
	case "json":
		outputFormat = outputs.NewJSONOutput(".", outputChannel, log)
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

func TestRunSecurityChecks(t *testing.T) {
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
