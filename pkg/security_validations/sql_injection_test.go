package securityvalidations_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/guilhermec94/security-code-scanner/pkg/logger"
	securityvalidations "github.com/guilhermec94/security-code-scanner/pkg/security_validations"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func setupSqlInjectionCheckTest() (securityvalidations.SqlInjectionValidation, chan securityvalidations.OuputData) {
	fileChan := make(chan string, 100)
	outputChannel := make(chan securityvalidations.OuputData, 100)
	config := securityvalidations.Config{
		NumberWorkers: 1,
		FileChannel:   fileChan,
		OutputChannel: outputChannel,
	}

	log := logger.NewFileLogger("log-si.txt")
	check := securityvalidations.NewSqlInjectionValidation(config, log)

	return check, outputChannel
}

func cleanUpSqlInjectionCheckTest() {
	e := os.Remove("log-si.txt")
	if e != nil {
		logrus.Fatal(e)
	}
}

func TestSqlInjectionValidation_Check(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		// setup
		check, outputChannel := setupSqlInjectionCheckTest()

		// send test data to channel
		absPath, err := filepath.Abs("../test_files/java/ConfigContainer.java")
		if err != nil {
			logrus.Fatal(err)
		}
		check.SubmitFile(absPath)
		check.CloseChannel()

		// call method
		check.Check()

		// assert
		fi, err := os.Stat("log-si.txt")
		if err != nil {
			logrus.Fatal(err)
		}

		size := fi.Size()
		assert.Equal(t, 3, len(outputChannel))
		assert.Equal(t, int64(0), size)
		t.Cleanup(func() { cleanUpSqlInjectionCheckTest() })
	})

	t.Run("error", func(t *testing.T) {
		// setup
		check, outputChannel := setupSqlInjectionCheckTest()

		// send test data to channel
		absPath, err := filepath.Abs("../test_files_test/java/ConfigContainer.java")
		if err != nil {
			logrus.Fatal(err)
		}
		check.SubmitFile(absPath)
		check.CloseChannel()

		// call method
		check.Check()

		// assert
		fi, err := os.Stat("log-si.txt")
		if err != nil {
			logrus.Fatal(err)
		}

		size := fi.Size()
		assert.Equal(t, 0, len(outputChannel))
		assert.Greater(t, size, int64(0))
		t.Cleanup(func() { cleanUpSqlInjectionCheckTest() })
	})
}
