package securityvalidations_test

import (
	"fmt"
	"os"
	"testing"

	securityvalidations "github.com/guilhermec94/security-code-scanner/pkg/security-validations"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func setupSqlInjectionCheckTest() (securityvalidations.SqlInjectionCheck, chan securityvalidations.OuputData) {
	fileChan := make(chan string, 100)
	outputChannel := make(chan securityvalidations.OuputData, 100)
	config := securityvalidations.Config{
		NumberWorkers: 1,
		FileChannel:   fileChan,
		OutputChannel: outputChannel,
	}

	log := logrus.New()
	logFile := "log-si.txt"
	file, err := os.OpenFile(logFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		fmt.Println("Failed to create logfile" + logFile)
		panic(err)
	}
	log.SetOutput(file)

	check := securityvalidations.NewSqlInjectionCheck(config, log)

	return check, outputChannel
}

func cleanUpSqlInjectionCheckTest() {
	e := os.Remove("log-si.txt")
	if e != nil {
		logrus.Fatal(e)
	}
}

func TestSqlInjectionCheck(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		// setup
		check, outputChannel := setupSqlInjectionCheckTest()

		// send test data to channel
		check.SubmitFile("/home/jimbob/projects/go/security-code-scanner/test_files/java/ConfigContainer.java")
		check.CloseChannel()

		// call method
		check.Check()

		// assert
		fi, err := os.Stat("log-si.txt")
		if err != nil {
			logrus.Fatal(err)
		}

		size := fi.Size()
		assert.Equal(t, 2, len(outputChannel))
		assert.Equal(t, int64(0), size)
		t.Cleanup(func() { cleanUpSqlInjectionCheckTest() })
	})

	t.Run("error", func(t *testing.T) {
		// setup
		check, outputChannel := setupSqlInjectionCheckTest()

		// send test data to channel
		check.SubmitFile("/home/jimbob/projects/go/security-code-scanner/test_files_test/ConfigContainer.java")
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
