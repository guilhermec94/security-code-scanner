package securityvalidations_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	securityvalidations "github.com/guilhermec94/security-code-scanner/pkg/security-validations"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func setupCrossSiteScriptingCheckTest() (securityvalidations.CrossSiteScriptingCheck, chan securityvalidations.OuputData) {
	fileChan := make(chan string, 100)
	outputChannel := make(chan securityvalidations.OuputData, 100)
	config := securityvalidations.Config{
		NumberWorkers: 1,
		FileChannel:   fileChan,
		OutputChannel: outputChannel,
	}

	log := logrus.New()
	logFile := "log-css.txt"
	file, err := os.OpenFile(logFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		fmt.Println("Failed to create logfile" + logFile)
		panic(err)
	}
	log.SetOutput(file)

	check := securityvalidations.NewCrossSiteScriptingCheck(config, log)

	return check, outputChannel
}

func cleanUpCrossSiteScriptingCheckTest() {
	e := os.Remove("log-css.txt")
	if e != nil {
		logrus.Fatal(e)
	}
}

func TestCrossSiteScriptingCheck(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		// setup
		check, outputChannel := setupCrossSiteScriptingCheckTest()

		// send test data to channel
		absPath, err := filepath.Abs("../test_files/html/test.html")
		if err != nil {
			logrus.Fatal(err)
		}
		check.SubmitFile(absPath)
		check.CloseChannel()

		// call method
		check.Check()

		// assert
		fi, err := os.Stat("log-css.txt")
		if err != nil {
			logrus.Fatal(err)
		}

		size := fi.Size()
		assert.Equal(t, 4, len(outputChannel))
		assert.Equal(t, int64(0), size)
		t.Cleanup(func() { cleanUpCrossSiteScriptingCheckTest() })
	})

	t.Run("error", func(t *testing.T) {
		// setup
		check, outputChannel := setupCrossSiteScriptingCheckTest()

		// send test data to channel
		absPath, err := filepath.Abs("../test_files_test/html/test.html")
		if err != nil {
			logrus.Fatal(err)
		}
		check.SubmitFile(absPath)
		check.CloseChannel()

		// call method
		check.Check()

		// assert
		fi, err := os.Stat("log-css.txt")
		if err != nil {
			logrus.Fatal(err)
		}

		size := fi.Size()
		assert.Equal(t, 0, len(outputChannel))
		assert.Greater(t, size, int64(0))
		t.Cleanup(func() { cleanUpCrossSiteScriptingCheckTest() })
	})

}
