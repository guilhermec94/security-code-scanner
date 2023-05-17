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

func setupCrossSiteScriptingCheckTest() (securityvalidations.CrossSiteScriptingValidation, chan securityvalidations.OuputData) {
	fileChan := make(chan string, 100)
	outputChannel := make(chan securityvalidations.OuputData, 100)
	config := securityvalidations.Config{
		NumberWorkers: 1,
		FileChannel:   fileChan,
		OutputChannel: outputChannel,
	}

	log := logger.NewFileLogger("log-css.txt")

	check := securityvalidations.NewCrossSiteScriptingValidation(config, log)

	return check, outputChannel
}

func cleanUpCrossSiteScriptingCheckTest() {
	e := os.Remove("log-css.txt")
	if e != nil {
		logrus.Fatal(e)
	}
}

func TestCrossSiteScriptingValidation_Check(t *testing.T) {
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
