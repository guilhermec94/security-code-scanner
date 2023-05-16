package securityvalidations_test

import (
	"os"
	"testing"

	"github.com/guilhermec94/security-code-scanner/pkg/logger"
	securityvalidations "github.com/guilhermec94/security-code-scanner/pkg/security-validations"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func setup() (securityvalidations.SensitiveDataCheck, chan securityvalidations.OuputData) {
	fileChan := make(chan string, 100)
	outputChannel := make(chan securityvalidations.OuputData, 100)
	config := securityvalidations.Config{
		NumberWorkers: 1,
		FileChannel:   fileChan,
		OutputChannel: outputChannel,
	}

	log := logger.GetInstance()

	check := securityvalidations.NewSensitiveDataCheck(config, log)

	return check, outputChannel
}

func TestSensitiveDataCheck_Check(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		// setup
		check, outputChannel := setup()

		// send test data to channel
		check.SubmitFile("/home/guilhermecarvalho/projects/personal/security-code-scanner/test_files/some_data.txt")
		check.CloseChannel()

		// call method
		check.Check()

		// assert
		fi, err := os.Stat("log.txt")
		if err != nil {
			logrus.Fatal(err)
		}

		size := fi.Size()
		assert.Equal(t, len(outputChannel), 1)
		assert.Equal(t, size, int64(0))
	})

	t.Run("error", func(t *testing.T) {
		// setup
		check, outputChannel := setup()

		// send test data to channel
		check.SubmitFile("/home/guilhermecarvalho/projects/personal/security-code-scanner/test_files_test")
		check.CloseChannel()

		// call method
		check.Check()

		// assert
		fi, err := os.Stat("log.txt")
		if err != nil {
			logrus.Fatal(err)
		}

		size := fi.Size()
		assert.Equal(t, len(outputChannel), 0)
		assert.Greater(t, size, int64(0))
	})
}
