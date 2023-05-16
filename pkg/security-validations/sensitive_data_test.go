package securityvalidations_test

import (
	"testing"

	"github.com/guilhermec94/security-code-scanner/pkg/logger"
	securityvalidations "github.com/guilhermec94/security-code-scanner/pkg/security-validations"
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
		// TODO: validate log file and contents
		assert.Equal(t, len(outputChannel), 1)
	})
}
