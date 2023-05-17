package outputs

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/guilhermec94/security-code-scanner/pkg/logger"
	securityvalidations "github.com/guilhermec94/security-code-scanner/pkg/security_validations"
	"github.com/sirupsen/logrus"
)

type JSONOutputFormat struct {
	OutputPath    string
	OutputChannel <-chan securityvalidations.OuputData
	logger        logger.CustomFileLogger
}

func NewJSONOutputFormat(outputPath string, outputChannel <-chan securityvalidations.OuputData, logger logger.CustomFileLogger) JSONOutputFormat {
	return JSONOutputFormat{
		OutputPath:    outputPath,
		OutputChannel: outputChannel,
		logger:        logger,
	}
}

func (j JSONOutputFormat) ProcessResults(done chan bool) {
	f, err := os.Create(j.OutputPath + "/output.json")
	if err != nil {
		j.logger.Log(logrus.ErrorLevel, "JSONOutputFormat", fmt.Sprintf("could not create file: %s\n", err))
		f.Close()
		done <- true
		return
	}

	j.write(f, "{\"results\":[", done)
	firstWrite := true
	for res := range j.OutputChannel {
		jsonData, err := json.MarshalIndent(res, "", "    ")
		if err != nil {
			j.logger.Log(logrus.ErrorLevel, "JSONOutputFormat", fmt.Sprintf("could not marshal json: %s\n", err))
			done <- true
			return
		}

		if firstWrite {
			j.write(f, string(jsonData), done)
			firstWrite = !firstWrite
		} else {
			j.write(f, ","+string(jsonData), done)
		}

	}

	j.write(f, "]}", done)

	err = f.Close()
	if err != nil {
		j.logger.Log(logrus.ErrorLevel, "JSONOutputFormat", fmt.Sprintf("could not close file: %s\n", err))
		done <- true
		return
	}
	done <- true
}

func (j JSONOutputFormat) write(file *os.File, data string, done chan bool) {
	_, err := fmt.Fprintln(file, data)
	if err != nil {
		j.logger.Log(logrus.ErrorLevel, "JSONOutputFormat", fmt.Sprintf("could not write to file: %s\n", err))
		done <- true
	}
}
