package outputs

import (
	"encoding/json"
	"fmt"
	"os"

	securityvalidations "github.com/guilhermec94/security-code-scanner/pkg/security-validations"
	"github.com/sirupsen/logrus"
)

type JSONOutput struct {
	OutputPath    string
	OutputChannel <-chan securityvalidations.OuputData
}

func NewJSONOutput(outputPath string, outputChannel <-chan securityvalidations.OuputData) JSONOutput {
	return JSONOutput{
		OutputPath:    outputPath,
		OutputChannel: outputChannel,
	}
}

func (j JSONOutput) ProcessResults(done chan bool) {
	f, err := os.Create(j.OutputPath + "/output.json")
	if err != nil {
		logrus.Info(fmt.Sprintf("could not create file: %s\n", err))
		f.Close()
		done <- true
		return
	}

	j.write(f, "{\"results\":[", done)
	firstWrite := true
	for res := range j.OutputChannel {
		jsonData, err := json.MarshalIndent(res, "", "    ")
		if err != nil {
			logrus.Info(fmt.Sprintf("could not marshal json: %s\n", err))
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
		logrus.Info(fmt.Sprintf("could not close file: %s\n", err))
		done <- true
		return
	}
	done <- true
}

func (j JSONOutput) write(file *os.File, data string, done chan bool) {
	_, err := fmt.Fprintln(file, data)
	if err != nil {
		logrus.Info(fmt.Sprintf("could not write to file: %s\n", err))
		done <- true
	}
}
