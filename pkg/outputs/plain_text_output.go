package outputs

import (
	"fmt"
	"os"

	securityvalidations "github.com/guilhermec94/security-code-scanner/pkg/security-validations"
	"github.com/sirupsen/logrus"
)

type PlainTextOutput struct {
	OutputPath    string
	OutputChannel <-chan securityvalidations.OuputData
}

func NewPlainTextOutput(outputPath string, outputChannel <-chan securityvalidations.OuputData) PlainTextOutput {
	return PlainTextOutput{
		OutputPath:    outputPath,
		OutputChannel: outputChannel,
	}
}

func (p PlainTextOutput) ProcessResults(done chan bool) {
	// TODO: slash windows/linux ?
	f, err := os.Create(p.OutputPath + "/output.txt")
	if err != nil {
		logrus.Info(fmt.Sprintf("could not create file: %s\n", err))
		f.Close()
		done <- true
		return
	}
	for res := range p.OutputChannel {
		data := fmt.Sprintf("%s in file \"%s\" on line %d", res.Vulnerability, res.File, res.Line)
		p.write(f, data, done)
	}
	err = f.Close()
	if err != nil {
		logrus.Info(fmt.Sprintf("could not close file: %s\n", err))
		done <- true
		return
	}
	done <- true
}

func (p PlainTextOutput) write(file *os.File, data string, done chan bool) {
	_, err := fmt.Fprintln(file, data)
	if err != nil {
		logrus.Info(fmt.Sprintf("could not write to file: %s\n", err))
		done <- true
	}
}
