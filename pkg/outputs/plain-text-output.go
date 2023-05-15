package outputs

import (
	"fmt"
	"os"
)

type PlainTextOutput struct {
	OutputPath    string
	OutputChannel <-chan string
}

func NewPlainTextOutput(outputPath string, outputChannel <-chan string) PlainTextOutput {
	return PlainTextOutput{
		OutputPath:    outputPath,
		OutputChannel: outputChannel,
	}
}

func (p PlainTextOutput) ProcessResults() {
	// TODO: slash windows/linux ?
	f, err := os.Create(p.OutputPath + "/output.txt")
	if err != nil {
		fmt.Println(err)
		f.Close()
		return
	}
	for res := range p.OutputChannel {
		fmt.Fprintln(f, res)
		if err != nil {
			fmt.Println(err)
			return
		}
	}
	err = f.Close()
	if err != nil {
		fmt.Println(err)
		return
	}
}
