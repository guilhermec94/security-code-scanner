package outputs

import (
	"encoding/json"
	"fmt"
	"os"

	securityvalidations "github.com/guilhermec94/security-code-scanner/pkg/security-validations"
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
		fmt.Println(err)
		f.Close()
		done <- true
		return
	}

	j.write(f, "{\"results\":[", done)
	firstWrite := true
	for res := range j.OutputChannel {
		jsonData, err := json.MarshalIndent(res, "", "    ")
		if err != nil {
			fmt.Printf("could not marshal json: %s\n", err)
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
		fmt.Println(err)
		done <- true
		return
	}
	done <- true
}

func (j JSONOutput) write(file *os.File, data string, done chan bool) {
	_, err := fmt.Fprintln(file, data)
	if err != nil {
		done <- true
	}
}
