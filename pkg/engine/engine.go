package engine

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"sync"
)

type SecurityCodeCheck interface {
	SubmitFile(path string)
	CloseChannel()
	Check()
}

type AnalylsisOuputFormat interface {
	ProcessResults()
}

type SCSEngine struct {
	SecurityValidations []SecurityCodeCheck
	Output              AnalylsisOuputFormat
	OuputChannel        chan string
}

func NewSCSEngine(securityValidationList []SecurityCodeCheck, output AnalylsisOuputFormat, ouputChannel chan string) SCSEngine {
	return SCSEngine{
		SecurityValidations: securityValidationList,
		Output:              output,
		OuputChannel:        ouputChannel,
	}
}

func (s SCSEngine) RunSecurityChecks(sourcePath string, outputType string) error {
	var wg sync.WaitGroup
	for _, c := range s.SecurityValidations {
		wg.Add(1)
		go s.startCheck(c, &wg)
	}

	go s.OuputResults(&wg)

	err := filepath.WalkDir(sourcePath, func(path string, file fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !file.IsDir() {
			for _, c := range s.SecurityValidations {
				c.SubmitFile(path)
			}
		}
		return nil
	})
	fmt.Println(err)
	for _, c := range s.SecurityValidations {
		c.CloseChannel()
	}

	wg.Wait()
	close(s.OuputChannel)
	return nil
}

func (s SCSEngine) startCheck(securityValidation SecurityCodeCheck, wg *sync.WaitGroup) {
	securityValidation.Check()
	wg.Done()
}

func (s SCSEngine) OuputResults(wg *sync.WaitGroup) {
	s.Output.ProcessResults()
}
