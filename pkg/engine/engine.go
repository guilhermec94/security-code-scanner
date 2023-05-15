package engine

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"sync"

	securityvalidations "github.com/guilhermec94/security-code-scanner/pkg/security-validations"
	"github.com/sirupsen/logrus"
)

type SecurityCodeCheck interface {
	SubmitFile(path string)
	CloseChannel()
	Check()
}

type AnalylsisOuputFormat interface {
	ProcessResults(done chan bool)
}

type SCSEngine struct {
	SecurityValidations []SecurityCodeCheck
	Output              AnalylsisOuputFormat
	OuputChannel        chan securityvalidations.OuputData
}

func NewSCSEngine(securityValidationList []SecurityCodeCheck, output AnalylsisOuputFormat, ouputChannel chan securityvalidations.OuputData) SCSEngine {
	return SCSEngine{
		SecurityValidations: securityValidationList,
		Output:              output,
		OuputChannel:        ouputChannel,
	}
}

func (s SCSEngine) RunSecurityChecks(sourcePath string, outputType string) error {
	var wg sync.WaitGroup
	doneReadingResults := make(chan bool)

	for _, c := range s.SecurityValidations {
		wg.Add(1)
		go s.startCheck(c, &wg)
	}

	go s.OuputResults(&wg, doneReadingResults)

	err := filepath.WalkDir(sourcePath, func(path string, file fs.DirEntry, err error) error {
		if err != nil {
			logrus.Info(fmt.Sprintf("could not walk path %s : %s\n", path, err))
			return err
		}
		if !file.IsDir() {
			for _, c := range s.SecurityValidations {
				c.SubmitFile(path)
			}
		}
		return nil
	})

	if err != nil {
		logrus.Info(fmt.Sprintf("could not walk path %s : %s\n", sourcePath, err))
	}

	for _, c := range s.SecurityValidations {
		c.CloseChannel()
	}

	wg.Wait()
	close(s.OuputChannel)
	<-doneReadingResults

	return nil
}

func (s SCSEngine) startCheck(securityValidation SecurityCodeCheck, wg *sync.WaitGroup) {
	securityValidation.Check()
	wg.Done()
}

func (s SCSEngine) OuputResults(wg *sync.WaitGroup, done chan bool) {
	s.Output.ProcessResults(done)
}
