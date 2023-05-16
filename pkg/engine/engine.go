package engine

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"sync"

	"github.com/guilhermec94/security-code-scanner/pkg/logger"
	securityvalidations "github.com/guilhermec94/security-code-scanner/pkg/security-validations"
	"github.com/sirupsen/logrus"
)

type SecurityValidation interface {
	SubmitFile(path string)
	CloseChannel()
	Check()
}

type AnalylsisOuputFormat interface {
	ProcessResults(done chan bool)
}

type SCSEngine struct {
	SecurityValidations []SecurityValidation
	Output              AnalylsisOuputFormat
	OuputChannel        chan securityvalidations.OuputData
	logger              *logrus.Logger
}

func NewSCSEngine(securityValidationList []SecurityValidation, output AnalylsisOuputFormat, outputChannel chan securityvalidations.OuputData, logger *logrus.Logger) SCSEngine {
	return SCSEngine{
		SecurityValidations: securityValidationList,
		Output:              output,
		OuputChannel:        outputChannel,
		logger:              logger,
	}
}

func (s SCSEngine) RunSecurityChecks(sourcePath string) error {
	var wg sync.WaitGroup
	doneReadingResults := make(chan bool)

	defer logger.CloseLog()

	for _, c := range s.SecurityValidations {
		wg.Add(1)
		go s.startCheck(c, &wg)
	}

	go s.ouputResults(doneReadingResults)

	err := filepath.WalkDir(sourcePath, func(path string, file fs.DirEntry, err error) error {
		if err != nil {
			s.logger.Error(fmt.Sprintf("could not walk path %s : %s\n", path, err))
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
		s.logger.Error(fmt.Sprintf("error searching path %s : %s\n", sourcePath, err))
	}

	for _, c := range s.SecurityValidations {
		c.CloseChannel()
	}

	wg.Wait()
	close(s.OuputChannel)
	<-doneReadingResults

	return nil
}

func (s SCSEngine) startCheck(securityValidation SecurityValidation, wg *sync.WaitGroup) {
	securityValidation.Check()
	wg.Done()
}

func (s SCSEngine) ouputResults(done chan bool) {
	s.Output.ProcessResults(done)
}
