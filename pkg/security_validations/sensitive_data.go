package securityvalidations

import (
	"fmt"
	"path/filepath"
	"sync"

	"github.com/guilhermec94/security-code-scanner/pkg/logger"
	"github.com/guilhermec94/security-code-scanner/pkg/utils"
	"github.com/sirupsen/logrus"
)

type SensitiveDataValidation struct {
	Config
	logger logger.CustomFileLogger
}

func NewSensitiveDataValidation(config Config, logger logger.CustomFileLogger) SensitiveDataValidation {
	return SensitiveDataValidation{
		Config: config,
		logger: logger,
	}
}

func (c SensitiveDataValidation) SubmitFile(path string) {
	c.Config.FileChannel <- path
}

func (c SensitiveDataValidation) CloseChannel() {
	close(c.FileChannel)
}

func (s SensitiveDataValidation) Check() {
	var wg sync.WaitGroup

	for i := 0; i < s.NumberWorkers; i++ {
		wg.Add(1)
		s.process(&wg)
	}

	wg.Wait()
}

func (s SensitiveDataValidation) process(wg *sync.WaitGroup) {
	defer wg.Done()

	for path := range s.FileChannel {
		fileName := filepath.Base(path)
		s.analyseFile(path, fileName)
	}
}

func (s SensitiveDataValidation) analyseFile(path, fileName string) {
	file, scanner, err := utils.OpenFile(path)
	defer func() {
		err := utils.CloseFile(file)
		if err != nil {
			s.logger.Log(logrus.ErrorLevel, "SensitiveDataValidation", fmt.Sprintf("can't close file %s %v", fileName, err))
			return
		}
	}()

	if err != nil {
		s.logger.Log(logrus.ErrorLevel, "SensitiveDataValidation", fmt.Sprintf("can't open file %s %v", fileName, err))
		return
	}

	err = utils.ScanFile(scanner, func(data []byte, lineNumber int) {
		matched := utils.ContainsSubstrings(string(data), "Checkmarx", "Hellman & Friedman", "$1.15b")
		if matched {
			s.OutputChannel <- OuputData{Vulnerability: SENSITIVE_DATA, File: fileName, Line: lineNumber}
		}
	})

	if err != nil {
		s.logger.Log(logrus.ErrorLevel, "SensitiveDataValidation", fmt.Sprintf("error scanning file %s %v", fileName, err))
	}

}
