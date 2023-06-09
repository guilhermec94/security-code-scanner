package securityvalidations

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/guilhermec94/security-code-scanner/pkg/logger"
	"github.com/guilhermec94/security-code-scanner/pkg/utils"
	"github.com/sirupsen/logrus"
)

type SqlInjectionValidation struct {
	Config
	logger logger.CustomFileLogger
}

func NewSqlInjectionValidation(config Config, logger logger.CustomFileLogger) SqlInjectionValidation {
	return SqlInjectionValidation{
		Config: config,
		logger: logger,
	}
}

func (s SqlInjectionValidation) SubmitFile(path string) {
	s.FileChannel <- path
}

func (s SqlInjectionValidation) CloseChannel() {
	close(s.FileChannel)
}

func (s SqlInjectionValidation) Check() {
	var wg sync.WaitGroup

	for i := 0; i < s.NumberWorkers; i++ {
		wg.Add(1)
		s.process(&wg)
	}

	wg.Wait()
}

func (s SqlInjectionValidation) process(wg *sync.WaitGroup) {
	defer wg.Done()

	for path := range s.FileChannel {
		fileName := filepath.Base(path)
		s.analyseFile(path, fileName)
	}
}

func (s SqlInjectionValidation) analyseFile(path, fileName string) {
	file, scanner, err := utils.OpenFile(path)
	defer func() {
		err := utils.CloseFile(file)
		if err != nil {
			s.logger.Log(logrus.ErrorLevel, "SqlInjectionValidation", fmt.Sprintf("can't close file %s %v", fileName, err))
			return
		}
	}()

	if err != nil {
		s.logger.Log(logrus.ErrorLevel, "SqlInjectionValidation", fmt.Sprintf("can't open file %s %v", fileName, err))
		return
	}

	pattern := ".*\"(SELECT).*(WHERE).*(%s).*\".*"
	reg, err := regexp.Compile(pattern)
	if err != nil {
		s.logger.Log(logrus.ErrorLevel, "SqlInjectionValidation", fmt.Sprintf("could not compile regex pattern: %s\n", err))
		return
	}

	err = utils.ScanFile(scanner, func(data []byte, lineNumber int) {
		matched := reg.Match(data)
		if matched {
			s.OutputChannel <- OuputData{Vulnerability: SQL_INJECTION, File: fileName, Line: lineNumber}
		}
	})

	if err != nil {
		s.logger.Log(logrus.ErrorLevel, "SqlInjectionValidation", fmt.Sprintf("error scanning file %s %v", fileName, err))
	}
}
