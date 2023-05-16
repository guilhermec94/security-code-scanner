package securityvalidations

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/guilhermec94/security-code-scanner/pkg/utils"
	"github.com/sirupsen/logrus"
)

type SqlInjectionCheck struct {
	Config
}

func NewSqlInjectionCheck(config Config) SqlInjectionCheck {
	return SqlInjectionCheck{
		Config: config,
	}
}

func (s SqlInjectionCheck) SubmitFile(path string) {
	s.FileChannel <- path
}

func (s SqlInjectionCheck) CloseChannel() {
	close(s.FileChannel)
}

func (s SqlInjectionCheck) Check() {
	var wg sync.WaitGroup

	for i := 0; i < s.NumberWorkers; i++ {
		wg.Add(1)
		s.process(&wg)
	}

	wg.Wait()
}

func (s SqlInjectionCheck) process(wg *sync.WaitGroup) {
	defer wg.Done()

	for path := range s.FileChannel {
		fileName := filepath.Base(path)
		s.analyseFile(path, fileName)
	}

}

func (s SqlInjectionCheck) analyseFile(path, fileName string) {
	file, scanner := utils.OpenFile(path)
	defer utils.CloseFile(file)

	pattern := ".*\"(SELECT).*(WHERE).*(%s).*\".*"
	reg, err := regexp.Compile(pattern)
	if err != nil {
		logrus.Info(fmt.Sprintf("could not compile regex pattern: %s\n", err))
	} else {
		utils.ScanFile(scanner, func(data []byte, lineNumber int) {
			matched := reg.Match(data)
			if matched {
				s.OutputChannel <- OuputData{Vulnerability: SQL_INJECTION, File: fileName, Line: lineNumber}
			}
		})
	}
}
