package securityvalidations

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/guilhermec94/security-code-scanner/pkg/utils"
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
		extension := filepath.Ext(path)
		s.analyseFile(path, fileName, extension)
	}

}

func (s SqlInjectionCheck) analyseFile(path, fileName, extension string) {
	file, scanner := utils.OpenFile(path)
	defer utils.CloseFile(file)

	pattern := ".*\"(SELECT).*(WHERE).*(%s).*\".*"
	reg, _ := regexp.Compile(pattern)

	utils.ScanFile(scanner, func(data []byte, lineNumber int) {
		matched := reg.Match(data)
		if matched {
			s.OutputChannel <- fmt.Sprintf("[SQL Injection] in file \"%s\" on line %d", fileName, lineNumber)
		}
	})
}
