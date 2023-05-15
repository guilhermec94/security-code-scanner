package securityvalidations

import (
	"fmt"
	"path/filepath"
	"sync"

	"github.com/guilhermec94/security-code-scanner/pkg/utils"
)

type SensitiveDataCheck struct {
	Config
}

func NewSensitiveDataCheck(config Config) SensitiveDataCheck {
	return SensitiveDataCheck{
		Config: config,
	}
}

func (c SensitiveDataCheck) SubmitFile(path string) {
	c.Config.FileChannel <- path
}

func (c SensitiveDataCheck) CloseChannel() {
	close(c.FileChannel)
}

func (s SensitiveDataCheck) Check() {
	// check file extension to apply current parser
	var wg sync.WaitGroup

	for i := 0; i < s.NumberWorkers; i++ {
		wg.Add(1)
		s.process(&wg)
	}

	wg.Wait()
}

func (s SensitiveDataCheck) process(wg *sync.WaitGroup) {
	defer wg.Done()

	for path := range s.FileChannel {
		fileName := filepath.Base(path)
		extension := filepath.Ext(path)
		s.analyseFile(path, fileName, extension)
	}

}

func (s SensitiveDataCheck) analyseFile(path, fileName, extension string) {
	file, scanner := utils.OpenFile(path)
	defer utils.CloseFile(file)

	utils.ScanFile(scanner, func(data []byte, lineNumber int) {
		matched := utils.ContainsSubstrings(string(data), "Checkmarx", "Hellman & Friedman", "$1.15b")
		if matched {
			s.OutputChannel <- fmt.Sprintf("[Sensitive Data] in file \"%s\" on line %d", fileName, lineNumber)
		}
	})

}
