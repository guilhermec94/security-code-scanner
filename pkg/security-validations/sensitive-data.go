package securityvalidations

import (
	"bufio"
	"fmt"
	"log"
	"os"
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

func (c SensitiveDataCheck) SendFile(path string) {
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
	lineNumber := 1

	file, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	for scanner.Scan() {
		matched := utils.ContainsSubstrings(scanner.Text(), "Checkmarx", "Hellman & Friedman", "$1.15b")
		if matched {
			s.OutputChannel <- fmt.Sprintf("[Sensitive Data] in file \"%s\" on line %d", fileName, lineNumber)
		}
		lineNumber++
	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("something bad happened in the line %v: %v", lineNumber, err)
	}
}
