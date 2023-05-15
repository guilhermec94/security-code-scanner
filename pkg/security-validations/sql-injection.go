package securityvalidations

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sync"
)

type SqlInjectionCheck struct {
	Config
}

func NewSqlInjectionCheck(config Config) SqlInjectionCheck {
	return SqlInjectionCheck{
		Config: config,
	}
}

func (s SqlInjectionCheck) SendFile(path string) {
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
	lineNumber := 1

	file, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	pattern := ".*\"(SELECT).*(WHERE).*(%s).*\".*"
	reg, _ := regexp.Compile(pattern)

	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	for scanner.Scan() {
		matched := reg.Match(scanner.Bytes())
		if matched {
			s.OutputChannel <- fmt.Sprintf("[SQL Injection] in file \"%s\" on line %d", fileName, lineNumber)
		}
		lineNumber++
	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("something bad happened in the line %v: %v", lineNumber, err)
	}
}
