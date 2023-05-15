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

type CrossSiteScriptingCheck struct {
	Config
}

func NewCrossSiteScriptingCheck(config Config) CrossSiteScriptingCheck {
	return CrossSiteScriptingCheck{
		Config: config,
	}
}

func (c CrossSiteScriptingCheck) SendFile(path string) {
	c.FileChannel <- path
}

func (c CrossSiteScriptingCheck) CloseChannel() {
	close(c.FileChannel)
}

func (c CrossSiteScriptingCheck) Check() {
	var wg sync.WaitGroup

	for i := 0; i < c.NumberWorkers; i++ {
		wg.Add(1)
		c.process(&wg)
	}

	wg.Wait()
}

func (c CrossSiteScriptingCheck) process(wg *sync.WaitGroup) {
	defer wg.Done()

	for path := range c.FileChannel {
		fileName := filepath.Base(path)
		extension := filepath.Ext(path)
		c.analyseFile(path, fileName, extension)
	}

}

func (c CrossSiteScriptingCheck) analyseFile(path, fileName, extension string) {
	lineNumber := 1

	if extension == ".html" || extension == ".js" {

		file, err := os.Open(path)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()

		pattern := ".*(Alert\\(\\))+.*"
		reg, _ := regexp.Compile(pattern)

		scanner := bufio.NewScanner(file)
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, 1024*1024)
		for scanner.Scan() {
			matched := reg.Match(scanner.Bytes())
			if matched {
				c.OutputChannel <- fmt.Sprintf("[Cross Site Scripting] in file \"%s\" on line %d", fileName, lineNumber)
			}
			lineNumber++
		}
		if err := scanner.Err(); err != nil {
			log.Fatalf("something bad happened in the line %v: %v", lineNumber, err)
		}
	}
}
