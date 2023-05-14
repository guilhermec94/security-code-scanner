package securityvalidations

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/guilhermec94/security-code-scanner/pkg/engine"
)

type CrossSiteScriptingCheck struct {
	Config
}

func NewCrossSiteScriptingCheck(config Config) engine.SecurityCodeCheck {
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

func (c CrossSiteScriptingCheck) Check() error {
	// start N go routines
	// each will be fed a file to performa the check
	// when finished if the problems are detected then write to output channel
	// pick another file from the feed channel
	var wg sync.WaitGroup

	for i := 0; i < c.NumberWorkers; i++ {
		wg.Add(1)
		go func(i int) {
			c.process(&wg)
		}(i)
	}

	wg.Wait()

	return nil
}

func (c CrossSiteScriptingCheck) process(wg *sync.WaitGroup) {
	defer wg.Done()

	for path := range c.FileChannel {
		// analysis logic
		// validate only html and javascript files
		fileName := filepath.Base(path)
		extension := filepath.Ext(path)
		c.analyseFile(path, fileName, extension)
	}

}

func (c CrossSiteScriptingCheck) analyseFile(path, fileName, extension string) {
	// analysis logic
	// validate only html and javascript files
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
				// write to output channel
				fmt.Printf("[Cross Site Scripting] in file \"%s\" on line %d \n", fileName, lineNumber)
			}
			lineNumber++
		}
		if err := scanner.Err(); err != nil {
			log.Fatalf("something bad happened in the line %v: %v", lineNumber, err)
		}
	}
}
