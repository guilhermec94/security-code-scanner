package securityvalidations

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/guilhermec94/security-code-scanner/pkg/utils"
)

type CrossSiteScriptingCheck struct {
	Config
}

func NewCrossSiteScriptingCheck(config Config) CrossSiteScriptingCheck {
	return CrossSiteScriptingCheck{
		Config: config,
	}
}

func (c CrossSiteScriptingCheck) SubmitFile(path string) {
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
	if extension == ".html" || extension == ".js" {
		file, scanner := utils.OpenFile(path)
		defer utils.CloseFile(file)

		pattern := ".*(Alert\\(\\))+.*"
		reg, _ := regexp.Compile(pattern)

		utils.ScanFile(scanner, func(data []byte, lineNumber int) {
			matched := reg.Match(data)
			if matched {
				c.OutputChannel <- fmt.Sprintf("[Cross Site Scripting] in file \"%s\" on line %d", fileName, lineNumber)
			}
		})
	}
}
