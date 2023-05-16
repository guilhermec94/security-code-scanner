package securityvalidations

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/guilhermec94/security-code-scanner/pkg/utils"
	"github.com/sirupsen/logrus"
)

type CrossSiteScriptingCheck struct {
	Config
	logger *logrus.Logger
}

func NewCrossSiteScriptingCheck(config Config, logger *logrus.Logger) CrossSiteScriptingCheck {
	return CrossSiteScriptingCheck{
		Config: config,
		logger: logger,
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
		file, scanner, err := utils.OpenFile(path)
		defer func() {
			err := utils.CloseFile(file)
			if err != nil {
				c.logger.Errorf("can't close file %s %v", fileName, err)
				return
			}
		}()

		if err != nil {
			c.logger.Errorf("can't open file  %s %v", fileName, err)
			return
		}

		pattern := ".*(Alert\\(\\))+.*"
		reg, err := regexp.Compile(pattern)
		if err != nil {
			c.logger.Error(fmt.Sprintf("could not compile regex pattern: %s\n", err))
		} else {
			err = utils.ScanFile(scanner, func(data []byte, lineNumber int) {
				matched := reg.Match(data)
				if matched {
					c.OutputChannel <- OuputData{Vulnerability: CROSS_SITE_SCRIPTING, File: fileName, Line: lineNumber}
				}
			})

			if err != nil {
				c.logger.Errorf("error scanning file %s %v", fileName, err)
			}
		}
	}
}
