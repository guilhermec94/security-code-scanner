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

type CrossSiteScriptingValidation struct {
	Config
	logger logger.CustomFileLogger
}

func NewCrossSiteScriptingValidation(config Config, logger logger.CustomFileLogger) CrossSiteScriptingValidation {
	return CrossSiteScriptingValidation{
		Config: config,
		logger: logger,
	}
}

func (c CrossSiteScriptingValidation) SubmitFile(path string) {
	c.FileChannel <- path
}

func (c CrossSiteScriptingValidation) CloseChannel() {
	close(c.FileChannel)
}

func (c CrossSiteScriptingValidation) Check() {
	var wg sync.WaitGroup

	for i := 0; i < c.NumberWorkers; i++ {
		wg.Add(1)
		c.process(&wg)
	}

	wg.Wait()
}

func (c CrossSiteScriptingValidation) process(wg *sync.WaitGroup) {
	defer wg.Done()

	for path := range c.FileChannel {
		fileName := filepath.Base(path)
		extension := filepath.Ext(path)
		c.analyseFile(path, fileName, extension)
	}

}

func (c CrossSiteScriptingValidation) analyseFile(path, fileName, extension string) {
	if extension == ".html" || extension == ".js" {
		file, scanner, err := utils.OpenFile(path)
		defer func() {
			err := utils.CloseFile(file)
			if err != nil {
				c.logger.Log(logrus.ErrorLevel, "CrossSiteScriptingValidation", fmt.Sprintf("can't close file %s %v", fileName, err))
				return
			}
		}()

		if err != nil {
			c.logger.Log(logrus.ErrorLevel, "CrossSiteScriptingValidation", fmt.Sprintf("can't open file %s %v", fileName, err))
			return
		}

		pattern := ".*(Alert\\(\\))+.*"
		reg, err := regexp.Compile(pattern)
		if err != nil {
			c.logger.Log(logrus.ErrorLevel, "CrossSiteScriptingValidation", fmt.Sprintf("could not compile regex pattern: %s\n", err))
		} else {
			err = utils.ScanFile(scanner, func(data []byte, lineNumber int) {
				matched := reg.Match(data)
				if matched {
					c.OutputChannel <- OuputData{Vulnerability: CROSS_SITE_SCRIPTING, File: fileName, Line: lineNumber}
				}
			})

			if err != nil {
				c.logger.Log(logrus.ErrorLevel, "CrossSiteScriptingValidation", fmt.Sprintf("error scanning file %s %v", fileName, err))
			}
		}
	}
}
