package engine

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"sync"
)

type SecurityCodeCheck interface {
	SendFile(path string)
	CloseChannel()
	Check() error
}

type SCSEngine struct {
	SecurityValidations []SecurityCodeCheck
}

func NewSCSEngine(securityValidationList []SecurityCodeCheck) SCSEngine {
	return SCSEngine{
		SecurityValidations: securityValidationList,
	}
}

func (s SCSEngine) RunSecurityChecks(sourcePath string, outputType string) error {
	var wg sync.WaitGroup
	// get path to scan
	// write paths to all security check channels

	// start a go routine per check
	for _, c := range s.SecurityValidations {
		wg.Add(1)
		go s.startCheck(c, &wg)
	}

	err := filepath.WalkDir(sourcePath, func(path string, file fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !file.IsDir() {
			for _, c := range s.SecurityValidations {
				c.SendFile(path)
			}
		}
		return nil
	})
	fmt.Println(err)
	for _, c := range s.SecurityValidations {
		c.CloseChannel()
	}

	// read results from the checks
	// write results at the same time the checks are peforming to a file or output format chosen
	wg.Wait()
	return nil
}

func (s SCSEngine) startCheck(securityValidation SecurityCodeCheck, wg *sync.WaitGroup) {
	err := securityValidation.Check()
	if err != nil {
		fmt.Print("error")
	}
	wg.Done()
}
