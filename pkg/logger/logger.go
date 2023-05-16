package logger

import (
	"fmt"
	"os"
	"sync"

	"github.com/sirupsen/logrus"
)

var lock = &sync.Mutex{}
var log *logrus.Logger
var file *os.File

func GetInstance() *logrus.Logger {

	if log == nil {
		lock.Lock()
		defer lock.Unlock()

		if log == nil {
			log = logrus.New()
			logFile := "log.txt"
			file, err := os.OpenFile(logFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
			if err != nil {
				fmt.Println("Failed to create logfile" + logFile)
				panic(err)
			}
			log.SetOutput(file)
		}
	}

	return log
}

func CloseLog() {
	file.Close()
}
