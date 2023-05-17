package logger

import (
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
)

type CustomFileLogger struct {
	log  *logrus.Logger
	file *os.File
}

func NewFileLogger(fileName string) CustomFileLogger {
	log := logrus.New()
	logFile := fileName
	file, err := os.OpenFile(logFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		fmt.Println("Failed to create logfile" + logFile)
		panic(err)
	}
	log.SetFormatter(&logrus.TextFormatter{})
	log.SetOutput(file)

	return CustomFileLogger{
		log:  log,
		file: file,
	}
}

func (c CustomFileLogger) Log(level logrus.Level, source, msg string) {
	c.log.WithFields(logrus.Fields{
		"source": source,
	}).Log(level, msg)
}

func (c CustomFileLogger) CloseLog() {
	c.file.Close()
}
