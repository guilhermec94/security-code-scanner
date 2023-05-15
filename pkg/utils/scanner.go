package utils

import (
	"bufio"
	"log"
	"os"
)

func OpenFile(path string) (*os.File, *bufio.Scanner) {
	file, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	return file, scanner
}

func ScanFile(scanner *bufio.Scanner, f func(data []byte, lineNumber int)) {
	lineCounter := 1
	for scanner.Scan() {
		f(scanner.Bytes(), lineCounter)
		lineCounter++
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("something bad happened in the line %v: %v", lineCounter, err)
	}
}

func CloseFile(file *os.File) {
	file.Close()
}
