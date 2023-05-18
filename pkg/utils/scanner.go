package utils

import (
	"bufio"
	"os"
)

func OpenFile(path string) (*os.File, *bufio.Scanner, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	scanner := bufio.NewScanner(file)
	buf := []byte{}
	scanner.Buffer(buf, 1024*1024)

	return file, scanner, nil
}

func ScanFile(scanner *bufio.Scanner, f func(data []byte, lineNumber int)) error {
	lineCounter := 1
	for scanner.Scan() {
		f(scanner.Bytes(), lineCounter)
		lineCounter++
	}

	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

func CloseFile(file *os.File) error {
	return file.Close()
}
