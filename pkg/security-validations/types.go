package securityvalidations

type Config struct {
	NumberWorkers int
	FileChannel   chan string
	OutputChannel chan<- string
}
