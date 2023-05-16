package securityvalidations

type VulnerabilityType string

const (
	CROSS_SITE_SCRIPTING VulnerabilityType = "Cross Site Scripting"
	SENSITIVE_DATA       VulnerabilityType = "Sensitive Data"
	SQL_INJECTION        VulnerabilityType = "SQL Injection"
)

type Config struct {
	NumberWorkers int
	FileChannel   chan string
	OutputChannel chan<- OuputData
}

type OuputData struct {
	Vulnerability VulnerabilityType
	File          string
	Line          int
}
