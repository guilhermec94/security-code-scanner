package securityvalidations

import "github.com/guilhermec94/security-code-scanner/pkg/engine"

type SqlInjectionCheck struct {
	Config
}

func NewSqlInjectionCheck(config Config) engine.SecurityCodeCheck {
	return SqlInjectionCheck{
		Config: config,
	}
}

func (c SqlInjectionCheck) SendFile(path string) {
	c.Config.FileChannel <- path
}

func (c SqlInjectionCheck) CloseChannel() {
	close(c.FileChannel)
}

func (s SqlInjectionCheck) Check() error {
	return nil
}
