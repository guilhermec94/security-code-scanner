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

func (s SqlInjectionCheck) Check() error {
	return nil
}
