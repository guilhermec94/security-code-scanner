package securityvalidations

import "github.com/guilhermec94/security-code-scanner/pkg/engine"

type SensitiveDataCheck struct {
	Config
}

func NewSensitiveDataCheck(config Config) engine.SecurityCodeCheck {
	return SensitiveDataCheck{
		Config: config,
	}
}

func (s SensitiveDataCheck) Check() error {
	return nil
}
