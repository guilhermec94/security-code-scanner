package securityvalidations

import "github.com/guilhermec94/security-code-scanner/pkg/engine"

type CrossSiteScriptingCheck struct {
	Config
}

func NewCrossSiteScriptingCheck(config Config) engine.SecurityCodeCheck {
	return CrossSiteScriptingCheck{
		Config: config,
	}
}

func (c CrossSiteScriptingCheck) Check() error {
	return nil
}
