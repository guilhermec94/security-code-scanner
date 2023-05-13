package engine

type SecurityCodeCheck interface {
	Check() error
}

type SCSEngine struct {
	SecurityValidations []SecurityCodeCheck
}

func NewSCSEngine(securityValidationList []SecurityCodeCheck) SCSEngine {
	return SCSEngine{
		SecurityValidations: securityValidationList,
	}
}

func (s SCSEngine) RunSecurityChecks() error {
	return nil
}
