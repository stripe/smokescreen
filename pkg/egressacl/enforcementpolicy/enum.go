package enforcementpolicy

// An `ErforcementPolicy' represents what the policy is for a service.
type EnforcementPolicy int

const (
	OPEN = 1 + iota
	REPORT
	ENFORCE
)

func (s EnforcementPolicy) String() string {
	return [...]string{"UNKNOWN", "OPEN", "REPORT", "ENFORCE"}[s]
}
