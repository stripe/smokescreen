package smokescreen

// A `EgressAclDecision` represents the result of checking the ACL.
type EgressAclDecision int

const (
	EgressAclDecisionAllow EgressAclDecision = 1 + iota
	EgressAclDecisionAllowAndReport
	EgressAclDecisionDeny
)

func (s EgressAclDecision) String() string {
	return [...]string{"UNKNOWN", "EgressAclDecisionAllow", "EgressAclDecisionAllowAndReport", "EgressAclDecisionDeny"}[s]
}

// An `ConfigEnforcementPolicy' represents what the policy is for a service.
type ConfigEnforcementPolicy int

const (
	ConfigEnforcementPolicyOpen = 1 + iota
	ConfigEnforcementPolicyReport
	ConfigEnforcementPolicyEnforce
)

func (s ConfigEnforcementPolicy) String() string {
	return [...]string{"UNKNOWN", "ConfigEnforcementPolicyOpen", "ConfigEnforcementPolicyReport", "ConfigEnforcementPolicyEnforce"}[s]
}
