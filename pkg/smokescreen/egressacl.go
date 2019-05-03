package smokescreen

// EgressAcl encapsulates information about smokescreen egress proxy actions.
type EgressAcl interface {
	Decide(fromService string, toHost string) (decision EgressAclDecision, reason string, isDefaultRule bool, err error)
	Project(fromService string) (project string, err error)
}
