package smokescreen

type EgressAcl interface {
	Decide(fromService string, toHost string) (EgressAclDecision, bool, error)
	Project(fromService string) (string, error)
}
