package smokescreen

type EgressAcl interface {
	Decide(fromService string, toHost string) (EgressAclDecision, string, bool, error)
	Project(fromService string) (string, error)
}
