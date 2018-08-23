package smoker

type EgressAcl interface {
	Decide(fromService string, toHost string) (EgressAclDecision, error)
	Project(fromService string) (string, error)
}
