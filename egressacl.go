package smokescreen

type EgressAcl interface {
	Decide(fromService string, toHost string) (EgressAclDecision, error)
}
