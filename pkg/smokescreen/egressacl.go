package smokescreen

import "fmt"

type EgressAcl interface {
	Decide(fromService string, toHost string) (EgressAclDecision, error)
	Project(fromService string) (string, error)
}

type UnknownRoleError struct {
	Role string
}

func (u UnknownRoleError) Error() string {
	return fmt.Sprintf("unknown role role=%s", u.Role)
}
