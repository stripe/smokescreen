package smokescreen

import acl "github.com/stripe/smokescreen/pkg/smokescreen/acl/v1"

// EgressAcl encapsulates information about smokescreen egress proxy actions.
type EgressAcl interface {
	Decide(fromService string, toHost string) (decision acl.Decision, reason string, isDefaultRule bool, err error)
	Project(fromService string) (project string, err error)
}
