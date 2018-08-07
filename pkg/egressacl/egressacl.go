package egressacl

import "github.com/stripe/smokescreen/pkg/egressacl/decision"

type EgressAcl interface {
	Decide(fromService string, toHost string) (decision.Decision, error)
}
