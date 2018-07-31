package egressacl

import "github.com/stripe/smokescreen/pkg/egressacl/decision"

type EgressWhitelist interface {
	Decide(fromService string, toHost string) (decision.Decision, error)
}
