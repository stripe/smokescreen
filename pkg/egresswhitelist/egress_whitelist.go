package egresswhitelist

type Decision int

const (
	ALLOW Decision = 1 + iota
	ALLOWREPORT
	DENY
)

type EgressWhitelist interface {
	Decide(fromService string, toHost string) (Decision, error)
}


