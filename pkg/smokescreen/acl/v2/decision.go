// Package acl is the v2 egress ACL: the policy types, the parser for the v2
// file format, and the decision engine that every ACL format uses. The v1
// package translates v1 files into these types.
package acl

import (
	"fmt"
	"net/http"
)

// DecideArgs holds the arguments for an ACL decision. Using a struct keeps the
// Decider interface stable as new fields are added (e.g. Req for request-aware
// authorization in custom Decider implementations). The built-in engine does not
// inspect Req or ConnectReq; they are provided solely for use by custom implementations.
type DecideArgs struct {
	Req *http.Request
	// ConnectReq is the edge CONNECT request from the client when Decide is
	// evaluating a MITM inner HTTP request.
	ConnectReq       *http.Request
	Service          string
	Host             string
	ConnectProxyHost string
}

// Decider decides whether a request may reach its destination.
type Decider interface {
	Decide(args DecideArgs) (Decision, error)
}

// Decision is the result of an ACL check.
type Decision struct {
	Reason     string
	Default    bool
	Result     DecisionResult
	Project    string
	MitmConfig *MitmConfig
}

// MitmConfig configures how a MITM request is handled.
type MitmConfig struct {
	AddHeaders                  map[string]string `yaml:"add_headers"`
	DetailedHttpLogs            bool              `yaml:"detailed_http_logs"`
	DetailedHttpLogsFullHeaders []string          `yaml:"detailed_http_logs_full_headers"`
}

// DecisionResult represents the result of checking the ACL.
type DecisionResult int

// Possible decision results.
const (
	Allow DecisionResult = iota
	AllowAndReport
	Deny
)

func (d DecisionResult) String() string {
	return [...]string{"Allow", "AllowAndReport", "Deny"}[d]
}

// Mode is what happens to a request from a role when no rule matches it.
type Mode int

// Possible modes. The values match the v1 EnforcementPolicy values.
const (
	ModeUnknown Mode = iota
	ModeOpen
	ModeReport
	ModeEnforce
)

// Modes maps the names used in ACL files to modes.
var Modes = map[string]Mode{
	"open":    ModeOpen,
	"report":  ModeReport,
	"enforce": ModeEnforce,
}

func (m Mode) String() string {
	return [...]string{"Unknown", "Open", "Report", "Enforce"}[m]
}

// ModeFromString returns the mode for a name used in ACL files.
func ModeFromString(s string) (Mode, error) {
	if m, ok := Modes[s]; ok {
		return m, nil
	}
	return ModeUnknown, fmt.Errorf("unknown action %v", s)
}
