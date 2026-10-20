package acl

import (
	aclv2 "github.com/stripe/smokescreen/v2/pkg/smokescreen/acl/v2"
)

// DecisionResult represents the result of checking the ACL
type DecisionResult = aclv2.DecisionResult

// Possible decision results.
const (
	Allow          = aclv2.Allow
	AllowAndReport = aclv2.AllowAndReport
	Deny           = aclv2.Deny
)

// EnforcementPolicy represents what the policy is for a service
type EnforcementPolicy = aclv2.Mode

// Possible enforcement policies.
const (
	Unknown = aclv2.ModeUnknown
	Open    = aclv2.ModeOpen
	Report  = aclv2.ModeReport
	Enforce = aclv2.ModeEnforce
)

// EnforcementPolicies maps action names to enforcement policies.
var EnforcementPolicies = aclv2.Modes

// PolicyFromAction returns the enforcement policy for an action name.
func PolicyFromAction(action string) (EnforcementPolicy, error) {
	return aclv2.ModeFromString(action)
}
