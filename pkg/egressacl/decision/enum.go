package decision

// A `Decision` represents the result of checking the ACL.
type Decision int

const (
	ALLOW Decision = 1 + iota
	ALLOW_REPORT
	DENY
)

func (s Decision) String() string {
	return [...]string{"UNKNOWN", "ALLOW", "ALLOW_REPORT", "DENY"}[s]
}
