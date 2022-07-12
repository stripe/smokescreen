package smokescreen

import (
	"regexp"
)

const DefaultStatsdNamespace = "smokescreen."

// Using a globally-shared Regexp can impact performace due to lock contention,
// but calling Copy() for each connection is much worse, and it looks like
// handing out Regexps from a pool doesn't save us anything either, so we'll
// just live with it.
const hostExtractPattern = "^([^:]*)(:\\d+)?$"

var hostExtractRE *regexp.Regexp

func init() {
	hostExtractRE = regexp.MustCompile(hostExtractPattern)
}
