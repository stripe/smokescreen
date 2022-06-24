package smokescreen

import (
	"regexp"
)

const versionSemantic = "0.0.3"

// This can be set at build time:
// go build -ldflags='-X github.com/stripe/smokescreen/pkg/smokescreen.VersionID=33955a3' .
var VersionID = "unknown"

func Version() string {
	return versionSemantic + "-" + VersionID
}

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
