package smokescreen

const versionSemantic = "0.0.3"
const portMin, portMax = 0, 65535

// This can be set at build time:
// go build -ldflags='-X github.com/stripe/smokescreen/pkg/smokescreen.VersionID=33955a3' .
var VersionID = "unknown"

func Version() string {
	return versionSemantic + "-" + VersionID
}

const DefaultStatsdNamespace = "smokescreen."
