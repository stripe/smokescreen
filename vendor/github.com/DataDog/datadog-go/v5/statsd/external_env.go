package statsd

import (
	"os"
	"sync/atomic"
	"unicode"
)

// ddExternalEnvVarName specifies the env var to inject the environment name.
const ddExternalEnvVarName = "DD_EXTERNAL_ENV"

// externalEnvHolder stores the external env name atomically. The value is
// written at most once at client startup (initExternalEnv) and read on every
// metric write via getExternalEnv.
var externalEnvHolder atomic.Value

func init() {
	// Pre-seed with an empty string so Load never returns nil and the
	// type-assertion in the read path is unconditional. This is also what
	// guarantees the stored type stays string (atomic.Value requires the
	// concrete type of every Store call to match).
	externalEnvHolder.Store("")
}

// initExternalEnv initializes the external environment name.
func initExternalEnv() {
	value := os.Getenv(ddExternalEnvVarName)
	if value != "" {
		externalEnvHolder.Store(sanitizeExternalEnv(value))
	}
}

// sanitizeExternalEnv removes non-printable characters and pipe characters from the external environment name.
func sanitizeExternalEnv(externalEnv string) string {
	if externalEnv == "" {
		return ""
	}
	var output string
	for _, r := range externalEnv {
		if unicode.IsPrint(r) && r != '|' {
			output += string(r)
		}
	}

	return output
}

func getExternalEnv() string {
	return externalEnvHolder.Load().(string)
}

func setExternalEnvForTest(v string) {
	externalEnvHolder.Store(v)
}
