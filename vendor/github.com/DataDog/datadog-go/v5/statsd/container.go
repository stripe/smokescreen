package statsd

import (
	"sync"
	"sync/atomic"
)

var (
	containerID atomic.Value
	initOnce    sync.Once
)

func init() {
	// Pre-seed with an empty string so Load never returns nil and the
	// type-assertion in the read path is unconditional.
	containerID.Store("")
}

// getContainerID returns the container ID configured at the client creation.
// It can either be auto-discovered with origin detection or provided by the user.
// User-defined container ID is prioritized.
func getContainerID() string {
	return containerID.Load().(string)
}

func storeContainerID(id string) {
	containerID.Store(id)
}

func setContainerIDForTest(id string) {
	containerID.Store(id)
}
