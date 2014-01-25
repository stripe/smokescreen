// Package einhorn allows you to communicate with the einhorn master from a Go
// worker.
package einhorn

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
)

// CountListeners returns the number of listener fd's passed by the master.
func CountListeners() int {
	count, err := strconv.Atoi(os.Getenv("EINHORN_FD_COUNT"))
	if err != nil {
		return 0
	}
	return count
}

// GetListener returns the passed listener with the specified index.
func GetListener(index int) (net.Listener, error) {
	if CountListeners() < (index + 1) {
		return nil, errors.New("einhorn: too few EINHORN_FDs passed")
	}

	name := fmt.Sprintf("EINHORN_FD_%d", index)

	fileno, err := strconv.Atoi(os.Getenv(name))
	if err != nil {
		return nil, err
	}

	file := os.NewFile(uintptr(fileno), name)
	listener, err := net.FileListener(file)
	if err != nil {
		return nil, err
	}

	return listener, nil
}

// Ack sends an ack to the einhorn master.
func Ack() error {
	return sendToMaster(workerMessage{Command: "worker:ack", Pid: os.Getpid()})
}

type workerMessage struct {
	Command string `json:"comand"`
	Pid     int
}

func sendToMaster(msg workerMessage) error {
	controlConn, err := net.Dial("unix", os.Getenv("EINHORN_SOCK_PATH"))
	if err != nil {
		return err
	}
	defer controlConn.Close()

	e := json.NewEncoder(controlConn)
	if err := e.Encode(msg); err != nil {
		return err
	}

	if _, err := controlConn.Write([]byte("\n")); err != nil {
		return err
	}

	return nil
}
