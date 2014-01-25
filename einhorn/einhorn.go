// Package einhorn allows you to communicate with the einhorn master from a Go
// worker.
package einhorn

import (
	"encoding/json"
	"errors"
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
		return nil, errors.New("Too few EINHORN_FDs passed")
	}
	name := "EINHORN_FD_" + strconv.Itoa(index)

	fileno, err := strconv.Atoi(os.Getenv(name))
	if err != nil {
		return nil, errors.New("Could not parse fd: " + err.Error())
	}

	file := os.NewFile(uintptr(fileno), name)
	listener, err := net.FileListener(file)
	if err != nil {
		return nil, errors.New("Could not create listener from fd: " + err.Error())
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
	sockPath := os.Getenv("EINHORN_SOCK_PATH")
	controlConn, err := net.Dial("unix", sockPath)
	if err != nil {
		return errors.New("Could not connect to einhorn master: " + err.Error())
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
