// Package einhorn allows you to communicate with the einhorn master from a Go
// worker.
package einhorn

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path"
	"strconv"

	"launchpad.net/goyaml"
)

var TmpDir = "/tmp"

type Client struct {
	socket net.Conn
	reader *bufio.Reader
	writer *bufio.Writer
}

type ClientRequest struct {
	RequestId int `yaml:"request_id,omitempty"`
	Command   string
	Args      []string `yaml:",omitempty"`
}

type ClientAckRequest struct {
	Command string
	Pid     int
}

type ClientResponse struct {
	RequestId int `yaml:"request_id"`
	Message   string
	Wait      bool
}

func NewClient(socket net.Conn) *Client {
	return &Client{
		socket: socket,
		reader: bufio.NewReader(socket),
		writer: bufio.NewWriter(socket),
	}
}

func NewClientForPath(path string) (*Client, error) {
	socket, err := net.Dial("unix", path)
	if err != nil {
		return nil, err
	}

	return NewClient(socket), nil
}

func NewClientForName(name string) (*Client, error) {
	return NewClientForPath(path.Join(TmpDir, fmt.Sprintf("einhorn-%s.sock", name)))
}

func (c *Client) SendRequest(req interface{}) error {
	line, err := goyaml.Marshal(req)
	if err != nil {
		return err
	}

	encoded := url.QueryEscape(string(line))

	if _, err := c.writer.WriteString(encoded); err != nil {
		return err
	}
	if err := c.writer.WriteByte('\n'); err != nil {
		return err
	}
	return c.writer.Flush()
}

func (c *Client) ReadResponse() (*ClientResponse, error) {
	encoded, err := c.reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line, err := url.QueryUnescape(encoded)
	if err != nil {
		return nil, err
	}

	var response ClientResponse
	if err := goyaml.Unmarshal([]byte(line), &response); err != nil {
		return nil, err
	}

	return &response, nil
}

func (c *Client) Close() {
	c.socket.Close()
}

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

	listener, err := net.FileListener(os.NewFile(uintptr(fileno), name))
	if err != nil {
		return nil, err
	}

	return listener, nil
}

// IsWorker returns whether the current process is an einhorn worker.
func IsWorker() bool {
	masterPid := os.Getenv("EINHORN_MASTER_PID")
	if masterPid == "" {
		return false
	}

	pid, err := strconv.Atoi(masterPid)
	if err != nil {
		return false
	}

	return pid == os.Getppid()
}

// Ack sends an ack to the einhorn master.
func Ack() error {
	client, err := NewClientForPath(os.Getenv("EINHORN_SOCK_PATH"))
	if err != nil {
		return err
	}

	defer client.Close()

	return client.SendRequest(&ClientAckRequest{
		Command: "worker:ack",
		Pid:     os.Getpid(),
	})
}
