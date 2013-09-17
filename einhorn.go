package einhorn

import (
  "encoding/json"
  "os"
  "net"
  "errors"
  "strconv"
)

func CountListeners() uint {
  count, err := strconv.ParseUint(os.Getenv("EINHORN_FD_COUNT"), 10, 64)
  if err != nil {
    return 0
  } else {
    return uint(count)
  }
}

func GetListener(index uint) (net.Listener, error) {
  if CountListeners() < (index+1) { return nil, errors.New("Too few EINHORN_FDs passed") }
  name := "EINHORN_FD_" + strconv.Itoa(int(index))

  listener_fileno, err := strconv.Atoi(os.Getenv(name))
  if err != nil { return nil, errors.New("Could not parse fd: " + err.Error()) }

  listener_file := os.NewFile(uintptr(listener_fileno), name)
  listener, err := net.FileListener(listener_file)
  if err != nil { return nil, errors.New("Could not create listener from fd: " + err.Error()) }

  return listener, nil
}

func Ack() error {
  return sendToMaster(workerMessage{Command: "worker:ack", Pid: os.Getpid()})
}

type workerMessage struct {
  Command string `json:"comand"`
  Pid int
}

func sendToMaster(msg workerMessage) error {
  einhorn_sock_path := os.Getenv("EINHORN_SOCK_PATH")
  einhorn_control_conn, err := net.Dial("unix", einhorn_sock_path)
  if err != nil { return errors.New("Could not connect to einhorn master: "+err.Error()) }

  serialized, err := json.Marshal(msg)
  if err != nil { return errors.New("Could not serialize message: "+err.Error()) }

  _, err = einhorn_control_conn.Write(serialized)
  if err != nil { return errors.New("Could not write to einhorn master: "+err.Error()) }

  _, err = einhorn_control_conn.Write([]byte("\n"))
  if err != nil { return errors.New("Could not write to einhorn master: "+err.Error()) }

  err = einhorn_control_conn.Close()
  if err != nil { return errors.New("Could not close connection to einhorn master: "+err.Error()) }

  return nil
}
