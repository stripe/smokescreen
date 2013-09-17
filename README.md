go-einhorn
==========

go-einhorn allows you to communicate with the einhorn master from a Go worker.

- `einhorn.CountListeners() uint` - Get the number of listener fd's passed by the master
- `einhorn.GetListener(index uint) (net.Listener, error)` - Get the passed listener with the specified index

- `einhorn.Ack() error` - Ack to the einhorn master
