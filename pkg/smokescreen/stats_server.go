package smokescreen

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"

	"github.com/stripe/smokescreen/pkg/smokescreen/conntrack"
)

type StatsServer struct {
	config     *Config
	ln         net.Listener
	httpServer *http.Server
	mux        *http.ServeMux
}

func newServer(config *Config) (*StatsServer, error) {
	s := &StatsServer{
		config: config,
		mux:    http.NewServeMux(),
	}
	s.mux.HandleFunc("/", s.stats)

	socketPath := fmt.Sprintf("%s/track-%d.sock", config.StatsSocketDir, os.Getpid())
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("listen on stats socket %q: %w", socketPath, err)
	}
	if err := os.Chmod(socketPath, config.StatsSocketFileMode); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("set permissions on stats socket %q: %w", socketPath, err)
	}

	s.ln = ln
	s.httpServer = &http.Server{Handler: s.mux}
	return s, nil
}

// Serve serves stats until Shutdown is called or the listener fails.
func (s *StatsServer) Serve() {
	defer s.Shutdown()
	if err := s.httpServer.Serve(s.ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		s.config.Log.Errorf("stats server serving failed: %v", err)
	}
}

// Shutdown closes the stats server, listener, and any active stats requests.
func (s *StatsServer) Shutdown() {
	if err := s.httpServer.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		s.config.Log.Errorf("failed to close stats server: %v", err)
	}
	if err := s.ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		s.config.Log.Errorf("failed to close stats listener: %v", err)
	}
}

func (s *StatsServer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	s.mux.ServeHTTP(w, req)
}

func (s *StatsServer) stats(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("Content-Type", "application/json")
	rw.Write([]byte{
		byte('['),
		byte('\n'),
	})

	firstRun := true

	s.config.ConnTracker.Range(func(k, v interface{}) bool {
		if !firstRun {
			rw.Write([]byte{byte(','), byte('\n')})
		}
		firstRun = false
		instrumentedConn := k.(*conntrack.InstrumentedConn)
		repr, err := instrumentedConn.JsonStats()

		if err != nil {
			s.config.Log.Error(err)
		}

		rw.Write(repr)
		return true
	})

	rw.Write([]byte{
		byte(']'),
		byte('\n'),
	})
}

// StartStatsServer starts the Unix stats endpoint. It returns nil and logs an
// error if the socket cannot be bound or initialized.
func StartStatsServer(config *Config) *StatsServer {
	server, err := newServer(config)
	if err != nil {
		config.Log.Errorf("could not start the stats server: %v", err)
		return nil
	}
	go server.Serve()
	return server
}
