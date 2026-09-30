package smokescreen

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSelfConnectionsUseListenerPort(t *testing.T) {
	for _, source := range []string{"custom", "einhorn"} {
		t.Run(source, func(t *testing.T) {
			listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
			require.NoError(t, err)
			t.Cleanup(func() { listener.Close() })
			listeningPort := listener.Addr().(*net.TCPAddr).Port
			require.NotEqual(t, int(DefaultPort), listeningPort)

			config := NewConfig()
			config.AllowSelfConnections = true
			config.LocalIPs = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
			require.NoError(t, config.SetAllowRanges([]string{"127.0.0.1/32", "::1/128"}))
			config.Listener = listener

			if source == "einhorn" {
				file, err := listener.File()
				require.NoError(t, err)
				t.Cleanup(func() { file.Close() })
				// GetListener takes ownership of the inherited descriptor via os.NewFile.
				fd, err := syscall.Dup(int(file.Fd()))
				require.NoError(t, err)
				t.Setenv("EINHORN_MASTER_PID", fmt.Sprint(os.Getppid()))
				t.Setenv("EINHORN_FD_COUNT", "1")
				t.Setenv("EINHORN_FD_0", fmt.Sprint(fd))

				// Accept the worker's startup ACK without a real Einhorn process.
				socketDir, err := os.MkdirTemp("", "einhorn-")
				require.NoError(t, err)
				t.Cleanup(func() { os.RemoveAll(socketDir) })
				socket, err := net.Listen("unix", filepath.Join(socketDir, "ack"))
				require.NoError(t, err)
				t.Cleanup(func() { socket.Close() })
				t.Setenv("EINHORN_SOCK_PATH", socket.Addr().String())
				config.Listener = nil
			}

			// Exercise listener selection in StartWithConfig without serving traffic.
			quit := make(chan interface{}, 1)
			quit <- true
			StartWithConfig(config, quit)
			require.NotNil(t, config.Listener)
			assert.Equal(t, listeningPort, config.Listener.Addr().(*net.TCPAddr).Port)

			tests := []struct {
				name string
				ip   string
				port int
				want ipType
			}{
				{"actual listener IPv4", "127.0.0.1", listeningPort, ipDenySelfConnection},
				{"actual listener IPv6", "::1", listeningPort, ipDenySelfConnection},
				{"configured port IPv4", "127.0.0.1", int(config.Port), ipAllowUserConfigured},
				{"configured port IPv6", "::1", int(config.Port), ipAllowUserConfigured},
			}
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					addr := &net.TCPAddr{IP: net.ParseIP(tt.ip), Port: tt.port}
					assert.Equal(t, tt.want, classifyAddr(config, addr))
				})
			}
		})
	}
}
