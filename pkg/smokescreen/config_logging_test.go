package smokescreen

import (
	"github.com/stretchr/testify/require"
	"github.com/stripe/smokescreen/internal/testlog"
	"github.com/stripe/smokescreen/pkg/smokescreen/conntrack"
	"github.com/stripe/smokescreen/pkg/smokescreen/metrics"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestStatsServerResolvesNilLogger(t *testing.T) {
	cfg := NewConfig()
	cfg.Log = nil
	server := newServer(cfg)
	require.NotNil(t, server.config.Log)
	require.IsType(t, &slog.JSONHandler{}, server.config.Log.Handler())
}

func TestLoadFilePreservesDependencies(t *testing.T) {
	logger, records := testlog.New()
	cfg := NewConfig()
	cfg.Log = logger
	resolver := &deadlineResolver{t: t}
	cfg.Resolver = resolver
	metricClient := metrics.NewNoOpMetricsClient()
	cfg.MetricsClient = metricClient
	tracker := conntrack.NewTracker(0, metricClient, cfg.ShuttingDown, nil)
	cfg.ConnTracker = tracker
	cfg.RoleFromRequest = func(*http.Request) (string, error) { return "caller", nil }
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte("acl_file: testdata/acl.yaml\n"), 0600))
	require.NoError(t, cfg.LoadFile(path))
	require.Same(t, logger, cfg.Log)
	require.Same(t, resolver, cfg.Resolver)
	require.Same(t, metricClient, cfg.MetricsClient)
	require.Same(t, tracker, cfg.ConnTracker)
	role, err := cfg.RoleFromRequest(nil)
	require.NoError(t, err)
	require.Equal(t, "caller", role)
	require.NotEmpty(t, records.AllEntries())
}
