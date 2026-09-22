package smokescreen

import (
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
	"github.com/stripe/smokescreen/pkg/smokescreen/conntrack"
	"github.com/stripe/smokescreen/pkg/smokescreen/metrics"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFilePreservesDependencies(t *testing.T) {
	logger, records := logrustest.NewNullLogger()
	cfg := NewConfig()
	cfg.Log = logger
	resolver := &deadlineResolver{t: t}
	cfg.Resolver = resolver
	metricClient := metrics.NewNoOpMetricsClient()
	cfg.MetricsClient = metricClient
	tracker := conntrack.NewTracker(0, metricClient, cfg.Log, cfg.ShuttingDown, nil)
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
