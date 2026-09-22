package cmd

import (
	"os"
	"path/filepath"
	"testing"

	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
)

func TestConfigurationUsesLoggerDuringLoad(t *testing.T) {
	logger, records := logrustest.NewNullLogger()
	dir := t.TempDir()
	aclPath := filepath.Join(dir, "acl.yaml")
	require.NoError(t, os.WriteFile(aclPath, []byte("version: v1\nservices: []\n"), 0600))
	configPath := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte("acl_file: "+aclPath+"\n"), 0600))
	cfg, err := NewConfiguration([]string{"smokescreen", "--config-file", configPath}, logger)
	require.NoError(t, err)
	require.Same(t, logger, cfg.Log)
	var aclWarning bool
	for _, entry := range records.AllEntries() {
		if entry.Message == "no default rule set. any services without a rule will be denied." {
			aclWarning = true
		}
	}
	require.True(t, aclWarning, "the ACL must use the caller's logger during construction")
}
