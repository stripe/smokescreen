//go:build !nounit
// +build !nounit

package smokescreen

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A CRL file that does not parse should be reported as a configuration error,
// not dereferenced.
func TestSetupCrlsRejectsUnparseableFile(t *testing.T) {
	crlFile := filepath.Join(t.TempDir(), "bad.crl")
	require.NoError(t, os.WriteFile(crlFile, []byte("this is not a CRL"), 0600))

	conf := NewConfig()
	err := conf.SetupCrls([]string{crlFile})

	require.Error(t, err)
	assert.Contains(t, err.Error(), crlFile)
}

func TestSetupCrlsReportsAMissingFile(t *testing.T) {
	conf := NewConfig()

	err := conf.SetupCrls([]string{filepath.Join(t.TempDir(), "absent.crl")})

	assert.Error(t, err)
}
