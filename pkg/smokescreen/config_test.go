//go:build !nounit
// +build !nounit

package smokescreen

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestConfigValidate(t *testing.T) {
	t.Run("Test invalid config", func(t *testing.T) {
		conf := NewConfig()
		conf.ConnectTimeout = 10 * time.Second
		conf.ExitTimeout = 10 * time.Second
		conf.AdditionalErrorMessageOnDeny = "Proxy denied"
		conf.RejectResponseHandlerWithCtx = func(smokescreenContext *SmokescreenContext, response *http.Response) {
			fmt.Println("RejectResponseHandlerWithCtx")
		}
		conf.RejectResponseHandler = func(response *http.Response) {
			fmt.Println("RejectResponseHandler")
		}
		err := conf.Validate()
		require.Error(t, err)
	})

	t.Run("Test valid config", func(t *testing.T) {
		conf := NewConfig()
		conf.ConnectTimeout = 10 * time.Second
		conf.ExitTimeout = 10 * time.Second
		conf.AdditionalErrorMessageOnDeny = "Proxy denied"

		conf.RejectResponseHandler = func(response *http.Response) {
			fmt.Println("RejectResponseHandler")
		}
		err := conf.Validate()
		require.NoError(t, err)
	})
}
