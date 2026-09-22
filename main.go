package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/stripe/smokescreen/cmd"
	"github.com/stripe/smokescreen/internal/logging"
	"github.com/stripe/smokescreen/pkg/smokescreen"
)

// This default implementation of RoleFromRequest uses the CommonName of the
// client's certificate.  If no certificate is provided, the AllowMissingRole
// configuration option will control whether the request is rejected, or the
// default ACL is applied.
func defaultRoleFromRequest(req *http.Request) (string, error) {
	if req.TLS == nil {
		return "", smokescreen.MissingRoleError("defaultRoleFromRequest requires TLS")
	}
	if len(req.TLS.PeerCertificates) == 0 {
		return "", smokescreen.MissingRoleError("client did not provide certificate")
	}
	return req.TLS.PeerCertificates[0].Subject.CommonName, nil
}

func main() {
	logger := logging.OrDefault(nil)
	conf, err := cmd.NewConfiguration(nil, logger)
	if err != nil {
		logger.Error(logging.Sanitize(fmt.Sprintf("Could not create configuration: %v", err)))
		os.Exit(1)
	} else if conf != nil {
		conf.RoleFromRequest = defaultRoleFromRequest
		smokescreen.StartWithConfig(conf, nil)
	}
}
