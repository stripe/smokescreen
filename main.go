package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/sirupsen/logrus"
	"github.com/stripe/smokescreen/cmd"
	"github.com/stripe/smokescreen/pkg/smokescreen"
)

// This default implementation of RoleFromRequest uses the CommonName of the
// client's certificate.  If no certificate is provided, the AllowMissingRole
// configuration option will control whether the request is rejected, or the
// default ACL is applied.
func defaultHeaderRoleFromRequest(header string) func(req *http.Request) (string, error) {
	return func(req *http.Request) (string, error) {
		idHeader := req.Header[header]
		if len(idHeader) == 0 {
			return "", smokescreen.MissingRoleError(
				fmt.Sprintf("defaultRoleFromRequest the %s header be set", header))
		} else if len(idHeader) > 1 {
			return "", smokescreen.MissingRoleError(
				fmt.Sprintf("multiple headers provided for %s", header))
		}
		return idHeader[0], nil
	}
}

func defaultTLSRoleFromRequest(req *http.Request) (string, error) {
	if req.TLS == nil {
		return "", smokescreen.MissingRoleError("defaultRoleFromRequest requires TLS")
	}
	if len(req.TLS.PeerCertificates) == 0 {
		return "", smokescreen.MissingRoleError("client did not provide certificate")
	}
	return req.TLS.PeerCertificates[0].Subject.CommonName, nil
}

func main() {
	conf, err := cmd.NewConfiguration(nil, nil)
	if err != nil {
		logrus.Fatalf("Could not create configuration: %v", err)
	} else if conf != nil {
		if conf.TrustRoleFromHeader != "" {
			conf.RoleFromRequest = defaultHeaderRoleFromRequest(conf.TrustRoleFromHeader)
		} else {
			conf.RoleFromRequest = defaultTLSRoleFromRequest
		}

		conf.Log.Formatter = &logrus.JSONFormatter{}

		adapter := &smokescreen.Log2LogrusWriter{
			Entry: conf.Log.WithField("stdlog", "1"),
		}

		// Set the standard logger to use our logger's writer as output.
		log.SetOutput(adapter)
		log.SetFlags(0)
		smokescreen.StartWithConfig(conf, nil)
	}
	// Otherwise, --help or --version was passed and handled by NewConfiguration, so do nothing
}
