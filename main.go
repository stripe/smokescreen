package main

import (
	"net/http"

	log "github.com/sirupsen/logrus"
	"github.com/stripe/smokescreen/cmd"
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
	conf, err := cmd.NewConfiguration(nil, nil)
	if err != nil {
		log.Fatalf("Could not create configuration: %v", err)
	} else if conf != nil {
		conf.RoleFromRequest = defaultRoleFromRequest

		adapter := &smokescreen.Log2LogrusWriter{
			Entry: conf.Log.WithField("stdlog", "1"),
		}
		// Set the standard logger to use our logger's writter as output.
		log.SetOutput(adapter)
		smokescreen.StartWithConfig(conf, nil)
	} else {
		// --help or --version was passed and handled by NewConfiguration, so do nothing
	}
}
