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
	if len(req.TLS.PeerCertificates) == 0 {
		return "", smokescreen.MissingRoleError("client did not provide certificate")
	}
	return req.TLS.PeerCertificates[0].Subject.CommonName, nil
}

// This is an example of another way to obtain a role from a request, using an
// HTTP header.  Note that this is not reliable in the face of a malicious
// client with the ability to construct arbitrary HTTP requests.
/*
func headerRoleFromRequest(req *http.Request) (string, error) {
	idHeader := req.Header["X-Smokescreen-Role"]
	if len(idHeader) == 0 {
		return "", smokescreen.MissingRoleError("client did not send 'X-Smokescreen-Role' header")
	} else if len(idHeader) > 1 {
		return "", smokescreen.MissingRoleError("client sent multiple 'X-Smokescreen-Role' headers")
	}
	return idHeader[0], nil
}
*/


func main() {
	conf, err := cmd.NewConfiguration(nil, nil)
	if err != nil {
		log.Fatalf("Could not create configuration: %v", err)
	} else if conf != nil {
		conf.RoleFromRequest = defaultRoleFromRequest

		smokescreen.StartWithConfig(conf, nil)
	} else {
		// --help or --version was passed and handled by NewConfiguration, so do nothing
	}
}
