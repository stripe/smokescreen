package smokescreen

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/DataDog/datadog-go/statsd"
	log "github.com/sirupsen/logrus"
)

type Config struct {
	Ip                           string
	Port                         int
	CidrBlacklist                []net.IPNet
	CidrBlacklistExemptions      []net.IPNet
	ConnectTimeout               time.Duration
	ExitTimeout                  time.Duration
	MaintenanceFile              string
	StatsdClient                 *statsd.Client
	AllowProxyToLoopback         bool
	EgressAcl                    EgressAcl
	SupportProxyProtocol         bool
	TlsConfig                    *tls.Config
	CrlByAuthorityKeyId          map[string]*pkix.CertificateList
	RoleFromRequest              func(subject *http.Request) (string, error)
	clientCasBySubjectKeyId      map[string]*x509.Certificate
	AdditionalErrorMessageOnDeny string
	Log                          *log.Logger
	DisabledAclPolicyActions     []string

	hostExtractExpr *regexp.Regexp
}

type missingRoleError struct {
	error
}

func MissingRoleError(s string) error {
	return missingRoleError{errors.New(s)}
}

func IsMissingRoleError(err error) bool {
	_, ok := err.(missingRoleError)
	return ok
}


// RFC 5280,  4.2.1.1
type authKeyId struct {
	Id []byte `asn1:"optional,tag:0"`
}

func (config *Config) Init() error {
	var err error

	if config.CrlByAuthorityKeyId == nil {
		config.CrlByAuthorityKeyId = make(map[string]*pkix.CertificateList)
	}
	if config.clientCasBySubjectKeyId == nil {
		config.clientCasBySubjectKeyId = make(map[string]*x509.Certificate)
	}
	if config.Log == nil {
		config.Log = log.New()
	}

	config.hostExtractExpr, err = regexp.Compile("^([^:]*)(:\\d+)?$")
	if err != nil {
		return err
	}

	// Configure RoleFromRequest for default behavior. It is ultimately meant to be replaced by the user.
	if config.TlsConfig != nil && config.TlsConfig.ClientCAs != nil { // If client certs are set, pick the CN.
		config.RoleFromRequest = func(req *http.Request) (string, error) {
			fail := func(err error) (string, error) { return "", err }
			if len(req.TLS.PeerCertificates) == 0 {
				return fail(MissingRoleError("client did not provide certificate"))
			}
			return req.TLS.PeerCertificates[0].Subject.CommonName, nil
		}
	} else { // Use a custom header
		config.RoleFromRequest = func(req *http.Request) (string, error) {
			fail := func(err error) (string, error) { return "", err }
			idHeader := req.Header["X-Smokescreen-Role"]
			if len(idHeader) == 0 {
				return fail(MissingRoleError("client did not send 'X-Smokescreen-Role' header"))
			} else if len(idHeader) > 1 {
				return fail(MissingRoleError("client sent multiple 'X-Smokescreen-Role' headers"))
			}
			return idHeader[0], nil
		}
	}

	return nil
}

func (config *Config) SetupCrls(crlFiles []string) error {
	fail := func(err error) error { fmt.Print(err); return err }

	config.CrlByAuthorityKeyId = make(map[string]*pkix.CertificateList)
	config.clientCasBySubjectKeyId = make(map[string]*x509.Certificate)

	for _, crlFile := range crlFiles {
		crlBytes, err := ioutil.ReadFile(crlFile)
		if err != nil {
			return fail(err)
		}

		certList, err := x509.ParseCRL(crlBytes)
		if err != nil {
			log.Printf("Failed to parse CRL in '%s': %#v\n", crlFile, err)
		}

		// find the X509v3 Authority Key Identifier in the extensions (2.5.29.35)
		crlIssuerId := ""
		extensionOid := []int{2, 5, 29, 35}
		for _, v := range certList.TBSCertList.Extensions {
			if v.Id.Equal(extensionOid) { // Hurray, we found it
				// Boo, it's ASN.1.
				var crlAuthorityKey authKeyId
				_, err := asn1.Unmarshal(v.Value, &crlAuthorityKey)
				if err != nil {
					fmt.Printf("error: Failed to read AuthorityKey: %#v\n", err)
					continue
				}
				crlIssuerId = string(crlAuthorityKey.Id)
				break
			}
		}
		if crlIssuerId == "" {
			log.Print(fmt.Errorf("error: CRL from '%s' has no Authority Key Identifier: ignoring it\n", crlFile))
			continue
		}

		// Make sure we have a CA for this CRL or warn
		caCert, ok := config.clientCasBySubjectKeyId[crlIssuerId]

		if !ok {
			log.Printf("warn: CRL loaded for issuer '%s' but no such CA loaded: ignoring it\n", hex.EncodeToString([]byte(crlIssuerId)))
			fmt.Printf("%#v loaded certs\n", len(config.clientCasBySubjectKeyId))
			continue
		}

		// At this point, we have the CA certificate and the CRL. All that's left before evicting the CRL we currently trust is to verify the new CRL's signature
		err = caCert.CheckCRLSignature(certList)
		if err != nil {
			fmt.Printf("error: Could not trust CRL. Error during signature check: %#v\n", err)
			continue
		}

		// At this point, we have a new CRL which we trust. Let's evict the old one.
		config.CrlByAuthorityKeyId[crlIssuerId] = certList
		fmt.Printf("info: Loaded CRL for Authority ID '%s'\n", hex.EncodeToString([]byte(crlIssuerId)))
	}

	// Verify that all CAs loaded have a CRL
	for k, _ := range config.clientCasBySubjectKeyId {
		_, ok := config.CrlByAuthorityKeyId[k]
		if !ok {
			fmt.Printf("warn: no CRL loaded for Authority ID '%s'\n", hex.EncodeToString([]byte(k)))
		}
	}
	return nil
}

func (config *Config) SetupStatsd(addr, namespace string) error {
	if addr == "" {
		config.StatsdClient = nil
		return nil
	}

	track, err := statsd.New(addr)
	if err != nil {
		return err
	}
	config.StatsdClient = track

	config.StatsdClient.Namespace = namespace

	return nil
}

func (config *Config) SetupEgressAcl(aclFile string) error {
	if aclFile == "" {
		config.EgressAcl = nil
		return nil
	}

	log.Printf("Loading egress ACL from %s", aclFile)
	egressAcl, err := LoadYamlAclFromFilePath(config, aclFile)
	if err != nil {
		log.Print(err)
		return err
	}
	config.EgressAcl = egressAcl

	return nil
}

func (config *Config) SetupTls(tlsServerPemFile string, tlsClientCasFiles []string) error {
	fail := func(err error) error { return err }

	if tlsServerPemFile != "" {

		tlsConfig := tls.Config{}

		fileBytes, err := ioutil.ReadFile(tlsServerPemFile)
		if err != nil {
			return fail(err)
		}

		serverCert, err := ParsePemChain(fileBytes)
		if err != nil {
			return fail(err)
		}

		tlsConfig.Certificates = []tls.Certificate{
			serverCert,
		}

		if len(tlsClientCasFiles) != 0 {
			tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
			tlsConfig.ClientCAs = x509.NewCertPool()
			for _, clientCaFile := range tlsClientCasFiles {
				caBytes, err := ioutil.ReadFile(clientCaFile)
				if err != nil {
					return fail(err)
				}
				success := tlsConfig.ClientCAs.AppendCertsFromPEM(caBytes)
				if !success {
					return fail(fmt.Errorf("Problem decoding '%s'", clientCaFile))
				}

				config.populateClientCaMap(caBytes)
			}
		}

		tlsConfig.BuildNameToCertificate()
		config.TlsConfig = &tlsConfig
	} else {
		if len(tlsClientCasFiles) != 0 {
			return fail(fmt.Errorf("It is pointless to set client CAs without setting the server's cert/key."))
		}
		config.TlsConfig = nil
	}
	return nil
}

func ParsePemChain(pemBytes []byte) (tls.Certificate, error) {
	fail := func(err error) (tls.Certificate, error) { return tls.Certificate{}, err }

	var err error
	var cert tls.Certificate

	for {
		var certDerBlock *pem.Block
		certDerBlock, pemBytes = pem.Decode(pemBytes)
		if certDerBlock == nil {
			break
		}

		if strings.HasSuffix(certDerBlock.Type, "PRIVATE KEY") {
			if cert.PrivateKey != nil {
				return fail(fmt.Errorf("Found multiple '*PRIVATE KEY's block in the provided file."))
			}
			cert.PrivateKey, err = parsePrivateKey(certDerBlock.Bytes)
			if err != nil {
				return fail(err)
			}
		} else if certDerBlock.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, certDerBlock.Bytes)
		} else {
			log.Printf("warn: Unsupported PEM block '%s'. Resolution: ignoring", certDerBlock.Type)
		}
	}

	if len(cert.Certificate) == 0 {
		return fail(fmt.Errorf("Could not find any 'CERTIFICATE' in the provided file."))
	}

	if cert.PrivateKey == nil {
		return fail(fmt.Errorf("Could not find a '*PRIVATE KEY' in the provided file."))
	}
	// We don't need to parse the IpTypePublic key for TLS, but we so do anyway
	// to check that it looks sane and matches the IpTypePrivate key.
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fail(err)
	}

	switch pub := x509Cert.PublicKey.(type) {
	case *rsa.PublicKey:
		priv, ok := cert.PrivateKey.(*rsa.PrivateKey)
		if !ok {
			return fail(errors.New("tls: IpTypePrivate key type does not match IpTypePublic key type"))
		}
		if pub.N.Cmp(priv.N) != 0 {
			return fail(errors.New("tls: IpTypePrivate key does not match IpTypePublic key"))
		}
	case *ecdsa.PublicKey:
		priv, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
		if !ok {
			return fail(errors.New("tls: IpTypePrivate key type does not match IpTypePublic key type"))
		}
		if pub.X.Cmp(priv.X) != 0 || pub.Y.Cmp(priv.Y) != 0 {
			return fail(errors.New("tls: IpTypePrivate key does not match IpTypePublic key"))
		}
	default:
		return fail(errors.New("tls: unknown IpTypePublic key algorithm"))
	}

	return cert, nil
}

// Cargoculted from pkg/tls/tls.go
// Attempt to parse the given IpTypePrivate key DER block. OpenSSL 0.9.8 generates
// PKCS#1 IpTypePrivate keys by default, while OpenSSL 1.0.0 generates PKCS#8 keys.
// OpenSSL ecparam generates SEC1 EC IpTypePrivate keys for ECDSA. We try all three.
func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("tls: found unknown IpTypePrivate key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("tls: failed to parse IpTypePrivate key")
}

func (config *Config) populateClientCaMap(pemCerts []byte) (ok bool) {

	for len(pemCerts) > 0 {
		var block *pem.Block
		block, pemCerts = pem.Decode(pemCerts)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		fmt.Printf("info: Loaded CA with Authority ID '%s'\n", hex.EncodeToString(cert.SubjectKeyId))
		config.clientCasBySubjectKeyId[string(cert.SubjectKeyId)] = cert
		ok = true
	}
	return
}
