package smokescreen

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyConnection(t *testing.T) {
	certificate := func(serial int64, authorityKeyID, subjectKeyID string, isCA bool) *x509.Certificate {
		return &x509.Certificate{
			SerialNumber:   big.NewInt(serial),
			AuthorityKeyId: []byte(authorityKeyID),
			SubjectKeyId:   []byte(subjectKeyID),
			IsCA:           isCA,
		}
	}

	leaf := certificate(1, "intermediate", "leaf", false)
	intermediate := certificate(2, "root", "intermediate", true)
	root := certificate(3, "root-issuer", "root", true)
	rootA := certificate(20, "root-issuer", "root-a", true)
	rootB := certificate(21, "root-issuer", "root-b", true)
	revokedIntermediate := certificate(22, "root-a", "intermediate-a", true)
	cleanIntermediate := certificate(23, "root-b", "intermediate-b", true)

	tests := []struct {
		name               string
		verifiedChains     [][]*x509.Certificate
		revokedCertSerials map[string]map[string]bool
		wantErr            bool
	}{
		{
			name:           "revoked ordinary leaf is rejected",
			verifiedChains: [][]*x509.Certificate{{leaf, intermediate, root}},
			revokedCertSerials: map[string]map[string]bool{
				"intermediate": {"1": true},
			},
			wantErr: true,
		},
		{
			name:           "revoked intermediate is rejected",
			verifiedChains: [][]*x509.Certificate{{leaf, intermediate, root}},
			revokedCertSerials: map[string]map[string]bool{
				"root": {"2": true},
			},
			wantErr: true,
		},
		{
			name:           "non-revoked intermediate is accepted",
			verifiedChains: [][]*x509.Certificate{{leaf, intermediate, root}},
			revokedCertSerials: map[string]map[string]bool{
				"root": {"99": true},
			},
		},
		{
			name: "revoked non-anchor certificate with CA true is rejected",
			verifiedChains: [][]*x509.Certificate{{
				certificate(4, "issuer", "ca", true),
				root,
			}},
			revokedCertSerials: map[string]map[string]bool{
				"root": {"4": true},
			},
			wantErr: true,
		},
		{
			name:           "final root trust anchor is not checked",
			verifiedChains: [][]*x509.Certificate{{leaf, intermediate, root}},
			revokedCertSerials: map[string]map[string]bool{
				"root-issuer": {"3": true},
			},
		},
		{
			name:           "intermediate used as final trust anchor is not checked",
			verifiedChains: [][]*x509.Certificate{{leaf, intermediate}},
			revokedCertSerials: map[string]map[string]bool{
				"root": {"2": true},
			},
		},
		{
			name:           "empty verified chains is accepted",
			verifiedChains: nil,
			revokedCertSerials: map[string]map[string]bool{
				"intermediate": {"1": true},
			},
		},
		{
			name:           "empty inner chain is not a clean path",
			verifiedChains: [][]*x509.Certificate{{}},
			revokedCertSerials: map[string]map[string]bool{
				"intermediate": {"1": true},
			},
			wantErr: true,
		},
		{
			name:           "single-certificate chain is accepted",
			verifiedChains: [][]*x509.Certificate{{leaf}},
			revokedCertSerials: map[string]map[string]bool{
				"intermediate": {"1": true},
			},
		},
		{
			name:           "missing CRL map entry is accepted",
			verifiedChains: [][]*x509.Certificate{{leaf, intermediate, root}},
			revokedCertSerials: map[string]map[string]bool{
				"unrelated": {"1": true},
			},
		},
		{
			name: "revoked path first and clean path second is accepted",
			verifiedChains: [][]*x509.Certificate{
				{leaf, revokedIntermediate, rootA},
				{leaf, cleanIntermediate, rootB},
			},
			revokedCertSerials: map[string]map[string]bool{
				"root-a": {"22": true},
			},
		},
		{
			name: "clean path first and revoked path second is accepted",
			verifiedChains: [][]*x509.Certificate{
				{leaf, cleanIntermediate, rootB},
				{leaf, revokedIntermediate, rootA},
			},
			revokedCertSerials: map[string]map[string]bool{
				"root-a": {"22": true},
			},
		},
		{
			name: "all paths contain revoked intermediates",
			verifiedChains: [][]*x509.Certificate{
				{leaf, revokedIntermediate, rootA},
				{leaf, cleanIntermediate, rootB},
			},
			revokedCertSerials: map[string]map[string]bool{
				"root-a": {"22": true},
				"root-b": {"23": true},
			},
			wantErr: true,
		},
		{
			name: "shared leaf is revoked",
			verifiedChains: [][]*x509.Certificate{
				{leaf, revokedIntermediate, rootA},
				{leaf, cleanIntermediate, rootB},
			},
			revokedCertSerials: map[string]map[string]bool{
				"intermediate-a": {"1": true},
				"intermediate-b": {"1": true},
			},
			wantErr: true,
		},
		{
			name: "same revoked intermediate appears in every path",
			verifiedChains: [][]*x509.Certificate{
				{leaf, revokedIntermediate, rootA},
				{leaf, revokedIntermediate, rootB},
			},
			revokedCertSerials: map[string]map[string]bool{
				"root-a": {"22": true},
				"root-b": {"22": true},
			},
			wantErr: true,
		},
		{
			name: "empty path does not make revoked connection pass",
			verifiedChains: [][]*x509.Certificate{
				{},
				{leaf, revokedIntermediate, rootA},
			},
			revokedCertSerials: map[string]map[string]bool{
				"root-a": {"22": true},
			},
			wantErr: true,
		},
		{
			name: "revoked leaf without authority key ID is rejected",
			verifiedChains: [][]*x509.Certificate{{
				certificate(7, "", "leaf", false),
				intermediate,
				root,
			}},
			revokedCertSerials: map[string]map[string]bool{
				"intermediate": {"7": true},
			},
			wantErr: true,
		},
		{
			name: "revoked leaf with incorrect authority key ID is rejected",
			verifiedChains: [][]*x509.Certificate{{
				certificate(8, "incorrect", "leaf", false),
				intermediate,
				root,
			}},
			revokedCertSerials: map[string]map[string]bool{
				"intermediate": {"8": true},
			},
			wantErr: true,
		},
		{
			name:           "normal leaf with correct authority key ID is accepted",
			verifiedChains: [][]*x509.Certificate{{leaf, intermediate, root}},
			revokedCertSerials: map[string]map[string]bool{
				"intermediate": {"99": true},
			},
		},
		{
			name: "empty parent subject key ID is accepted safely",
			verifiedChains: [][]*x509.Certificate{{
				certificate(9, "", "leaf", false),
				certificate(10, "", "", true),
			}},
			revokedCertSerials: map[string]map[string]bool{
				"different-issuer": {"9": true},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := NewConfig()
			config.revokedCertSerials = tt.revokedCertSerials
			pkiDir := filepath.Join("..", "..", "cmd", "testdata", "pki")
			if err := config.SetupTls(
				filepath.Join(pkiDir, "server-bundle.pem"),
				filepath.Join(pkiDir, "server-key.pem"),
				nil,
			); err != nil {
				t.Fatalf("SetupTls() error = %v", err)
			}

			err := config.TlsConfig.VerifyConnection(tls.ConnectionState{VerifiedChains: tt.verifiedChains})
			if tt.wantErr && err == nil {
				t.Fatal("verifyConnection() error = nil, want revocation error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("verifyConnection() error = %v, want nil", err)
			}
		})
	}
}

func TestSetupCrls(t *testing.T) {
	pkiDir := filepath.Join("..", "..", "cmd", "testdata", "pki")
	crlPath := filepath.Join(pkiDir, "crl.pem")
	caPath := filepath.Join(pkiDir, "ca.pem")

	loadClientCA := func(t *testing.T, config *Config) {
		t.Helper()
		if err := addCertsFromFile(config, x509.NewCertPool(), caPath); err != nil {
			t.Fatalf("addCertsFromFile() error = %v", err)
		}
	}

	readCRL := func(t *testing.T) *pkix.CertificateList {
		t.Helper()
		crlBytes, err := os.ReadFile(crlPath)
		if err != nil {
			t.Fatalf("ReadFile() error = %v", err)
		}
		certList, err := x509.ParseCRL(crlBytes)
		if err != nil {
			t.Fatalf("ParseCRL() error = %v", err)
		}
		return certList
	}

	writeCRL := func(t *testing.T, certList *pkix.CertificateList) string {
		t.Helper()
		der, err := asn1.Marshal(*certList)
		if err != nil {
			t.Fatalf("Marshal() error = %v", err)
		}
		path := filepath.Join(t.TempDir(), "test.crl")
		if err := os.WriteFile(path, der, 0600); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}
		return path
	}

	assertSetupCrlsError := func(t *testing.T, err error, path, want string) {
		t.Helper()
		if err == nil {
			t.Fatalf("SetupCrls() error = nil, want error containing %q", want)
		}
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("SetupCrls() error = %q, want it to contain %q", err, want)
		}
		if !strings.Contains(err.Error(), path) {
			t.Fatalf("SetupCrls() error = %q, want it to contain CRL path %q", err, path)
		}
	}

	t.Run("parse failure", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "invalid.crl")
		if err := os.WriteFile(path, []byte("not a CRL"), 0600); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}

		err := NewConfig().SetupCrls([]string{path})
		assertSetupCrlsError(t, err, path, "failed to parse CRL")
	})

	t.Run("missing authority key identifier", func(t *testing.T) {
		certList := readCRL(t)
		authorityKeyIdentifierOID := asn1.ObjectIdentifier{2, 5, 29, 35}
		extensions := certList.TBSCertList.Extensions[:0]
		for _, extension := range certList.TBSCertList.Extensions {
			if !extension.Id.Equal(authorityKeyIdentifierOID) {
				extensions = append(extensions, extension)
			}
		}
		certList.TBSCertList.Extensions = extensions
		certList.TBSCertList.Raw = nil

		path := writeCRL(t, certList)
		err := NewConfig().SetupCrls([]string{path})
		assertSetupCrlsError(t, err, path, "has no Authority Key Identifier")
	})

	t.Run("no matching client CA", func(t *testing.T) {
		err := NewConfig().SetupCrls([]string{crlPath})
		assertSetupCrlsError(t, err, crlPath, "no matching client CA is loaded")
	})

	t.Run("invalid signature", func(t *testing.T) {
		crlBytes, err := os.ReadFile(crlPath)
		if err != nil {
			t.Fatalf("ReadFile() error = %v", err)
		}
		block, _ := pem.Decode(crlBytes)
		if block == nil {
			t.Fatal("Decode() returned no PEM block")
		}
		block.Bytes[len(block.Bytes)-1] ^= 0xff
		path := filepath.Join(t.TempDir(), "invalid-signature.crl")
		if err := os.WriteFile(path, block.Bytes, 0600); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}

		config := NewConfig()
		loadClientCA(t, config)
		err = config.SetupCrls([]string{path})
		assertSetupCrlsError(t, err, path, "failed to verify signature")
	})

	t.Run("valid CRL", func(t *testing.T) {
		config := NewConfig()
		loadClientCA(t, config)
		if err := config.SetupCrls([]string{crlPath}); err != nil {
			t.Fatalf("SetupCrls() error = %v, want nil", err)
		}
		if len(config.CrlByAuthorityKeyId) != 1 {
			t.Fatalf("loaded CRLs = %d, want 1", len(config.CrlByAuthorityKeyId))
		}
		for issuerKeyID, certList := range config.CrlByAuthorityKeyId {
			if certList == nil {
				t.Fatal("loaded CRL is nil")
			}
			revokedCertificates := certList.TBSCertList.RevokedCertificates
			if len(revokedCertificates) == 0 {
				t.Fatal("valid CRL contains no revoked certificates")
			}
			revokedSerial := revokedCertificates[0].SerialNumber.String()
			if !config.revokedCertSerials[issuerKeyID][revokedSerial] {
				t.Fatalf("revoked serial %q was not indexed", revokedSerial)
			}
		}
	})

	t.Run("no configured CRLs", func(t *testing.T) {
		if err := NewConfig().SetupCrls(nil); err != nil {
			t.Fatalf("SetupCrls() error = %v, want nil", err)
		}
	})
}
