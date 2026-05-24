package utils_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/spiffe/spire-identity-exchange/internal/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseCSR(t *testing.T) {
	// Helper function to generate a valid CSR
	generateValidCSR := func(t *testing.T, spiffeID string) string {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		template := x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName:   "test",
				Organization: []string{"Test Org"},
			},
		}

		if spiffeID != "" {
			uri, err := url.Parse(spiffeID)
			require.NoError(t, err)
			template.URIs = []*url.URL{uri}
		}

		csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
		require.NoError(t, err)

		csrPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: csrBytes,
		})

		return string(csrPEM)
	}

	generateInvalidSignatureCSR := func(t *testing.T) string {
		validCSR := generateValidCSR(t, "spiffe://example.org/test")
		block, _ := pem.Decode([]byte(validCSR))
		block.Bytes[len(block.Bytes)-1] ^= 0xFF
		return string(pem.EncodeToMemory(block))
	}

	generateMalformedCSR := func() string {
		return string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: []byte("not a valid CSR"),
		}))
	}

	testCases := []struct {
		name          string
		csrPEM        string
		expectError   bool
		errorContains string
		validate      func(*testing.T, *x509.CertificateRequest)
	}{
		{
			name:        "Valid CSR with SPIFFE ID",
			csrPEM:      generateValidCSR(t, "spiffe://example.org/test"),
			expectError: false,
			validate: func(t *testing.T, csr *x509.CertificateRequest) {
				assert.NotNil(t, csr)
				assert.Equal(t, "test", csr.Subject.CommonName)
				assert.Equal(t, []string{"Test Org"}, csr.Subject.Organization)
				assert.Len(t, csr.URIs, 1)
				assert.Equal(t, "spiffe://example.org/test", csr.URIs[0].String())
			},
		},
		{
			name:        "Valid CSR without SPIFFE ID",
			csrPEM:      generateValidCSR(t, ""),
			expectError: false,
			validate: func(t *testing.T, csr *x509.CertificateRequest) {
				assert.NotNil(t, csr)
				assert.Equal(t, "test", csr.Subject.CommonName)
				assert.Len(t, csr.URIs, 0)
			},
		},
		{
			name:          "Empty CSR",
			csrPEM:        "",
			expectError:   true,
			errorContains: "no PEM data found",
		},
		{
			name:          "Invalid PEM format",
			csrPEM:        "not a PEM block",
			expectError:   true,
			errorContains: "no PEM data found",
		},
		{
			name: "Wrong PEM type",
			csrPEM: string(pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: []byte("some data"),
			})),
			expectError:   true,
			errorContains: "unexpected PEM type: CERTIFICATE",
		},
		{
			name:          "Malformed CSR bytes",
			csrPEM:        generateMalformedCSR(),
			expectError:   true,
			errorContains: "failed to parse CSR",
		},
		{
			name:          "Invalid CSR signature",
			csrPEM:        generateInvalidSignatureCSR(t),
			expectError:   true,
			errorContains: "invalid CSR signature",
		},
		{
			name:        "CSR with extra data after PEM block",
			csrPEM:      generateValidCSR(t, "spiffe://example.org/test") + "\nextra data that should be ignored",
			expectError: false,
			validate: func(t *testing.T, csr *x509.CertificateRequest) {
				assert.NotNil(t, csr)
				assert.Equal(t, "test", csr.Subject.CommonName)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			csr, err := utils.ParseCSR(tc.csrPEM)

			if tc.expectError {
				assert.Error(t, err)
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains)
				}
				assert.Nil(t, csr)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, csr)
				if tc.validate != nil {
					tc.validate(t, csr)
				}
			}
		})
	}
}

func TestEncodeCertChainWithBundle(t *testing.T) {
	generateTestCert := func(t *testing.T, commonName string, isCA bool, spiffeID string) *x509.Certificate {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
		serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
		require.NoError(t, err)

		template := &x509.Certificate{
			SerialNumber: serialNumber,
			Subject: pkix.Name{
				CommonName: commonName,
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(24 * time.Hour),
			IsCA:                  isCA,
			BasicConstraintsValid: isCA,
		}

		if spiffeID != "" {
			uri, err := url.Parse(spiffeID)
			require.NoError(t, err)
			template.URIs = []*url.URL{uri}
		}

		certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
		require.NoError(t, err)

		cert, err := x509.ParseCertificate(certBytes)
		require.NoError(t, err)

		return cert
	}

	testCases := []struct {
		name              string
		certs             []*x509.Certificate
		expectCertPEM     bool
		expectBundlePEM   bool
		expectExpiresAt   bool
		validateCertCount int
	}{
		{
			name: "Single leaf certificate",
			certs: []*x509.Certificate{
				generateTestCert(t, "leaf", false, "spiffe://example.org/test"),
			},
			expectCertPEM:     true,
			expectBundlePEM:   false,
			expectExpiresAt:   true,
			validateCertCount: 1,
		},
		{
			name: "Chain with leaf and intermediate",
			certs: []*x509.Certificate{
				generateTestCert(t, "leaf", false, "spiffe://example.org/test"),
				generateTestCert(t, "intermediate", true, ""),
			},
			expectCertPEM:     true,
			expectBundlePEM:   true,
			expectExpiresAt:   true,
			validateCertCount: 2,
		},
		{
			name:              "Empty certificate chain",
			certs:             []*x509.Certificate{},
			expectCertPEM:     false,
			expectBundlePEM:   false,
			expectExpiresAt:   false,
			validateCertCount: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			certPEM, bundlePEM, expiresAt := utils.EncodeCertChainWithBundle(tc.certs)

			if tc.expectCertPEM {
				assert.NotEmpty(t, certPEM, "expected non-empty certPEM")
			} else {
				assert.Empty(t, certPEM, "expected empty certPEM")
			}

			if tc.expectBundlePEM {
				assert.NotEmpty(t, bundlePEM, "expected non-empty bundlePEM")
			} else {
				assert.Empty(t, bundlePEM, "expected empty bundlePEM")
			}

			if tc.expectExpiresAt {
				assert.NotEmpty(t, expiresAt, "expected non-empty expiresAt")
				_, err := time.Parse(time.RFC3339, expiresAt)
				assert.NoError(t, err, "expiresAt should be valid RFC3339 format")
			} else {
				assert.Empty(t, expiresAt, "expected empty expiresAt")
			}
		})
	}
}
