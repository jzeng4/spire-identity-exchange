package utils

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

// ParseCSR parses and validates a PEM-encoded CSR
func ParseCSR(csrPEM string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return nil, errors.New("no PEM data found")
	}
	if block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("unexpected PEM type: %s", block.Type)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %w", err)
	}
	if err = csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("invalid CSR signature: %w", err)
	}
	return csr, nil
}

// EncodeCertChainWithBundle returns:
// - PEM of the certificate chain
// - PEM of the root bundle (if available)
// - Expiration time of the leaf certificate
func EncodeCertChainWithBundle(certChain []*x509.Certificate) (certPEM string, bundlePEM string, expiresAt string) {
	var certPEMBuffer bytes.Buffer
	for _, cert := range certChain {
		pem.Encode(&certPEMBuffer, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
	}

	if len(certChain) > 1 {
		rootCert := certChain[len(certChain)-1]
		if rootCert.IsCA {
			bundlePEM = string(pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: rootCert.Raw,
			}))
		}
	}

	if len(certChain) > 0 {
		expiresAt = certChain[0].NotAfter.Format(time.RFC3339)
	}

	certPEM = certPEMBuffer.String()
	return
}
