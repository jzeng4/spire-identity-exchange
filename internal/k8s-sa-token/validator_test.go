package k8ssatoken

import (
	"context"
	"testing"

	"github.com/spiffe/spire-identity-exchange/internal/config"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

const (
	testCAFile         = "/etc/spire-identity-exchange/ca-bundle.crt"
	testClientCertFile = "/etc/ssl/certs/client.crt"
	testClientKeyFile  = "/etc/ssl/private/client.key"
)

func TestNewValidator(t *testing.T) {
	logger := zap.NewNop()

	testCases := []struct {
		name      string
		config    config.K8sAPIClientTlsConfig
		expectErr bool
	}{
		{
			name: "empty config should succeed",
			config: config.K8sAPIClientTlsConfig{
				CertFile: "",
				KeyFile:  "",
				CAFile:   "",
			},
			expectErr: false,
		},
		{
			name: "config with certificate files",
			config: config.K8sAPIClientTlsConfig{
				CertFile: testClientCertFile,
				KeyFile:  testClientKeyFile,
				CAFile:   testCAFile,
			},
			expectErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			validator, err := NewValidator(tc.config, logger)

			if tc.expectErr && err == nil {
				assert.Error(t, err, "expected error but got none")
			}

			if !tc.expectErr && err != nil {
				assert.NoError(t, err, "expected no error but got: %v", err)
			}

			if !tc.expectErr && validator == nil {
				assert.NotNil(t, validator, "expected validator to be created")
			}
		})
	}
}

func TestValidateToken(t *testing.T) {
	logger := zap.NewNop()
	cfg := config.K8sAPIClientTlsConfig{
		CAFile: testCAFile,
	}

	validator, err := NewValidator(cfg, logger)
	if err != nil {
		t.Fatalf("failed to create validator: %v", err)
	}

	testCases := []struct {
		name      string
		token     string
		expectErr bool
	}{
		{
			name:      "empty token",
			token:     "",
			expectErr: true,
		},
		{
			name:      "invalid JWT token",
			token:     "invalid.jwt.token",
			expectErr: true,
		},
	}

	ctx := context.Background()
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tokenInfo, err := validator.Validate(ctx, tc.token)

			if tc.expectErr && err == nil {
				assert.Error(t, err, "expected error but got none")
			}

			if !tc.expectErr && err != nil {
				assert.NoError(t, err, "expected no error but got: %v", err)
			}

			if !tc.expectErr && tokenInfo == nil {
				assert.NotNil(t, tokenInfo, "expected token info to be returned")
			}
		})
	}
}
