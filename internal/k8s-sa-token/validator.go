package k8ssatoken

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/spiffe/spire-identity-exchange/internal/config"
	"github.com/spiffe/spire-identity-exchange/internal/utils"
	"go.uber.org/zap"
)

// Validator validates Kubernetes service account tokens.
// It implements the validator.TokenValidator interface.
type Validator struct {
	// Kubernetes API server URL (operator-configured; NEVER derived from the token).
	apiHost string
	// Expected audiences forwarded to the TokenReview Spec (may be empty to skip audience binding).
	audiences []string
	// TLS configuration for authenticating with the K8s API server
	tlsConfig config.K8sAPIClientTlsConfig
	// Logger for logging
	logger *zap.Logger
}

// NewValidator creates a new K8s SA token validator
func NewValidator(cfg config.K8sSATokenConfig, logger *zap.Logger) (*Validator, error) {
	if cfg.APIHost == "" {
		return nil, fmt.Errorf("k8sSAToken.apiHost is required")
	}
	logger.Info("Initialized K8s SA token validator",
		zap.String("apiHost", cfg.APIHost),
		zap.Strings("audiences", cfg.Audiences))

	return &Validator{
		apiHost:   cfg.APIHost,
		audiences: cfg.Audiences,
		tlsConfig: cfg.TLS,
		logger:    logger,
	}, nil
}

// Validate validates a Kubernetes service account token via the K8s TokenReview API
// and returns the JWT claims. Implements validator.TokenValidator.
//
// The TokenReview is always sent to the operator-configured apiHost — never to a host
// derived from the token's iss claim, which would be attacker-controlled before verification.
func (v *Validator) Validate(ctx context.Context, token string) (*utils.Claims, error) {
	if len(token) == 0 {
		return nil, fmt.Errorf("token cannot be empty")
	}

	// Parse the token unverified solely to surface claims for SPIFFE ID derivation.
	// The TokenReview call (below) is the authoritative authentication step.
	rawClaims := make(jwt.MapClaims)
	_, _, err := new(jwt.Parser).ParseUnverified(token, rawClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to extract JWT claims: %w", err)
	}

	v.logger.Info("Validating token via configured K8s API server", zap.String("apiHost", v.apiHost))

	tokenVerifier, err := utils.NewK8sSaTokenVerifier(
		v.apiHost,
		v.audiences,
		v.tlsConfig.CertFile,
		v.tlsConfig.KeyFile,
		v.tlsConfig.CAFile,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create token verifier: %w", err)
	}

	if err = tokenVerifier.Verify(ctx, token); err != nil {
		return nil, fmt.Errorf("token verification failed: %w", err)
	}

	// Populate both RegisteredClaims and RawClaims via the Claims UnmarshalJSON.
	claimsJSON, err := json.Marshal(rawClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to encode claims: %w", err)
	}
	var claims utils.Claims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, fmt.Errorf("failed to decode claims: %w", err)
	}

	v.logger.Info("Token validated successfully", zap.String("issuer", claims.Issuer), zap.String("subject", claims.Subject))

	return &claims, nil
}
