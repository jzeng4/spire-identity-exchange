package k8ssatoken

import (
	"context"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/spiffe/spire-identity-exchange/internal/config"
	"github.com/spiffe/spire-identity-exchange/internal/utils"
	"go.uber.org/zap"
)

// Validator validates Kubernetes service account tokens.
// It implements the validator.TokenValidator interface.
type Validator struct {
	// TLS configuration for authenticating with the K8s API server
	config config.K8sAPIClientTlsConfig
	// Logger for logging
	logger *zap.Logger
}

// NewValidator creates a new K8s SA token validator
func NewValidator(cfg config.K8sAPIClientTlsConfig, logger *zap.Logger) (*Validator, error) {
	logger.Info("Initialized K8s SA token validator - API host will be derived from token issuer field")

	return &Validator{
		config: cfg,
		logger: logger,
	}, nil
}

// Validate validates a Kubernetes service account token via the K8s TokenReview API
// and returns the JWT claims. Implements validator.TokenValidator.
func (v *Validator) Validate(ctx context.Context, token string) (*utils.Claims, error) {
	if len(token) == 0 {
		return nil, fmt.Errorf("token cannot be empty")
	}

	// Extract JWT claims to get issuer information (unverified at this stage)
	rawClaims := make(jwt.MapClaims)
	_, _, err := new(jwt.Parser).ParseUnverified(token, rawClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to extract JWT claims: %w", err)
	}

	// Extract issuer from claims - this will be the K8s API server URL
	issuer, ok := rawClaims["iss"].(string)
	if !ok || issuer == "" {
		return nil, fmt.Errorf("missing or invalid issuer in JWT token")
	}

	v.logger.Info("Validating token from K8s API server", zap.String("issuer", issuer))

	// Verify the token using K8s TokenReview API
	tokenVerifier, err := utils.NewK8sSaTokenVerifier(
		issuer,
		v.config.CertFile,
		v.config.KeyFile,
		v.config.CAFile,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create token verifier: %w", err)
	}

	if err = tokenVerifier.Verify(ctx, token); err != nil {
		return nil, fmt.Errorf("token verification failed: %w", err)
	}

	// Convert jwt.MapClaims to map[string]interface{}
	claimsMap := make(map[string]interface{}, len(rawClaims))
	for k, val := range rawClaims {
		claimsMap[k] = val
	}

	subject, _ := claimsMap["sub"].(string)
	v.logger.Info("Token validated successfully", zap.String("issuer", issuer), zap.String("subject", subject))

	return &utils.Claims{RawClaims: claimsMap}, nil
}
