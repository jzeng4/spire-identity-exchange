package githuboidc

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sync/atomic"
	"time"

	backoff "github.com/cenkalti/backoff/v4"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/spiffe/spire-identity-exchange/internal/config"
	constant "github.com/spiffe/spire-identity-exchange/internal/const"
	"github.com/spiffe/spire-identity-exchange/internal/metrics"
	"github.com/spiffe/spire-identity-exchange/internal/utils"
	v "github.com/spiffe/spire-identity-exchange/internal/validator"
	"google.golang.org/grpc/codes"
)

const (
	githubJwksURL              = "https://token.actions.githubusercontent.com/.well-known/jwks"
	keyCacheValidityDuration   = 5 * time.Minute
	kidHeader                  = "kid"
	maxJwksRetries             = 3
	initialBackoffInterval     = 1 * time.Second
	maxBackoffInterval         = 30 * time.Second
	backOffRandomizationFactor = 0.5
	backoffMultiplier          = 2.0
	// largeLeeway is a very large leeway (~100 years) used to effectively disable
	// time-based validation (exp, nbf, iat) while keeping other validations active
	largeLeeway = 876000 * time.Hour
)

// jwksCache caches JWKS for a provider
type jwksCache struct {
	// keys is an atomic.Value that stores the JWKS keys
	keys atomic.Value
	// expiresAt is an atomic.Value that stores the expiration time of the JWKS keys
	expiresAt atomic.Value
	ttl       time.Duration
}

type githubValidator struct {
	// The OIDC provider configuration
	config config.GitHubOIDCConfig
	// Cached JWKS keys
	keyCache *jwksCache
	// Logger for logging
	logger *zap.Logger
	// HTTP client for fetching JWKS
	httpClient *http.Client
	// Metrics for the validator
	metrics metrics.Metrics
}

// NewValidator creates a new GitHub OIDC validator.
// It implements validator.TokenValidator and validator.KeySynchronizer.
func NewValidator(ctx context.Context, cfg config.GitHubOIDCConfig, m metrics.Metrics, logger *zap.Logger) (v.TokenValidator, error) {
	cacheTTL := keyCacheValidityDuration
	if cfg.JWKSCacheDuration != 0 {
		cacheTTL = time.Duration(cfg.JWKSCacheDuration)
	}

	return &githubValidator{
		config:  cfg,
		metrics: m,
		logger:  logger,
		keyCache: &jwksCache{
			keys: atomic.Value{},
			ttl:  cacheTTL,
		},
		httpClient: http.DefaultClient,
	}, nil
}

// Validate validates an OIDC token and returns claims
func (gv *githubValidator) Validate(ctx context.Context, token string) (*utils.Claims, error) {
	claims := &utils.Claims{
		RawClaims: make(map[string]interface{}),
	}

	if err := gv.validateToken(token, claims); err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	if err := gv.validateClaims(claims.RawClaims, gv.config); err != nil {
		return nil, fmt.Errorf("claim validation failed: %w", err)
	}

	return claims, nil
}

// Start starts the periodic refreshes of the JWKS cache. Implements validator.KeySynchronizer.
func (gv *githubValidator) Start(ctx context.Context) error {
	if err := gv.refreshJWKSWithBackoff(ctx); err != nil {
		return fmt.Errorf("initial JWKS fetch failed: %w", err)
	}
	go gv.startJWKSRefresher(ctx)
	return nil
}

// validateToken validates the JWT signature and collects the claims.
func (gv *githubValidator) validateToken(tokenString string, claims *utils.Claims) error {
	keys, err := gv.getVerificationKeys()
	if err != nil {
		return fmt.Errorf("failed to get verification keys: %w", err)
	}

	var parserOpts []jwt.ParserOption
	if gv.config.Issuer != "" {
		parserOpts = append(parserOpts, jwt.WithIssuer(gv.config.Issuer))
	}
	if gv.config.SkipTokenExpiration {
		parserOpts = append(parserOpts, jwt.WithLeeway(largeLeeway))
	}

	now := time.Now()
	statusCode := codes.InvalidArgument
	defer func() {
		gv.metrics.ObserveOperationDuration(constant.ComponentLabel, constant.PluginLabel, constant.OperationValidateToken, statusCode.String(), time.Since(now).Seconds())
		gv.metrics.IncOperationCount(constant.ComponentLabel, constant.PluginLabel, constant.OperationValidateToken, statusCode.String())
	}()

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		switch token.Method.(type) {
		case *jwt.SigningMethodRSA, *jwt.SigningMethodECDSA:
			// ok
		default:
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		kid, ok := token.Header[kidHeader].(string)
		if !ok {
			return nil, errors.New("token missing kid header")
		}

		key, ok := keys[kid]
		if !ok {
			return nil, fmt.Errorf("unknown key id: %s", kid)
		}

		return key, nil
	}, parserOpts...)

	if err != nil {
		return fmt.Errorf("token parsing failed: %w", err)
	}
	if !token.Valid {
		return errors.New("token is invalid")
	}

	aud, err := claims.GetAudience()
	if err != nil {
		return fmt.Errorf("failed to get audience: %w", err)
	}
	if !gv.validateAudiences(aud) {
		return fmt.Errorf("audience mismatch: expected %v, got %v", gv.config.Audiences, aud)
	}

	statusCode = codes.OK
	return nil
}

func (gv *githubValidator) validateAudiences(tokenAudiences []string) bool {
	for _, aud := range tokenAudiences {
		if slices.Contains(gv.config.Audiences, aud) {
			return true
		}
	}
	return false
}

func (gv *githubValidator) validateRepository(repo string, cfg config.GitHubOIDCConfig) bool {
	if repo == "" {
		return false
	}
	return utils.IsValueAllowed(repo, cfg.AllowedRepositories)
}

func (gv *githubValidator) validateClaims(claims map[string]interface{}, cfg config.GitHubOIDCConfig) error {
	for _, required := range cfg.RequiredClaims {
		if value := utils.GetStringClaim(claims, required); value == "" {
			return fmt.Errorf("missing required claim: %s", required)
		}
	}

	repo := utils.GetStringClaim(claims, constant.ClaimRepository)
	if !gv.validateRepository(repo, cfg) {
		return fmt.Errorf("repository is not allowed: %s", repo)
	}

	return nil
}

func (gv *githubValidator) getVerificationKeys() (map[string]crypto.PublicKey, error) {
	if gv.keyCache == nil {
		return nil, errors.New("JWKS key cache is nil")
	}

	cachedValue := gv.keyCache.keys.Load()
	if cachedValue == nil {
		return nil, errors.New("JWKS cache not initialized - no keys loaded")
	}

	keys, ok := cachedValue.(map[string]crypto.PublicKey)
	if !ok {
		return nil, fmt.Errorf("JWKS cache contains invalid type: expected map[string]crypto.PublicKey, got %T", cachedValue)
	}

	if len(keys) == 0 {
		return nil, errors.New("JWKS cache is empty - no signing keys available")
	}

	return keys, nil
}

func (gv *githubValidator) refreshJWKSWithBackoff(ctx context.Context) error {
	expBackoff := backoff.NewExponentialBackOff()
	expBackoff.InitialInterval = initialBackoffInterval
	expBackoff.MaxInterval = maxBackoffInterval
	expBackoff.MaxElapsedTime = time.Duration(maxJwksRetries) * maxBackoffInterval
	expBackoff.RandomizationFactor = backOffRandomizationFactor
	expBackoff.Multiplier = backoffMultiplier

	if err := backoff.Retry(func() error { return gv.refreshJWKS(ctx) }, backoff.WithContext(expBackoff, ctx)); err != nil {
		return fmt.Errorf("failed to refresh JWKS after retries: %w", err)
	}
	return nil
}

func (gv *githubValidator) refreshJWKS(ctx context.Context) error {
	uri := gv.config.JWKSURI
	if uri == "" {
		uri = githubJwksURL
	}

	jwks, err := gv.fetchJWKS(ctx, uri)
	if err != nil {
		return fmt.Errorf("failed to refresh JWKS: %w", err)
	}

	keys, err := gv.convertJWKS(*jwks)
	if err != nil {
		return fmt.Errorf("failed to convert JWKS: %w", err)
	}

	gv.keyCache.keys.Store(keys)
	gv.keyCache.expiresAt.Store(time.Now().Add(gv.keyCache.ttl))
	gv.logger.Info("JWKS cache refreshed", zap.Int("count", len(keys)))

	return nil
}

func (gv *githubValidator) startJWKSRefresher(ctx context.Context) {
	ticker := time.NewTicker(gv.keyCache.ttl / 2)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := gv.refreshJWKSWithBackoff(ctx); err != nil {
				gv.logger.Error("periodic JWKS refresh failed", zap.Error(err))
			}
		case <-ctx.Done():
			return
		}
	}
}

func (gv *githubValidator) convertJWKS(jwks jose.JSONWebKeySet) (map[string]crypto.PublicKey, error) {
	keys := make(map[string]crypto.PublicKey)
	for _, jwk := range jwks.Keys {
		if jwk.KeyID == "" {
			gv.logger.Warn("JWK missing key ID, skipping")
			continue
		}
		if jwk.Use != "" && jwk.Use != "sig" {
			gv.logger.Warn("JWK not intended for signatures", zap.String("kid", jwk.KeyID), zap.String("use", jwk.Use))
			continue
		}
		publicKey := jwk.Public().Key
		if publicKey == nil {
			gv.logger.Warn("failed to extract public key from JWK", zap.String("kid", jwk.KeyID))
			continue
		}
		switch key := publicKey.(type) {
		case crypto.PublicKey:
			keys[jwk.KeyID] = key
			gv.logger.Debug("Added JWK to key cache", zap.String("kid", jwk.KeyID), zap.String("algorithm", jwk.Algorithm))
		default:
			gv.logger.Warn("unexpected key type from JWK", zap.String("kid", jwk.KeyID), zap.String("type", fmt.Sprintf("%T", publicKey)))
		}
	}

	if len(keys) == 0 {
		return nil, errors.New("no valid keys found in JWKS")
	}

	gv.logger.Info("Successfully fetched and parsed JWKS", zap.Int("keyCount", len(keys)))
	return keys, nil
}

func (gv *githubValidator) fetchJWKS(ctx context.Context, uri string) (*jose.JSONWebKeySet, error) {
	statusCode := codes.OK
	now := time.Now()
	defer func() {
		gv.metrics.IncOperationCount(constant.ComponentLabel, constant.PluginLabel, constant.OperationFetchJWKS, statusCode.String())
		gv.metrics.ObserveOperationDuration(constant.ComponentLabel, constant.PluginLabel, constant.OperationFetchJWKS, statusCode.String(), time.Since(now).Seconds())
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		statusCode = codes.InvalidArgument
		return nil, fmt.Errorf("failed to create JWKS request: %w", err)
	}

	resp, err := gv.httpClient.Do(req)
	if err != nil {
		statusCode = codes.Internal
		return nil, fmt.Errorf("http client failed to fetch JWKS from %s: %w", uri, err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			gv.logger.Error("failed to close JWKS response body", zap.Error(cerr))
		}
	}()

	if resp.StatusCode != http.StatusOK {
		statusCode = codes.Internal
		return nil, fmt.Errorf("JWKS fetch failed with status: %d from %s", resp.StatusCode, uri)
	}

	var jwks jose.JSONWebKeySet
	if err = json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		statusCode = codes.Internal
		return nil, fmt.Errorf("failed to decode JWKS from %s: %w", uri, err)
	}
	return &jwks, nil
}
