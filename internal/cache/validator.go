package cache

import (
	"context"
	"errors"
	"fmt"

	"github.com/spiffe/spire-identity-exchange/internal/utils"
	v "github.com/spiffe/spire-identity-exchange/internal/validator"
)

type replayCheckingValidator struct {
	inner v.TokenValidator
	cache ReplayCache
}

// NewReplayCheckingValidator wraps inner with replay detection using cache.
// Tokens without a jti claim are rejected.
func NewReplayCheckingValidator(inner v.TokenValidator, cache ReplayCache) v.TokenValidator {
	return &replayCheckingValidator{inner: inner, cache: cache}
}

func (r *replayCheckingValidator) Start(ctx context.Context) error {
	if syncer, ok := r.inner.(v.KeySynchronizer); ok {
		return syncer.Start(ctx)
	}
	return nil
}

func (r *replayCheckingValidator) Validate(ctx context.Context, token string) (*utils.Claims, error) {
	claims, err := r.inner.Validate(ctx, token)
	if err != nil {
		return nil, err
	}

	if claims.ID == "" {
		return nil, errors.New("token missing jti claim: replay detection requires a unique token ID")
	}

	if claims.ExpiresAt == nil {
		return nil, errors.New("token missing exp claim: cannot determine replay cache TTL")
	}

	if !r.cache.Add(claims.ID, claims.ExpiresAt.Time) {
		return nil, fmt.Errorf("token replay detected: jti %q has already been used", claims.ID)
	}

	return claims, nil
}
