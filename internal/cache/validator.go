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
//
// Semantics: a token's jti is recorded as soon as the inner validator accepts it,
// BEFORE the downstream MintCertificate call runs. This is single-attempted-use,
// not single-successful-use. The trade-off is intentional:
//   - Marking after a successful mint opens a race window in which a concurrent
//     attacker who races the legitimate client could mint with the same token —
//     the cache check would pass for both calls because neither has finished yet.
//   - Marking on validation success closes that window: any second attempt fails
//     fast at the cache check regardless of what the first attempt does.
//
// The cost is that a legitimate client whose mint fails (bad CSR, transient SPIRE
// error, etc.) must obtain a fresh token rather than retry with the same one.
// OIDC tokens are short-lived and cheap to re-issue, so this is the safer default.
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
