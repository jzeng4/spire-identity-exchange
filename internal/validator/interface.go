package validator

import (
	"context"

	"github.com/spiffe/spire-identity-exchange/internal/utils"
)

// TokenValidator defines the interface for token validation
type TokenValidator interface {
	// Validate validates a token
	Validate(ctx context.Context, token string) (*utils.Claims, error)
}

// KeySynchronizer defines the interface for refreshing
type KeySynchronizer interface {
	// Start starts the key synchronizer
	Start(ctx context.Context) error
}
