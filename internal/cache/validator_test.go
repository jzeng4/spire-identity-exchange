package cache

import (
	"context"
	"testing"

	"github.com/spiffe/spire-identity-exchange/internal/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeValidator struct {
	claims *utils.Claims
	err    error
}

func (f *fakeValidator) Validate(_ context.Context, _ string) (*utils.Claims, error) {
	return f.claims, f.err
}

type fakeSyncValidator struct {
	fakeValidator
	started  bool
	startErr error
}

func (f *fakeSyncValidator) Start(_ context.Context) error {
	f.started = true
	return f.startErr
}

func TestStart_DelegatesToInnerKeySynchronizer(t *testing.T) {
	inner := &fakeSyncValidator{}
	rc := NewInMemoryReplayCache(context.Background())
	v := NewReplayCheckingValidator(inner, rc)

	syncer := v.(*replayCheckingValidator)
	err := syncer.Start(context.Background())

	require.NoError(t, err)
	assert.True(t, inner.started)
}

func TestStart_NoOpWhenInnerLacksKeySynchronizer(t *testing.T) {
	inner := &fakeValidator{}
	rc := NewInMemoryReplayCache(context.Background())
	v := NewReplayCheckingValidator(inner, rc)

	syncer := v.(*replayCheckingValidator)
	err := syncer.Start(context.Background())

	require.NoError(t, err)
}

func TestStart_PropagatesError(t *testing.T) {
	inner := &fakeSyncValidator{startErr: assert.AnError}
	rc := NewInMemoryReplayCache(context.Background())
	v := NewReplayCheckingValidator(inner, rc)

	syncer := v.(*replayCheckingValidator)
	err := syncer.Start(context.Background())

	require.ErrorIs(t, err, assert.AnError)
}
