package cache

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestReplayCache_Add(t *testing.T) {
	rc := NewInMemoryReplayCache(context.Background())

	assert.True(t, rc.Add("jti-1", time.Now().Add(time.Minute)))
	assert.False(t, rc.Add("jti-1", time.Now().Add(time.Minute)))
	assert.True(t, rc.Add("jti-2", time.Now().Add(time.Minute)))
}

func TestReplayCache_EvictionStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	rc := NewInMemoryReplayCache(ctx)

	assert.True(t, rc.Add("jti-1", time.Now().Add(time.Minute)))

	cancel()
	time.Sleep(50 * time.Millisecond)

	assert.False(t, rc.Add("jti-1", time.Now().Add(time.Minute)))
}
