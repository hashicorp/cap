package main

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/cap/oidc"
	"github.com/patrickmn/go-cache"
)

type extendedState struct {
	oidc.State
	t oidc.Token
}

type stateCache struct {
	c *cache.Cache
}

func newStateCache(entryTimeout time.Duration, cleanupInterval time.Duration) *stateCache {
	return &stateCache{
		c: cache.New(entryTimeout, cleanupInterval),
	}

}

// Read implements the callback.StateReader interface and will delete the state
// before returning.
func (sc *stateCache) Read(ctx context.Context, stateID string) (oidc.State, error) {
	const op = "stateCache.Read"
	if stateRaw, ok := sc.c.Get(stateID); ok {
		if extended, ok := stateRaw.(*extendedState); ok {
			return extended, nil
		}
		return nil, fmt.Errorf("%s: not an extended state", op)

	}
	return nil, fmt.Errorf("%s: state %s not found", op, stateID)
}

func (sc *stateCache) Add(s oidc.State) {
	extended := extendedState{State: s}
	sc.c.SetDefault(s.ID(), &extended)
}

func (sc *stateCache) SetToken(id string, t oidc.Token) error {
	const op = "stateCache.SetToken"
	s, exp, ok := sc.c.GetWithExpiration(id)
	if !ok {
		return fmt.Errorf("%s: %s not found", op, id)
	}
	extended, ok := s.(*extendedState)
	if !ok {
		return fmt.Errorf("%s, not an extended state", op)
	}
	sc.c.Set(id, &extendedState{State: extended.State, t: t}, time.Until(exp))
	return nil
}

func (sc *stateCache) Delete(id string) {
	sc.c.Delete(id)
}
