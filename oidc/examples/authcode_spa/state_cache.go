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
func (sc *stateCache) Read(ctx context.Context, stateId string) (oidc.State, error) {
	if stateRaw, ok := sc.c.Get(stateId); ok {
		if extended, ok := stateRaw.(*extendedState); ok {
			return extended, nil
		}
		return nil, fmt.Errorf("not an extended state")

	}
	return nil, fmt.Errorf("state %s not found", stateId)
}

func (sc *stateCache) Add(s oidc.State) {
	extended := extendedState{State: s}
	sc.c.SetDefault(s.Id(), &extended)
}

func (sc *stateCache) SetToken(id string, t oidc.Token) error {
	s, exp, ok := sc.c.GetWithExpiration(id)
	if !ok {
		return fmt.Errorf("%s not found", id)
	}
	extended, ok := s.(*extendedState)
	if !ok {
		return fmt.Errorf("not an extended state")
	}
	sc.c.Set(id, &extendedState{State: extended.State, t: t}, exp.Sub(time.Now()))
	return nil
}

func (sc *stateCache) Delete(id string) {
	sc.c.Delete(id)
}
