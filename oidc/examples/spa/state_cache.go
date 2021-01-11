package main

import (
	"context"
	"fmt"
	"sync"

	"github.com/hashicorp/cap/oidc"
)

type extendedState struct {
	oidc.State
	t oidc.Token
}

type stateCache struct {
	m sync.Mutex
	c map[string]extendedState
}

func newStateCache() *stateCache {
	return &stateCache{
		c: map[string]extendedState{},
	}

}

// Read implements the callback.StateReader interface and will delete the state
// before returning.
func (sc *stateCache) Read(ctx context.Context, stateID string) (oidc.State, error) {
	const op = "stateCache.Read"
	sc.m.Lock()
	defer sc.m.Unlock()
	if s, ok := sc.c[stateID]; ok {
		if s.IsExpired() {
			delete(sc.c, stateID)
			return nil, fmt.Errorf("%s: state %s not found", op, stateID)
		}
		return s, nil
	}
	return nil, fmt.Errorf("%s: state %s not found", op, stateID)
}

func (sc *stateCache) Add(s oidc.State) {
	sc.m.Lock()
	defer sc.m.Unlock()
	sc.c[s.ID()] = extendedState{State: s}
}

func (sc *stateCache) SetToken(id string, t oidc.Token) error {
	const op = "stateCache.SetToken"
	sc.m.Lock()
	defer sc.m.Unlock()
	if s, ok := sc.c[id]; ok {
		if s.IsExpired() {
			delete(sc.c, id)
			return fmt.Errorf("%s: state %s not found (expired)", op, id)
		}
		sc.c[id] = extendedState{State: s.State, t: t}
		return nil
	}
	return fmt.Errorf("%s: %s not found", op, id)

}

func (sc *stateCache) Delete(id string) {
	sc.m.Lock()
	defer sc.m.Unlock()
	delete(sc.c, id)
}
