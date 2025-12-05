// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"fmt"
	"sync"

	"github.com/hashicorp/cap/oidc"
)

type extendedRequest struct {
	oidc.Request
	t oidc.Token
}

type requestCache struct {
	m sync.Mutex
	c map[string]extendedRequest
}

func newRequestCache() *requestCache {
	return &requestCache{
		c: map[string]extendedRequest{},
	}
}

// Read implements the callback.StateReader interface and will delete the state
// before returning.
func (rc *requestCache) Read(ctx context.Context, state string) (oidc.Request, error) {
	const op = "requestCache.Read"
	rc.m.Lock()
	defer rc.m.Unlock()
	if oidcRequest, ok := rc.c[state]; ok {
		if oidcRequest.IsExpired() {
			delete(rc.c, state)
			return nil, fmt.Errorf("%s: state %s not found", op, state)
		}
		return oidcRequest, nil
	}
	return nil, fmt.Errorf("%s: state %s not found", op, state)
}

func (rc *requestCache) Add(s oidc.Request) {
	rc.m.Lock()
	defer rc.m.Unlock()
	rc.c[s.State()] = extendedRequest{Request: s}
}

func (rc *requestCache) SetToken(id string, t oidc.Token) error {
	const op = "stateCache.SetToken"
	rc.m.Lock()
	defer rc.m.Unlock()
	if oidcRequest, ok := rc.c[id]; ok {
		if oidcRequest.IsExpired() {
			delete(rc.c, id)
			return fmt.Errorf("%s: state %s not found (expired)", op, id)
		}
		rc.c[id] = extendedRequest{Request: oidcRequest.Request, t: t}
		return nil
	}
	return fmt.Errorf("%s: %s not found", op, id)
}

func (rc *requestCache) Delete(id string) {
	rc.m.Lock()
	defer rc.m.Unlock()
	delete(rc.c, id)
}
