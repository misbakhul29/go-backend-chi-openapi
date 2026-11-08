package oauth

import (
	"errors"
	"fmt"
	"sync"
)

var (
	ErrProviderNotFound = errors.New("oauth provider not found")
)

type Registry struct {
	mu        sync.RWMutex
	providers map[string]OAuthProvider
}

func NewRegistry() *Registry {
	return &Registry{
		providers: make(map[string]OAuthProvider),
	}
}

func (r *Registry) Register(provider OAuthProvider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.providers[provider.Name()] = provider
}

func (r *Registry) Get(name string) (OAuthProvider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrProviderNotFound, name)
	}
	return p, nil
}

func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.providers))
	for name := range r.providers {
		names = append(names, name)
	}
	return names
}
