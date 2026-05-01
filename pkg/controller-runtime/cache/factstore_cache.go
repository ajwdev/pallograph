// Package cache provides an implementation of Mangle's FactStore backed by a
// controller-runtime cache.
package cache

import (
	"fmt"

	"github.com/google/mangle/ast"
	"github.com/google/mangle/factstore"
	"k8s.io/client-go/rest"
	ctrlcache "sigs.k8s.io/controller-runtime/pkg/cache"
)

type FactStoreCache interface {
	factstore.ReadOnlyFactStore
	ctrlcache.Cache
}

type factStoreCacheImpl struct {
	ctrlcache.Cache
}

func New(cfg *rest.Config, opts ctrlcache.Options) (FactStoreCache, error) {
	inner, err := ctrlcache.New(cfg, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create underlying cache: %w", err)
	}

	return Wrap(inner), nil
}

func Wrap(inner ctrlcache.Cache) FactStoreCache {
	return &factStoreCacheImpl{
		Cache: inner,
	}
}

// Contains implements the factore.ReadOnlyFactStore interface
func (c *factStoreCacheImpl) Contains(atom ast.Atom) bool {
	return false
}

// EstimateFactCount implements the factore.ReadOnlyFactStore interface
func (c *factStoreCacheImpl) EstimateFactCount() int {
	return 0
}

// ListPredicates implements the factore.ReadOnlyFactStore interface
func (c *factStoreCacheImpl) ListPredicates() []ast.PredicateSym {
	return nil
}

// GetFacts implements the factore.ReadOnlyFactStore interface
func (c *factStoreCacheImpl) GetFacts(atom ast.Atom, fn func(ast.Atom) error) error {
	return nil
}
