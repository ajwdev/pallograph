package cache

import (
	"context"
	"fmt"

	"github.com/google/btree"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlcache "sigs.k8s.io/controller-runtime/pkg/cache"
)

// BTreeCache is a controller-runtime cache that uses BTree storage
// instead of hashmaps. This allows for:
// - Ordered iteration
// - Atomic snapshots
// - Efficient range queries
type BTreeCache interface {
	ctrlcache.Cache

	// Snapshot returns an atomic snapshot of all cached objects of a given type
	// The snapshot is a point-in-time copy and won't be affected by future updates
	Snapshot(ctx context.Context, obj client.Object) (*btree.BTreeG[StoreItem], error)

	// SnapshotAll returns snapshots for all cached types
	// Returns a map of GVK -> BTree snapshot
	SnapshotAll(ctx context.Context) (map[schema.GroupVersionKind]*btree.BTreeG[StoreItem], error)
}

type btreeCacheImpl struct {
	ctrlcache.Cache
}

// NewBTreeCache creates a new cache that uses BTree-backed storage
func NewBTreeCache(cfg *rest.Config, opts ctrlcache.Options) (BTreeCache, error) {
	// Configure the cache to use our custom BTree informer
	opts.DefaultTransform = opts.DefaultTransform // preserve existing transform
	opts.NewInformer = NewBTreeInformer           // Use BTree-backed informers

	// Create the underlying cache with our custom options
	inner, err := ctrlcache.New(cfg, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create underlying cache: %w", err)
	}

	return &btreeCacheImpl{
		Cache: inner,
	}, nil
}

// WrapWithBTreeCache wraps an existing cache to add BTree snapshot capabilities
// Note: This only works if the cache was created with NewBTreeInformer
func WrapWithBTreeCache(inner ctrlcache.Cache) BTreeCache {
	return &btreeCacheImpl{
		Cache: inner,
	}
}

// Snapshot returns an atomic snapshot of all cached objects of the given type
func (c *btreeCacheImpl) Snapshot(ctx context.Context, obj client.Object) (*btree.BTreeG[StoreItem], error) {
	// Get the informer for this object type
	// controller-runtime's GetInformer returns cache.Informer, but the underlying
	// implementation is a client-go SharedIndexInformer
	informer, err := c.Cache.GetInformer(ctx, obj)
	if err != nil {
		return nil, fmt.Errorf("failed to get informer: %w", err)
	}

	// The informer should be our btreeSharedIndexInformer wrapper
	if btreeInf, ok := informer.(*btreeSharedIndexInformer); ok {
		return btreeInf.btreeIdx.Snapshot(), nil
	}

	return nil, fmt.Errorf("informer does not use BTree indexer (was cache created with NewBTreeCache?)")
}

// SnapshotAll returns snapshots for all known informers
// This is useful for creating a consistent view across all resource types
func (c *btreeCacheImpl) SnapshotAll(ctx context.Context) (map[schema.GroupVersionKind]*btree.BTreeG[StoreItem], error) {
	// Note: controller-runtime doesn't expose a way to list all informers,
	// so this is a best-effort implementation that requires the user to
	// have already retrieved informers for the types they care about.
	//
	// In practice, you'll want to call Snapshot() for each type you're tracking.
	return nil, fmt.Errorf("SnapshotAll is not yet implemented - use Snapshot() for each type instead")
}

// SnapshotWithMetadata returns a snapshot with additional statistics
func (c *btreeCacheImpl) SnapshotWithMetadata(ctx context.Context, obj client.Object) (SnapshotMetadata, error) {
	// Get the informer for this object type
	informer, err := c.Cache.GetInformer(ctx, obj)
	if err != nil {
		return SnapshotMetadata{}, fmt.Errorf("failed to get informer: %w", err)
	}

	// The informer should be our btreeSharedIndexInformer wrapper
	if btreeInf, ok := informer.(*btreeSharedIndexInformer); ok {
		return btreeInf.btreeIdx.SnapshotWithMeta(), nil
	}

	return SnapshotMetadata{}, fmt.Errorf("informer does not use BTree indexer")
}
