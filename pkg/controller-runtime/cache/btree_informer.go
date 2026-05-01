package cache

import (
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/cache"
)

// btreeSharedIndexInformer wraps a standard SharedIndexInformer but exposes
// our custom BTree indexer for snapshot access
type btreeSharedIndexInformer struct {
	cache.SharedIndexInformer
	btreeIdx *btreeIndexer
}

// NewBTreeInformer creates a SharedIndexInformer using a BTree-backed indexer
// instead of the default hashmap-based storage. This allows for:
// - Ordered iteration over cached objects
// - Atomic snapshots via BTree.Clone()
// - Memory-efficient point-in-time copies
//
// This function is intended to be passed as cache.Options.NewInformer to
// controller-runtime's cache.New() function.
//
// NOTE: Due to client-go limitations, this creates a standard informer
// and syncs changes to a BTree in parallel. While this duplicates data,
// it provides the snapshot functionality you need while maintaining
// compatibility with controller-runtime.
func NewBTreeInformer(
	lw cache.ListerWatcher,
	objType runtime.Object,
	resyncPeriod time.Duration,
	indexers cache.Indexers,
) cache.SharedIndexInformer {
	// Create standard informer with standard storage
	standardInformer := cache.NewSharedIndexInformer(
		lw,
		objType,
		resyncPeriod,
		indexers,
	)

	// Create our BTree indexer
	btreeIdx := NewBTreeIndexer(cache.MetaNamespaceKeyFunc, indexers)

	// Add event handlers to sync to BTree
	standardInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			btreeIdx.Add(obj)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			btreeIdx.Update(newObj)
		},
		DeleteFunc: func(obj interface{}) {
			btreeIdx.Delete(obj)
		},
	})

	// Wrap the informer to expose our BTree indexer
	return &btreeSharedIndexInformer{
		SharedIndexInformer: standardInformer,
		btreeIdx:            btreeIdx.(*btreeIndexer),
	}
}

// GetBTreeIndexer extracts the btreeIndexer from a SharedIndexInformer
// Returns nil if the informer doesn't use a BTree indexer
func GetBTreeIndexer(informer cache.SharedIndexInformer) *btreeIndexer {
	// Check if it's our wrapper type
	if btreeInf, ok := informer.(*btreeSharedIndexInformer); ok {
		return btreeInf.btreeIdx
	}

	// Otherwise try to get from the indexer (won't work with standard informers)
	indexer := informer.GetIndexer()
	if btreeIdx, ok := indexer.(*btreeIndexer); ok {
		return btreeIdx
	}

	return nil
}
