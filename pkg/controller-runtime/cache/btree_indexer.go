package cache

import (
	"fmt"
	"sync"

	"github.com/google/btree"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/client-go/tools/cache"
)

// StoreItem represents an item stored in the BTree with its key
type StoreItem struct {
	Key    string
	Object interface{}
}

// Less implements the comparison for BTree ordering
// Items are ordered by their key (namespace/name)
func (a StoreItem) Less(b StoreItem) bool {
	return a.Key < b.Key
}

// btreeIndexer implements cache.Indexer using a BTree as the underlying storage.
// This allows for ordered iteration and atomic snapshots via Clone().
type btreeIndexer struct {
	// BTree storage - sorted by key
	tree *btree.BTreeG[StoreItem]

	// Key function to extract object key
	keyFunc cache.KeyFunc

	// Indexers maps index name to index function
	indexers cache.Indexers

	// indices maps index name -> index value -> set of object keys
	// Example: "namespace" -> "default" -> {"pod1", "pod2", "pod3"}
	indices map[string]map[string]map[string]struct{}

	mu sync.RWMutex
}

// lessFunc is the comparison function for BTree ordering
func lessFunc(a, b StoreItem) bool {
	return a.Less(b)
}

// NewBTreeIndexer creates a new BTree-backed indexer
func NewBTreeIndexer(keyFunc cache.KeyFunc, indexers cache.Indexers) cache.Indexer {
	return &btreeIndexer{
		tree:     btree.NewG[StoreItem](32, lessFunc), // degree 32 is a reasonable default
		keyFunc:  keyFunc,
		indexers: indexers,
		indices:  make(map[string]map[string]map[string]struct{}),
	}
}

// Add inserts an object into the store
func (b *btreeIndexer) Add(obj interface{}) error {
	key, err := b.keyFunc(obj)
	if err != nil {
		return cache.KeyError{Obj: obj, Err: err}
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	// Add to BTree
	item := StoreItem{Key: key, Object: obj}
	b.tree.ReplaceOrInsert(item)

	// Update indices
	b.updateIndices(nil, obj, key)

	return nil
}

// Update modifies an existing object in the store
func (b *btreeIndexer) Update(obj interface{}) error {
	key, err := b.keyFunc(obj)
	if err != nil {
		return cache.KeyError{Obj: obj, Err: err}
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	// Get old object if it exists
	var oldObj interface{}
	if old, ok := b.tree.Get(StoreItem{Key: key}); ok {
		oldObj = old.Object
	}

	// Update in BTree
	item := StoreItem{Key: key, Object: obj}
	b.tree.ReplaceOrInsert(item)

	// Update indices
	b.updateIndices(oldObj, obj, key)

	return nil
}

// Delete removes an object from the store
func (b *btreeIndexer) Delete(obj interface{}) error {
	key, err := b.keyFunc(obj)
	if err != nil {
		return cache.KeyError{Obj: obj, Err: err}
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	// Remove from BTree
	item := StoreItem{Key: key}
	if old, ok := b.tree.Delete(item); ok {
		// Remove from indices
		b.updateIndices(old.Object, nil, key)
	}

	return nil
}

// Get retrieves an object by its key
func (b *btreeIndexer) Get(obj interface{}) (item interface{}, exists bool, err error) {
	key, err := b.keyFunc(obj)
	if err != nil {
		return nil, false, cache.KeyError{Obj: obj, Err: err}
	}
	return b.GetByKey(key)
}

// GetByKey retrieves an object by its string key
func (b *btreeIndexer) GetByKey(key string) (item interface{}, exists bool, err error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if found, ok := b.tree.Get(StoreItem{Key: key}); ok {
		return found.Object, true, nil
	}
	return nil, false, nil
}

// List returns all objects in the store
func (b *btreeIndexer) List() []interface{} {
	b.mu.RLock()
	defer b.mu.RUnlock()

	result := make([]interface{}, 0, b.tree.Len())
	b.tree.Ascend(func(item StoreItem) bool {
		result = append(result, item.Object)
		return true
	})
	return result
}

// ListKeys returns all keys in the store
func (b *btreeIndexer) ListKeys() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()

	result := make([]string, 0, b.tree.Len())
	b.tree.Ascend(func(item StoreItem) bool {
		result = append(result, item.Key)
		return true
	})
	return result
}

// Replace clears the store and replaces with the given list
func (b *btreeIndexer) Replace(list []interface{}, resourceVersion string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Clear existing data
	b.tree.Clear(true)
	b.indices = make(map[string]map[string]map[string]struct{})

	// Add all new items
	for _, obj := range list {
		key, err := b.keyFunc(obj)
		if err != nil {
			return cache.KeyError{Obj: obj, Err: err}
		}

		item := StoreItem{Key: key, Object: obj}
		b.tree.ReplaceOrInsert(item)
		b.updateIndices(nil, obj, key)
	}

	return nil
}

// Resync is a no-op for this implementation
func (b *btreeIndexer) Resync() error {
	return nil
}

// Index returns objects that match the given index name and value
func (b *btreeIndexer) Index(indexName string, obj interface{}) ([]interface{}, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	indexFunc, ok := b.indexers[indexName]
	if !ok {
		return nil, fmt.Errorf("index %q does not exist", indexName)
	}

	indexValues, err := indexFunc(obj)
	if err != nil {
		return nil, err
	}

	// Collect all objects matching any of the index values
	var result []interface{}
	for _, indexValue := range indexValues {
		if keys, ok := b.indices[indexName][indexValue]; ok {
			for key := range keys {
				if item, ok := b.tree.Get(StoreItem{Key: key}); ok {
					result = append(result, item.Object)
				}
			}
		}
	}

	return result, nil
}

// IndexKeys returns object keys that match the given index name and value
func (b *btreeIndexer) IndexKeys(indexName, indexedValue string) ([]string, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if _, ok := b.indexers[indexName]; !ok {
		return nil, fmt.Errorf("index %q does not exist", indexName)
	}

	keys := b.indices[indexName][indexedValue]
	result := make([]string, 0, len(keys))
	for key := range keys {
		result = append(result, key)
	}
	return result, nil
}

// ListIndexFuncValues returns all values for a given index
func (b *btreeIndexer) ListIndexFuncValues(indexName string) []string {
	b.mu.RLock()
	defer b.mu.RUnlock()

	indexValues := b.indices[indexName]
	result := make([]string, 0, len(indexValues))
	for val := range indexValues {
		result = append(result, val)
	}
	return result
}

// ByIndex returns objects for a given index name and value
func (b *btreeIndexer) ByIndex(indexName, indexedValue string) ([]interface{}, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if _, ok := b.indexers[indexName]; !ok {
		return nil, fmt.Errorf("index %q does not exist", indexName)
	}

	var result []interface{}
	if keys, ok := b.indices[indexName][indexedValue]; ok {
		result = make([]interface{}, 0, len(keys))
		for key := range keys {
			if item, ok := b.tree.Get(StoreItem{Key: key}); ok {
				result = append(result, item.Object)
			}
		}
	}

	return result, nil
}

// GetIndexers returns the indexers
func (b *btreeIndexer) GetIndexers() cache.Indexers {
	return b.indexers
}

// AddIndexers adds more indexers to the store
func (b *btreeIndexer) AddIndexers(newIndexers cache.Indexers) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.tree.Len() > 0 {
		return fmt.Errorf("cannot add indexers after data is added")
	}

	for name, indexFunc := range newIndexers {
		b.indexers[name] = indexFunc
	}
	return nil
}

// updateIndices updates the index when an object is added, updated, or deleted
// oldObj and newObj can be nil for add and delete operations
func (b *btreeIndexer) updateIndices(oldObj, newObj interface{}, key string) {
	// Remove old index entries
	if oldObj != nil {
		for indexName, indexFunc := range b.indexers {
			indexValues, err := indexFunc(oldObj)
			if err != nil {
				continue
			}
			for _, indexValue := range indexValues {
				if b.indices[indexName] != nil && b.indices[indexName][indexValue] != nil {
					delete(b.indices[indexName][indexValue], key)
				}
			}
		}
	}

	// Add new index entries
	if newObj != nil {
		for indexName, indexFunc := range b.indexers {
			indexValues, err := indexFunc(newObj)
			if err != nil {
				continue
			}
			for _, indexValue := range indexValues {
				if b.indices[indexName] == nil {
					b.indices[indexName] = make(map[string]map[string]struct{})
				}
				if b.indices[indexName][indexValue] == nil {
					b.indices[indexName][indexValue] = make(map[string]struct{})
				}
				b.indices[indexName][indexValue][key] = struct{}{}
			}
		}
	}
}

// Snapshot returns an atomic point-in-time snapshot of the BTree
// The returned BTree is a clone and can be read without affecting the original
func (b *btreeIndexer) Snapshot() *btree.BTreeG[StoreItem] {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.tree.Clone()
}

// SnapshotWithMetadata returns a snapshot along with metadata about what's stored
type SnapshotMetadata struct {
	Tree       *btree.BTreeG[StoreItem]
	TotalItems int
	Namespaces map[string]int // namespace -> count
}

// SnapshotWithMeta returns a snapshot with additional metadata
func (b *btreeIndexer) SnapshotWithMeta() SnapshotMetadata {
	b.mu.RLock()
	defer b.mu.RUnlock()

	result := SnapshotMetadata{
		Tree:       b.tree.Clone(),
		TotalItems: b.tree.Len(),
		Namespaces: make(map[string]int),
	}

	// Count items per namespace
	b.tree.Ascend(func(item StoreItem) bool {
		if obj, ok := item.Object.(interface{}); ok {
			if accessor, err := meta.Accessor(obj); err == nil {
				ns := accessor.GetNamespace()
				if ns == "" {
					ns = "<cluster-scoped>"
				}
				result.Namespaces[ns]++
			}
		}
		return true
	})

	return result
}
