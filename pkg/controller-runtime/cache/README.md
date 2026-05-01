# BTree-Backed Controller-Runtime Cache

This package provides a drop-in replacement for controller-runtime's cache that uses Google's `btree` package instead of hashmaps for storage.

## Why BTree?

**Benefits:**
- **Ordered Iteration**: Objects are stored in sorted order by namespace/name
- **Atomic Snapshots**: `Clone()` provides O(1) copy-on-write snapshots
- **Range Queries**: Efficient lookups by namespace or key prefix
- **Safe Concurrent Access**: Snapshots are immutable copies

**Tradeoffs:**
- **Data Duplication**: Due to client-go's architecture, data is stored in both the standard cache AND the BTree. This is unavoidable because client-go's `NewSharedIndexInformer` doesn't support custom storage backends.
- O(log n) lookups vs O(1) for hashmaps (usually negligible in practice)
- Slightly higher memory overhead for tree structure

## Important Note on Data Duplication

After investigating client-go's architecture, we found that it's **not possible** to replace the underlying storage mechanism in `SharedIndexInformer` without forking client-go. The constructors (`NewSharedIndexInformer`, etc.) create their own internal storage and don't expose hooks for custom implementations.

**Our Solution:**
- We create a standard informer with standard hashmap storage
- We add event handlers that sync all changes to a parallel BTree
- This duplicates data, BUT provides atomic snapshot capability
- The memory overhead is the cost of snapshot functionality

**Why This Is Acceptable:**
- Kubernetes objects are typically small (few KB each)
- The BTree uses copy-on-write, so snapshots themselves are cheap
- You get atomic, consistent snapshots without locking the main cache
- Alternative approaches (custom cache, forking client-go) are much more complex

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Manager                                                    │
│  ┌───────────────────────────────────────────────────────┐ │
│  │  BTreeCache (btree_cache.go)                          │ │
│  │  ┌─────────────────────────────────────────────────┐  │ │
│  │  │  btreeSharedIndexInformer (wrapper)             │  │ │
│  │  │  ┌─────────────────────┐  ┌─────────────────┐  │  │ │
│  │  │  │ Standard Informer   │  │ BTree Indexer   │  │  │ │
│  │  │  │ ┌─────────────────┐ │  │ (snapshot-able) │  │  │ │
│  │  │  │ │ Hashmap Store   │ │  │                 │  │  │ │
│  │  │  │ │ (standard cache)│ │  │ google/btree    │  │  │ │
│  │  │  │ └─────────────────┘ │  │ - Clone() O(1)  │  │  │ │
│  │  │  └──────────┬──────────┘  └─────────────────┘  │  │ │
│  │  │             │                      ▲           │  │ │
│  │  │             │  Event Handlers      │           │  │ │
│  │  │             │  (Add/Update/Delete) │           │  │ │
│  │  │             └──────────────────────┘           │  │ │
│  │  │                                                │  │ │
│  │  │  Data is duplicated to enable snapshots       │  │ │
│  │  └─────────────────────────────────────────────────┘  │ │
│  └───────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

The informer maintains data in TWO places:
1. **Standard hashmap cache** - Used by controller-runtime for normal operations
2. **BTree** - Synced via event handlers, provides snapshot capability

## Components

### 1. `btree_indexer.go`
Implements `cache.Indexer` interface using BTree storage:
- Stores objects in a `btree.BTreeG[StoreItem]`
- Maintains secondary indices for namespace lookups, etc.
- Provides `Snapshot()` method for atomic clones

### 2. `btree_informer.go`
Wrapper for SharedIndexInformer that adds BTree snapshot capability:
- `NewBTreeInformer()` - Creates standard informer + parallel BTree with event handlers
- `btreeSharedIndexInformer` - Wrapper that exposes both standard and BTree storage
- `GetBTreeIndexer()` - Extracts BTree indexer from wrapped informer

### 3. `btree_cache.go`
High-level cache wrapper:
- `NewBTreeCache()` - Creates cache with BTree storage
- `Snapshot()` - Gets atomic snapshot for a resource type
- Compatible with controller-runtime's `Cache` interface

### 4. `example_usage.go`
Usage examples showing:
- Manager setup
- Periodic snapshots
- Snapshot comparison
- Mangle integration
- Range queries

## Usage

### Basic Setup

```go
import (
    "sigs.k8s.io/controller-runtime/pkg/manager"
    btreecache "github.com/ajwdev/pallograph/pkg/controller-runtime/cache"
)

mgr, err := manager.New(cfg, manager.Options{
    NewCache: btreecache.NewBTreeCache,
})
```

### Taking Snapshots

```go
cache := mgr.GetCache().(btreecache.BTreeCache)

// Take atomic snapshot
snapshot, err := cache.Snapshot(ctx, &corev1.Pod{})

// Iterate over snapshot (immutable, won't change)
snapshot.Ascend(func(item btreecache.StoreItem) bool {
    pod := item.Object.(*corev1.Pod)
    fmt.Printf("Pod: %s/%s\n", pod.Namespace, pod.Name)
    return true
})
```

### Periodic Snapshots

```go
ticker := time.NewTicker(5 * time.Minute)
for range ticker.C {
    snapshot, _ := cache.Snapshot(ctx, &corev1.Pod{})

    // Process snapshot in background
    go processSnapshot(snapshot)
}
```

## Implementation Details

### How It Works

1. **Manager Creation**: Pass `NewBTreeCache` as `manager.Options.NewCache`
2. **Cache Creation**: `NewBTreeCache()` sets `cache.Options.NewInformer = NewBTreeInformer`
3. **Informer Creation**: When cache needs an informer, it calls `NewBTreeInformer()` which:
   - Creates a standard `SharedIndexInformer` with normal hashmap storage
   - Creates a parallel `btreeIndexer` for snapshots
   - Registers event handlers to sync changes from standard -> BTree
   - Wraps both in `btreeSharedIndexInformer`
4. **Normal Operations**: Use standard hashmap cache (fast O(1) lookups)
5. **Snapshots**: Access BTree via `Snapshot()` for atomic point-in-time copies

### Key Interface: cache.Indexer

The `btreeIndexer` implements client-go's `cache.Indexer` interface:
- `Add/Update/Delete` - Modify BTree
- `Get/List` - Query BTree
- `Index/ByIndex` - Secondary index lookups
- `Replace` - Bulk updates

Plus our custom method:
- `Snapshot()` - Returns `BTree.Clone()`

### Memory Usage

**Data Duplication:**
- Objects are stored in BOTH the standard cache AND the BTree
- This is necessary due to client-go architecture limitations
- Memory overhead = ~2x the object storage

**Efficient Snapshots:**
- `BTree.Clone()` is O(1) and uses copy-on-write
- Snapshots share tree structure with the main tree
- Only modified nodes are duplicated when tree changes
- Multiple snapshots can coexist efficiently

## Integration with Mangle

See `example_usage.go` for a complete example of converting BTree snapshots to Mangle facts.

Basic pattern:
```go
snapshot, _ := cache.Snapshot(ctx, &corev1.Pod{})
snapshot.Ascend(func(item btreecache.StoreItem) bool {
    // Convert item.Object to Mangle fact
    fact := convertToFact(item.Object)
    store.Add(fact)
    return true
})
```

## Testing

To verify the BTree cache works correctly:

1. Create a manager with `NewBTreeCache`
2. Start the manager and wait for cache sync
3. Take a snapshot
4. Verify snapshot contains expected objects
5. Modify cluster state
6. Take another snapshot
7. Compare snapshots to see changes

## Future Enhancements

Possible improvements:
- [ ] SnapshotAll() for multi-type atomic snapshots
- [ ] Snapshot metadata (counts, namespaces, etc.)
- [ ] Incremental diffs between snapshots
- [ ] Export snapshots to disk
- [ ] Snapshot versioning/history
