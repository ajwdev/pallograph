# Custom Informer Implementation Notes

This document captures research and planning for potentially replacing the current "piggyback" approach (wrapping `SharedIndexInformer` and mirroring to btree) with a fully custom informer that uses the btree as its sole storage backend.

## Current Architecture

```
SharedIndexInformer (hashmap-based)
    │
    ├── Event Handlers ──► btreeIndexer (duplicate storage)
    │
    └── Standard Indexer (hashmap)
```

**Problem**: Data is stored twice - once in the standard hashmap cache and once in the btree. This is unavoidable because `NewSharedIndexInformer` doesn't expose custom storage hooks.

## Target Architecture

```
Custom Informer
    │
    ├── Reflector (reuse from client-go)
    │
    ├── DeltaFIFO (reuse from client-go)
    │
    └── btreeIndexer (single storage) ──► Event Handlers
```

## Upstream KEP Status

As of February 2025, there is **no KEP** for making `ThreadSafeStore` pluggable in client-go. Related discussions:

- [Kyverno #1832](https://github.com/kyverno/kyverno/issues/1832) - Custom informer cache for memory reduction
- [SIG API Machinery discussion](https://groups.google.com/g/kubernetes-sig-api-machinery/c/rxQO8lIo6kg) - Disk-based informer caching
- [kubernetes/kubernetes#91436](https://github.com/kubernetes/kubernetes/issues/91436) - Sharing custom indexers (merged, but about sharing not pluggability)

### What Would Need to Change Upstream

1. Add `ThreadSafeStore` option to `SharedIndexInformerOptions`
2. Modify `NewSharedIndexInformerWithOptions` to accept custom store
3. Or add `NewIndexerWithStore(keyFunc, store)` constructor

Challenges for upstream acceptance:
- API surface increase
- Behavioral contract guarantees for custom implementations
- Testing burden
- Need to demonstrate measurable benefits

## What We Already Have

| Component | Status | Location |
|-----------|--------|----------|
| `btreeIndexer` (implements `cache.Indexer`) | ✅ Complete | `pkg/controller-runtime/cache/btree_indexer.go` |
| Key extraction, secondary indices | ✅ Complete | `pkg/controller-runtime/cache/btree_indexer.go` |
| Snapshot capability | ✅ Complete | `pkg/controller-runtime/cache/btree_indexer.go` |
| Event handler logic | ✅ Complete | `pkg/controller-runtime/cache/btree_informer.go` (in wrapper) |

## Components to Build

### 1. DeltaFIFO Integration (Easy)

The `DeltaFIFO` already accepts a `KnownObjects` parameter:

```go
fifo := cache.NewDeltaFIFOWithOptions(cache.DeltaFIFOOptions{
    KnownObjects:          btreeIdx,  // Your btreeIndexer
    KeyFunction:           cache.MetaNamespaceKeyFunc,
    EmitDeltaTypeReplaced: true,
})
```

### 2. Reflector (Easy - reuse as-is)

```go
r := cache.NewReflector(
    listerWatcher,    // Your ListerWatcher
    &corev1.Pod{},    // Example object
    fifo,             // DeltaFIFO from above
    resyncPeriod,
)
```

### 3. Process Loop (Medium)

```go
func (s *btreeInformer) Run(stopCh <-chan struct{}) {
    // Start reflector in background
    go s.reflector.Run(stopCh)

    // Process loop
    wait.Until(func() {
        for {
            _, err := s.fifo.Pop(func(obj interface{}, isInInitialList bool) error {
                deltas := obj.(cache.Deltas)
                return s.handleDeltas(deltas)
            })
            if err != nil {
                if err == cache.ErrFIFOClosed {
                    return
                }
                // Handle error
            }
        }
    }, time.Second, stopCh)
}

func (s *btreeInformer) handleDeltas(deltas cache.Deltas) error {
    for _, d := range deltas {
        switch d.Type {
        case cache.Added, cache.Replaced:
            s.btreeIdx.Add(d.Object)
            s.processor.distribute(addNotification{newObj: d.Object})
        case cache.Updated:
            old, exists, _ := s.btreeIdx.Get(d.Object)
            s.btreeIdx.Update(d.Object)
            if exists {
                s.processor.distribute(updateNotification{oldObj: old, newObj: d.Object})
            }
        case cache.Deleted:
            s.btreeIdx.Delete(d.Object)
            s.processor.distribute(deleteNotification{oldObj: d.Object})
        }
    }
    return nil
}
```

### 4. Event Handler Distribution (Medium, ~150 lines)

```go
type sharedProcessor struct {
    listeners []*processorListener
    mu        sync.RWMutex
}

func (p *sharedProcessor) addListener(handler cache.ResourceEventHandler) {
    listener := &processorListener{
        handler:   handler,
        pendingCh: make(chan interface{}, 1000),
    }
    p.mu.Lock()
    p.listeners = append(p.listeners, listener)
    p.mu.Unlock()
    go listener.run() // Each listener has its own goroutine
}

func (p *sharedProcessor) distribute(notification interface{}) {
    p.mu.RLock()
    defer p.mu.RUnlock()
    for _, l := range p.listeners {
        l.add(notification)
    }
}
```

### 5. HasSynced / WaitForCacheSync (Easy)

```go
func (s *btreeInformer) HasSynced() bool {
    return s.fifo.HasSynced()
}
```

## Estimated New Code

| Component | Lines | Difficulty |
|-----------|-------|------------|
| Core informer struct + Run loop | ~100 | Easy |
| Delta handling | ~50 | Easy |
| Event processor + listeners | ~150 | Medium |
| Resync logic | ~30 | Easy |
| HasSynced/Started plumbing | ~20 | Easy |
| **Total new code** | **~350** | |

## Reusable client-go Components

These can be used directly without modification:

- `cache.DeltaFIFO` - Queue for buffering changes
- `cache.Reflector` - Handles list/watch against API server
- `cache.ListerWatcher` - Interface for list/watch operations
- `cache.MetaNamespaceKeyFunc` - Standard key extraction
- `cache.Deltas` - Delta types (Added, Updated, Deleted, Replaced, Sync)

## Trade-offs

| Approach | Pros | Cons |
|----------|------|------|
| **Current (wrapper)** | Works now, less code to maintain | 2x memory, slight event latency |
| **Custom informer** | Single storage, cleaner architecture | More code to maintain, need to track upstream changes |

## References

- [client-go cache package](https://pkg.go.dev/k8s.io/client-go/tools/cache)
- [client-go shared_informer.go](https://github.com/kubernetes/client-go/blob/master/tools/cache/shared_informer.go)
- [client-go thread_safe_store.go](https://github.com/kubernetes/client-go/blob/master/tools/cache/thread_safe_store.go)
- [client-go store.go](https://github.com/kubernetes/client-go/blob/master/tools/cache/store.go)

## Next Steps

1. Decide if memory savings justify the maintenance burden
2. If proceeding, start with a minimal implementation for a single resource type
3. Add tests comparing behavior with standard `SharedIndexInformer`
4. Integrate with controller-runtime's `Cache` interface
