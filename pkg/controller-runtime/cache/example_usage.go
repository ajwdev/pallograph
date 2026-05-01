package cache

// This file provides example usage patterns for the BTree cache
// It is not compiled - it's just for documentation purposes

/*

Example 1: Basic Usage with Manager
------------------------------------

import (
	"context"
	"time"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	btreecache "github.com/ajwdev/pallograph/pkg/controller-runtime/cache"
)

func main() {
	cfg := config.GetConfigOrDie()

	// Create manager with BTree cache
	mgr, err := manager.New(cfg, manager.Options{
		NewCache: btreecache.NewBTreeCache,
	})
	if err != nil {
		panic(err)
	}

	// Get the cache (it will be a BTreeCache)
	cache := mgr.GetCache().(btreecache.BTreeCache)

	// Start the manager
	ctx := context.Background()
	go mgr.Start(ctx)

	// Wait for cache to sync
	mgr.GetCache().WaitForCacheSync(ctx)

	// Take a snapshot of all pods
	snapshot, err := cache.Snapshot(ctx, &corev1.Pod{})
	if err != nil {
		panic(err)
	}

	// Iterate over the snapshot (won't be affected by future updates)
	snapshot.Ascend(func(item btreecache.StoreItem) bool {
		pod := item.Object.(*corev1.Pod)
		fmt.Printf("Pod: %s/%s\n", pod.Namespace, pod.Name)
		return true
	})
}


Example 2: Periodic Snapshots
------------------------------

import (
	"context"
	"time"

	corev1 "k8s.io/api/core/v1"
)

func periodicSnapshot(ctx context.Context, cache btreecache.BTreeCache) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Take atomic snapshot
			snapshot, err := cache.Snapshot(ctx, &corev1.Pod{})
			if err != nil {
				log.Printf("Snapshot failed: %v", err)
				continue
			}

			// Process snapshot asynchronously
			go processSnapshot(snapshot)

		case <-ctx.Done():
			return
		}
	}
}

func processSnapshot(snapshot *btree.BTreeG[btreecache.StoreItem]) {
	// This snapshot is immutable - process it without locks
	count := 0
	snapshot.Ascend(func(item btreecache.StoreItem) bool {
		count++
		// Convert to facts, export to storage, etc.
		return true
	})
	log.Printf("Processed snapshot with %d items", count)
}


Example 3: Snapshot Comparison / Diff
--------------------------------------

import (
	"fmt"
)

func compareSnapshots(old, new *btree.BTreeG[btreecache.StoreItem]) {
	added := make(map[string]bool)
	modified := make(map[string]bool)
	deleted := make(map[string]bool)

	// Mark all old items as potentially deleted
	old.Ascend(func(item btreecache.StoreItem) bool {
		deleted[item.Key] = true
		return true
	})

	// Check new items
	new.Ascend(func(item btreecache.StoreItem) bool {
		if _, exists := deleted[item.Key]; exists {
			// Item exists in both - might be modified
			delete(deleted, item.Key)

			// Compare old vs new to detect modifications
			if oldItem, ok := old.Get(item); ok {
				if !reflect.DeepEqual(oldItem.Object, item.Object) {
					modified[item.Key] = true
				}
			}
		} else {
			// Item only in new - was added
			added[item.Key] = true
		}
		return true
	})

	fmt.Printf("Added: %d, Modified: %d, Deleted: %d\n",
		len(added), len(modified), len(deleted))
}


Example 4: Mangle FactStore Integration
----------------------------------------

import (
	"github.com/google/mangle/ast"
	"github.com/google/mangle/factstore"
	"github.com/google/mangle/json2struct"
	"encoding/json"
)

type BTreeFactStore struct {
	cache btreecache.BTreeCache
}

func (f *BTreeFactStore) GetFacts(ctx context.Context, obj client.Object, callback func(ast.Atom) error) error {
	// Get snapshot
	snapshot, err := f.cache.Snapshot(ctx, obj)
	if err != nil {
		return err
	}

	// Convert each object to a Mangle fact
	var lastErr error
	snapshot.Ascend(func(item btreecache.StoreItem) bool {
		// Serialize object to JSON
		data, err := json.Marshal(item.Object)
		if err != nil {
			lastErr = err
			return false
		}

		// Convert to map
		var m map[string]any
		if err := json.Unmarshal(data, &m); err != nil {
			lastErr = err
			return false
		}

		// Convert to Mangle struct
		mangleStruct, err := json2struct.ConvertValue(m)
		if err != nil {
			lastErr = err
			return false
		}

		// Create fact
		fact := ast.Atom{
			Predicate: ast.PredicateSym{Symbol: "k8s_object", Arity: 1},
			Args:      []ast.BaseTerm{mangleStruct},
		}

		// Call callback
		if err := callback(fact); err != nil {
			lastErr = err
			return false
		}

		return true
	})

	return lastErr
}


Example 5: Ordered Range Queries
---------------------------------

import (
	"strings"
)

// Get all pods in a specific namespace (efficiently using BTree ordering)
func getPodsInNamespace(snapshot *btree.BTreeG[btreecache.StoreItem], namespace string) []corev1.Pod {
	var pods []corev1.Pod

	// BTree is ordered by key (namespace/name), so we can use range iteration
	startKey := namespace + "/"
	endKey := namespace + "0" // '0' is after '/'

	snapshot.AscendRange(
		btreecache.StoreItem{Key: startKey},
		btreecache.StoreItem{Key: endKey},
		func(item btreecache.StoreItem) bool {
			if pod, ok := item.Object.(*corev1.Pod); ok {
				if pod.Namespace == namespace {
					pods = append(pods, *pod)
				}
			}
			return true
		},
	)

	return pods
}

*/
