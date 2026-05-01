package cache

// This file shows how to integrate the BTree cache with your existing main.go
// Copy these patterns into your actual code

/*

STEP 1: Update imports in main.go
----------------------------------

Add this import:
    btreecache "github.com/ajwdev/pallograph/pkg/controller-runtime/cache"


STEP 2: Modify manager creation
--------------------------------

Replace this:
    mgr, err := manager.New(config.GetConfigOrDie(), manager.Options{})

With this:
    mgr, err := manager.New(config.GetConfigOrDie(), manager.Options{
        NewCache: btreecache.NewBTreeCache,
    })


STEP 3: Access the cache with snapshot capability
--------------------------------------------------

After the manager is created, you can get the cache:

    // Get cache as BTreeCache interface
    cache := mgr.GetCache()

    // Start manager and wait for sync (important!)
    ctx := context.Background()
    go func() {
        if err := mgr.Start(signals.SetupSignalHandler()); err != nil {
            log.Error(err, "could not start manager")
            os.Exit(1)
        }
    }()

    // Wait for cache to populate
    if !cache.WaitForCacheSync(ctx) {
        log.Error(nil, "cache never synced")
        os.Exit(1)
    }


STEP 4: Take periodic snapshots
--------------------------------

Add this function to take periodic snapshots:

func periodicSnapshot(ctx context.Context, cache btreecache.BTreeCache) {
    ticker := time.NewTicker(5 * time.Minute)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            // Take snapshot of all pods
            snapshot, err := cache.Snapshot(ctx, &corev1.Pod{})
            if err != nil {
                log.Printf("Failed to snapshot pods: %v", err)
                continue
            }

            // Take snapshot of all replicasets
            rsSnapshot, err := cache.Snapshot(ctx, &appsv1.ReplicaSet{})
            if err != nil {
                log.Printf("Failed to snapshot replicasets: %v", err)
                continue
            }

            // Process snapshots (convert to Mangle facts, export, etc.)
            go processSnapshots(snapshot, rsSnapshot)

        case <-ctx.Done():
            return
        }
    }
}


STEP 5: Convert snapshots to Mangle facts
------------------------------------------

Here's how to convert a snapshot to Mangle facts:

func snapshotToFacts(snapshot *btree.BTreeG[btreecache.StoreItem], store factstore.SimpleInMemoryStore) error {
    snapshot.Ascend(func(item btreecache.StoreItem) bool {
        // Marshal to JSON
        data, err := json.Marshal(item.Object)
        if err != nil {
            log.Printf("Failed to marshal object: %v", err)
            return true
        }

        // Convert to map
        var m map[string]any
        if err := json.Unmarshal(data, &m); err != nil {
            log.Printf("Failed to unmarshal: %v", err)
            return true
        }

        // Remove nulls (Mangle requirement)
        removeNulls(m)

        // Convert to Mangle struct
        mangleStruct, err := json2struct.ConvertValue(m)
        if err != nil {
            log.Printf("Failed to convert to Mangle: %v", err)
            return true
        }

        // Create fact
        fact := ast.Atom{
            Predicate: ast.PredicateSym{Symbol: "k8s_object", Arity: 1},
            Args:      []ast.BaseTerm{mangleStruct},
        }

        // Add to store
        store.Add(fact)
        return true
    })

    return nil
}


COMPLETE EXAMPLE: Modified main.go
-----------------------------------

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/mangle/ast"
	"github.com/google/mangle/factstore"
	"github.com/google/mangle/json2struct"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"

	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/manager/signals"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	btreecache "github.com/ajwdev/pallograph/pkg/controller-runtime/cache"
)

func main() {
	logf.SetLogger(zap.New())
	log := logf.Log.WithName("pallograph")

	// Create manager with BTree cache
	mgr, err := manager.New(config.GetConfigOrDie(), manager.Options{
		NewCache: btreecache.NewBTreeCache,  // <-- Use BTree cache
	})
	if err != nil {
		log.Error(err, "could not create manager")
		os.Exit(1)
	}

	cl := mgr.GetClient()

	// Setup controller
	err = builder.
		ControllerManagedBy(mgr).
		For(&appsv1.ReplicaSet{}).
		Owns(&corev1.Pod{}, builder.OnlyMetadata).
		Complete(reconcile.Func(func(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
			rs := &appsv1.ReplicaSet{}
			err := cl.Get(ctx, req.NamespacedName, rs)
			if err != nil {
				return reconcile.Result{}, client.IgnoreNotFound(err)
			}

			var podsMeta metav1.PartialObjectMetadataList
			err = cl.List(ctx, &podsMeta, client.InNamespace(req.Namespace), client.MatchingLabels(rs.Spec.Template.Labels))
			if err != nil {
				return reconcile.Result{}, client.IgnoreNotFound(err)
			}

			rs.Labels["pod-count"] = fmt.Sprintf("%v", len(podsMeta.Items))
			err = cl.Update(ctx, rs)
			if err != nil {
				return reconcile.Result{}, err
			}

			return reconcile.Result{}, nil
		}))
	if err != nil {
		log.Error(err, "could not create controller")
		os.Exit(1)
	}

	// Get cache as BTreeCache for snapshot access
	cache := mgr.GetCache()

	// Start periodic snapshots in background
	ctx := context.Background()
	go periodicSnapshot(ctx, cache.(btreecache.BTreeCache), log)

	// Start manager
	if err := mgr.Start(signals.SetupSignalHandler()); err != nil {
		log.Error(err, "could not start manager")
		os.Exit(1)
	}
}

func periodicSnapshot(ctx context.Context, cache btreecache.BTreeCache, log logr.Logger) {
	// Wait for cache to sync first
	if !cache.WaitForCacheSync(ctx) {
		log.Error(nil, "cache never synced")
		return
	}

	log.Info("Cache synced, starting periodic snapshots")

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Take snapshots
			podSnapshot, err := cache.Snapshot(ctx, &corev1.Pod{})
			if err != nil {
				log.Error(err, "failed to snapshot pods")
				continue
			}

			rsSnapshot, err := cache.Snapshot(ctx, &appsv1.ReplicaSet{})
			if err != nil {
				log.Error(err, "failed to snapshot replicasets")
				continue
			}

			// Convert to Mangle facts
			store := factstore.NewSimpleInMemoryStore()

			log.Info("Processing pod snapshot", "count", podSnapshot.Len())
			snapshotToFacts(podSnapshot, store, "pod")

			log.Info("Processing replicaset snapshot", "count", rsSnapshot.Len())
			snapshotToFacts(rsSnapshot, store, "replicaset")

			log.Info("Snapshot complete", "total_facts", store.EstimateFactCount())

		case <-ctx.Done():
			return
		}
	}
}

func snapshotToFacts(snapshot *btree.BTreeG[btreecache.StoreItem], store factstore.SimpleInMemoryStore, predicateName string) {
	snapshot.Ascend(func(item btreecache.StoreItem) bool {
		data, err := json.Marshal(item.Object)
		if err != nil {
			return true
		}

		var m map[string]any
		if err := json.Unmarshal(data, &m); err != nil {
			return true
		}

		removeNulls(m)

		mangleStruct, err := json2struct.ConvertValue(m)
		if err != nil {
			return true
		}

		fact := ast.Atom{
			Predicate: ast.PredicateSym{Symbol: predicateName, Arity: 1},
			Args:      []ast.BaseTerm{mangleStruct},
		}

		store.Add(fact)
		return true
	})
}

// removeNulls recursively removes null values from JSON data
func removeNulls(data map[string]any) {
	for k, v := range data {
		if v == nil {
			delete(data, k)
			continue
		}
		switch val := v.(type) {
		case map[string]any:
			removeNulls(val)
		case []any:
			for _, item := range val {
				if m, ok := item.(map[string]any); ok {
					removeNulls(m)
				}
			}
		}
	}
}

*/
