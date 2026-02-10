package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/google/mangle/ast"
	"github.com/google/mangle/factstore"
	"github.com/google/mangle/interpreter"
	"github.com/google/mangle/json2struct"
)

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

// loadK8sObjects reads a JSON-lines file of Kubernetes objects and adds them as k8s/5 facts
func loadK8sObjects(store factstore.SimpleInMemoryStore, filename string) (int, error) {
	fd, err := os.Open(filename)
	if err != nil {
		return 0, fmt.Errorf("failed to open file %s: %w", filename, err)
	}
	defer fd.Close()

	var count int
	rdr := bufio.NewReader(fd)
	dec := json.NewDecoder(rdr)
	for {
		var m map[string]any
		err := dec.Decode(&m)
		if err == io.EOF {
			break
		}
		if err != nil {
			return count, err
		}

		// Remove null values recursively as apparently Mangle can't handle them
		removeNulls(m)

		mangleStruct, err := json2struct.ConvertValue(m)
		if err != nil {
			return count, err
		}

		// Extract TypeMeta (apiVersion, kind) and ObjectMeta (namespace, name)
		apiVersion := m["apiVersion"].(string)
		kind := m["kind"].(string)
		metadata := m["metadata"].(map[string]any)
		namespace, _ := metadata["namespace"].(string) // may be empty for cluster-scoped
		name := metadata["name"].(string)

		// Create a k8s/5 fact: k8s(ApiVersion, Kind, Namespace, Name, Data)
		fact := ast.Atom{
			Predicate: ast.PredicateSym{Symbol: "k8s", Arity: 5},
			Args: []ast.BaseTerm{
				ast.String(apiVersion),
				ast.String(kind),
				ast.String(namespace),
				ast.String(name),
				mangleStruct,
			},
		}

		store.Add(fact)
		count++
		fmt.Printf("Inserted %s/%s: %s/%s\n", apiVersion, kind, namespace, name)
	}
	return count, nil
}

func main() {
	store := factstore.NewSimpleInMemoryStore()

	// Load all Kubernetes objects into a single k8s/5 predicate
	files := []string{"allpods.json", "serviceaccounts.json"}
	var totalCount int
	for _, f := range files {
		count, err := loadK8sObjects(store, f)
		if err != nil {
			log.Fatal(err)
		}
		totalCount += count
	}
	fmt.Printf("\nLoaded %d total Kubernetes objects\n", totalCount)
	fmt.Printf("Predicates: %v\n", store.ListPredicates())

	// Create an interpreter for running queries
	interp := interpreter.New(os.Stdout, ".", nil)

	// Preload our fact store into the interpreter
	// Only need to declare the base k8s/5 predicate
	knownPredicates := map[ast.PredicateSym]ast.Decl{
		{Symbol: "k8s", Arity: 5}: {DeclaredAtom: ast.Atom{Predicate: ast.PredicateSym{Symbol: "k8s", Arity: 5}}},
	}
	if err := interp.Preload(nil, store, knownPredicates); err != nil {
		log.Fatalf("failed to preload: %v", err)
	}

	// Define all rules at once
	fmt.Println("\n=== Defining rules ===")
	err := interp.Define(`
		# Convenience predicates derived from the base k8s/5 predicate
		pod(Namespace, Name, Data) :-
			k8s("v1", "Pod", Namespace, Name, Data).

		serviceaccount(Namespace, Name, Data) :-
			k8s("v1", "ServiceAccount", Namespace, Name, Data).

		# Extract serviceAccountName from pods
		pod_sa(Namespace, PodName, SAName) :-
			pod(Namespace, PodName, Data),
			:match_field(Data, /spec, Spec),
			:match_field(Spec, /serviceAccountName, SAName).

		# Join pods with existing service accounts
		pod_with_sa(Namespace, PodName, SAName) :-
			pod(Namespace, PodName, Data),
			:match_field(Data, /spec, Spec),
			:match_field(Spec, /serviceAccountName, SAName),
			serviceaccount(Namespace, SAName, _).

		# Extract container images
		pod_image(Namespace, PodName, Image) :-
			pod(Namespace, PodName, Data),
			:match_field(Data, /spec, Spec),
			:match_field(Spec, /containers, Containers),
			:list:member(Container, Containers),
			:match_field(Container, /image, Image).

		# Find all objects in a namespace (demonstrates generic querying)
		objects_in_ns(Namespace, Kind, Name) :-
			k8s(_, Kind, Namespace, Name, _).

		# Service accounts that ARE used by pods (helper for orphaned check)
		sa_in_use(Namespace, SAName) :-
			pod_sa(Namespace, _, SAName).

		# Find orphaned service accounts (no pod references them)
		# Uses stratified negation - sa_in_use must be computed first
		orphaned_sa(Namespace, SAName) :-
			serviceaccount(Namespace, SAName, _),
			!sa_in_use(Namespace, SAName).
	`)
	if err != nil {
		log.Printf("Define error: %v", err)
	}

	// Query 1: All pods using the derived predicate
	fmt.Println("\n=== Query 1: All pods (via derived predicate) ===")
	interp.QueryInteractive(`pod(Namespace, Name, _)`)

	// Query 2: Pods in kube-system
	fmt.Println("\n=== Query 2: Pods in kube-system ===")
	interp.QueryInteractive(`pod("kube-system", Name, _)`)

	// Query 3: All service accounts
	fmt.Println("\n=== Query 3: All service accounts ===")
	interp.QueryInteractive(`serviceaccount(Namespace, Name, _)`)

	// Query 4: Direct query on k8s/5 - all objects in a namespace
	fmt.Println("\n=== Query 4: All objects in kube-system (generic query) ===")
	interp.QueryInteractive(`objects_in_ns("kube-system", Kind, Name)`)

	// Query 5: Pods with their service account names
	fmt.Println("\n=== Query 5: Pods with their service account names ===")
	interp.QueryInteractive(`pod_sa(Namespace, PodName, SAName)`)

	// Query 6: Pods using 'coredns' service account
	fmt.Println("\n=== Query 6: Pods using 'coredns' service account ===")
	interp.QueryInteractive(`pod_sa(Namespace, PodName, "coredns")`)

	// Query 7: Pods joined with existing service accounts
	fmt.Println("\n=== Query 7: Pods with existing service accounts (join) ===")
	interp.QueryInteractive(`pod_with_sa(Namespace, PodName, SAName)`)

	// Query 8: Container images
	fmt.Println("\n=== Query 8: Container images ===")
	interp.QueryInteractive(`pod_image(Namespace, PodName, Image)`)

	// Query 9: Orphaned service accounts
	fmt.Println("\n=== Query 9: Orphaned service accounts (not used by any pod) ===")
	interp.QueryInteractive(`orphaned_sa(Namespace, SAName)`)
}
