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

// loadJSONFacts reads a JSON-lines file and adds facts to the store with the given predicate name
func loadJSONFacts(store factstore.SimpleInMemoryStore, filename, predicateName string) (int, error) {
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

		// Extract namespace and name from metadata
		metadata := m["metadata"].(map[string]any)
		namespace := metadata["namespace"].(string)
		name := metadata["name"].(string)

		// Create a fact (atom) with namespace, name, and full struct
		fact := ast.Atom{
			Predicate: ast.PredicateSym{Symbol: predicateName, Arity: 3},
			Args: []ast.BaseTerm{
				ast.String(namespace),
				ast.String(name),
				mangleStruct,
			},
		}

		store.Add(fact)
		count++
		fmt.Printf("Inserted %s: %s/%s\n", predicateName, namespace, name)
	}
	return count, nil
}

func main() {
	store := factstore.NewSimpleInMemoryStore()

	// Load pods
	podCount, err := loadJSONFacts(store, "allpods.json", "pod")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Loaded %d pods\n", podCount)

	// Load service accounts
	saCount, err := loadJSONFacts(store, "serviceaccounts.json", "serviceaccount")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Loaded %d service accounts\n", saCount)

	fmt.Printf("\nPredicates: %v\n", store.ListPredicates())

	// Create an interpreter for running queries
	interp := interpreter.New(os.Stdout, ".", nil)

	// Preload our fact store into the interpreter
	// The interpreter needs declarations for our predicates
	knownPredicates := map[ast.PredicateSym]ast.Decl{
		{Symbol: "pod", Arity: 3}:            {DeclaredAtom: ast.Atom{Predicate: ast.PredicateSym{Symbol: "pod", Arity: 3}}},
		{Symbol: "serviceaccount", Arity: 3}: {DeclaredAtom: ast.Atom{Predicate: ast.PredicateSym{Symbol: "serviceaccount", Arity: 3}}},
	}
	if err := interp.Preload(nil, store, knownPredicates); err != nil {
		log.Fatalf("failed to preload: %v", err)
	}

	// Example 1: Query all pods (returns all pod facts)
	fmt.Println("\n=== Query 1: All pods ===")
	query1, _ := interp.ParseQuery("pod(Namespace, Name, _)")
	results1, err := interp.Query(query1)
	if err != nil {
		log.Printf("Query error: %v", err)
	}
	for _, r := range results1 {
		fmt.Printf("  %s/%s\n", r.Args[0], r.Args[1])
	}

	// Example 2: Query pods in a specific namespace
	fmt.Println("\n=== Query 2: Pods in kube-system ===")
	query2, _ := interp.ParseQuery(`pod("kube-system", Name, _)`)
	results2, err := interp.Query(query2)
	if err != nil {
		log.Printf("Query error: %v", err)
	}
	for _, r := range results2 {
		fmt.Printf("  %s\n", r.Args[1])
	}

	// Example 3: Query all service accounts
	fmt.Println("\n=== Query 3: All service accounts ===")
	query3, _ := interp.ParseQuery("serviceaccount(Namespace, Name, _)")
	results3, err := interp.Query(query3)
	if err != nil {
		log.Printf("Query error: %v", err)
	}
	for _, r := range results3 {
		fmt.Printf("  %s/%s\n", r.Args[0], r.Args[1])
	}

	// Example 4: Interactive query (shows formatted output)
	fmt.Println("\n=== Query 4: Interactive query for pods in local-path-storage ===")
	interp.QueryInteractive(`pod("local-path-storage", Name, Data)`)

	// Define all rules at once
	// Uses :match_field(Struct, /fieldname, Value) to extract nested fields
	// Field names are prefixed with / in Mangle
	fmt.Println("\n=== Defining rules ===")
	err = interp.Define(`
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

		# Extract container images using :list:member to iterate over list
		# :list:member(Element, List) - Element is output, List is input
		pod_image(Namespace, PodName, Image) :-
			pod(Namespace, PodName, Data),
			:match_field(Data, /spec, Spec),
			:match_field(Spec, /containers, Containers),
			:list:member(Container, Containers),
			:match_field(Container, /image, Image).
	`)
	if err != nil {
		log.Printf("Define error: %v", err)
	}

	// Query 5: Pods with their service account names
	fmt.Println("\n=== Query 5: Pods with their service account names ===")
	interp.QueryInteractive(`pod_sa(Namespace, PodName, SAName)`)

	// Query 6: Pods using a specific service account
	fmt.Println("\n=== Query 6: Pods using 'coredns' service account ===")
	interp.QueryInteractive(`pod_sa(Namespace, PodName, "coredns")`)

	// Query 7: Pods joined with existing service accounts
	fmt.Println("\n=== Query 7: Pods with existing service accounts (join) ===")
	interp.QueryInteractive(`pod_with_sa(Namespace, PodName, SAName)`)

	// Query 8: Container images
	fmt.Println("\n=== Query 8: Container images ===")
	interp.QueryInteractive(`pod_image(Namespace, PodName, Image)`)
}
