package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/ajwdev/pallograph/pkg/policy"
	"github.com/google/mangle/ast"
	"github.com/google/mangle/factstore"
	"github.com/google/mangle/interpreter"
	"github.com/google/mangle/json2struct"
	"github.com/google/mangle/parse"
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

// loadApiResources reads the output of `kubectl api-resources -o name` and
// adds api_resource(ApiGroup, Resource) facts to the store. Lines starting
// with '#' are treated as comments and skipped.
//
// Format: core resources are just the resource name (e.g. "pods"); named-group
// resources are "resource.apigroup" (e.g. "deployments.apps").
func loadApiResources(store factstore.SimpleInMemoryStore, filename string) (int, error) {
	fd, err := os.Open(filename)
	if err != nil {
		return 0, fmt.Errorf("failed to open file %s: %w", filename, err)
	}
	defer fd.Close()

	var count int
	scanner := bufio.NewScanner(fd)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		resource, apiGroup, _ := strings.Cut(line, ".")
		store.Add(ast.Atom{
			Predicate: ast.PredicateSym{Symbol: "api_resource", Arity: 2},
			Args:      []ast.BaseTerm{ast.String(apiGroup), ast.String(resource)},
		})
		count++
	}
	return count, scanner.Err()
}

// loadRulesFromFile parses a .mg file into a SourceUnit
func loadRulesFromFile(path string) (parse.SourceUnit, error) {
	f, err := os.Open(path)
	if err != nil {
		return parse.SourceUnit{}, err
	}
	defer f.Close()
	return parse.Unit(f)
}

func main() {
	repl := flag.Bool("repl", false, "start interactive query REPL after evaluation")
	flag.Parse()

	// Fact store for k8s objects. The engine holds this as its source of truth;
	// a controller reconcile loop would mutate it and call engine.Evaluate again.
	store := factstore.NewSimpleInMemoryStore()

	// Load all Kubernetes objects
	files := []string{"allpods.json", "serviceaccounts.json", "rbac.json"}
	var totalCount int
	for _, f := range files {
		count, err := loadK8sObjects(store, f)
		if err != nil {
			log.Fatal(err)
		}
		totalCount += count
	}
	fmt.Printf("\nLoaded %d total Kubernetes objects\n", totalCount)

	// Load API resource types (output of `kubectl api-resources -o name`)
	apiResourceCount, err := loadApiResources(store, "api-resources.txt")
	if err != nil {
		log.Fatalf("failed to load api-resources.txt: %v", err)
	}
	fmt.Printf("Loaded %d API resource types\n", apiResourceCount)

	// Load rule files from the rules directory
	ruleFiles, err := filepath.Glob("rules/*.mg")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Found rule files: %v\n", ruleFiles)

	var ruleUnits []parse.SourceUnit
	for _, rf := range ruleFiles {
		unit, err := loadRulesFromFile(rf)
		if err != nil {
			log.Fatalf("failed to load %s: %v", rf, err)
		}
		ruleUnits = append(ruleUnits, unit)
		fmt.Printf("Loaded rules from: %s\n", rf)
	}

	// Declare EDB (Extensional Database) predicates so rules can reference them.
	// user_groups/2 is populated at query time from a UserInfo struct.
	// api_resource/2 is loaded from `kubectl api-resources -o name` output.
	knownPredicates := map[ast.PredicateSym]ast.Decl{
		{Symbol: "k8s", Arity: 5}:         {DeclaredAtom: ast.Atom{Predicate: ast.PredicateSym{Symbol: "k8s", Arity: 5}}},
		{Symbol: "user_groups", Arity: 2}: {DeclaredAtom: ast.Atom{Predicate: ast.PredicateSym{Symbol: "user_groups", Arity: 2}}},
		{Symbol: "api_resource", Arity: 2}: {DeclaredAtom: ast.Atom{Predicate: ast.PredicateSym{Symbol: "api_resource", Arity: 2}}},
	}

	// Build policy engine. Rules are compiled once here; on each Evaluate call
	// a fresh derived-fact overlay is computed and discarded, so re-evaluation
	// after store mutations always reflects current state.
	engine, err := policy.New(store, ruleUnits, knownPredicates)
	if err != nil {
		log.Fatalf("failed to build policy engine: %v", err)
	}

	dryRun := &policy.DryRunCollector{}
	logHandler := &policy.LogHandler{}

	for _, pred := range []string{"orphaned_sa", "host_network_pod", "privileged_pod"} {
		if err := engine.Register(pred, logHandler, dryRun); err != nil {
			log.Fatalf("register predicate %q: %v", pred, err)
		}
	}

	fmt.Println("\n=== Evaluating policies ===")
	if err := engine.Evaluate(context.Background()); err != nil {
		log.Fatalf("policy evaluation: %v", err)
	}
	dryRun.PrintSummary()

	if !*repl {
		return
	}

	// REPL gets its own interpreter; it's a separate concern from policy evaluation.
	interp := interpreter.New(os.Stdout, ".", nil)
	if err := interp.Preload(ruleUnits, store, knownPredicates); err != nil {
		log.Fatalf("failed to build REPL interpreter: %v", err)
	}

	fmt.Println("\n=== Interactive Query Mode ===")
	fmt.Println("Enter queries or rules. Examples:")
	fmt.Println("  pod(Ns, Name, _)                    # query all pods")
	fmt.Println("  pod_sa(\"kube-system\", Pod, SA)      # pods with SAs in kube-system")
	fmt.Println("  ::define my_rule(X) :- pod(X, _, _). # define a new rule")
	fmt.Println("  ::show all                          # list all predicates")
	fmt.Println("  ::quit                              # exit")
	fmt.Println()

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("mangle> ")
		if !scanner.Scan() {
			break
		}
		line := scanner.Text()
		if line == "" {
			continue
		}
		if line == "::quit" || line == "::exit" {
			break
		}
		if line == "::show all" {
			interp.Show("all")
			continue
		}
		if len(line) > 9 && line[:9] == "::define " {
			rule := line[9:]
			if err := interp.Define(rule); err != nil {
				fmt.Printf("Error: %v\n", err)
			} else {
				fmt.Println("Rule defined.")
			}
			continue
		}
		interp.QueryInteractive(line)
	}
}
