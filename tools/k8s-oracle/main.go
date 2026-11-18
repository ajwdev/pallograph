// k8s-oracle answers questions about Kubernetes with the upstream code
// that decides them, as ground truth for Pallograph's model:
//
//   - rbac: authorization requests with the kube-apiserver RBAC
//     authorizer, and impersonation and RBAC write questions with the API
//     server code around it.
//   - labels: which objects each label selector selects, with the
//     apimachinery selector code and the scope each controller lists
//     objects in.
//
// A world is a directory of manifests. Subcommands:
//
//	k8s-oracle rbac gen-worlds -seed S -count N <dir>      writes N random worlds under <dir>
//	k8s-oracle rbac gen [-limit N] [-seed S] <world>...    writes <world>/requests.ndjson
//	k8s-oracle rbac eval <world>...                        writes <world>/oracle.ndjson
//	k8s-oracle rbac kind-verify [-context C] <world>...    checks the oracle against a live API server
//	k8s-oracle labels eval <world>...                      writes <world>/selections.ndjson and query-results.ndjson
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func main() {
	if len(os.Args) < 3 {
		usage()
	}

	var err error
	switch os.Args[1] {
	case "rbac":
		err = runRBAC(os.Args[2], os.Args[3:])
	case "labels":
		err = runLabels(os.Args[2], os.Args[3:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "k8s-oracle:", err)
		os.Exit(1)
	}
}

func runRBAC(command string, args []string) error {
	switch command {
	case "gen-worlds":
		return runGenWorlds(args)
	case "gen":
		return runGen(args)
	case "eval":
		return runEval(args)
	case "kind-verify":
		return runKindVerify(args)
	}
	usage()
	return nil
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage: k8s-oracle rbac gen-worlds -seed S -count N <dir>
       k8s-oracle rbac gen [-limit N] [-seed S] <world>...
       k8s-oracle rbac eval <world>...
       k8s-oracle rbac kind-verify [-context C] [-sample N] <world>...
       k8s-oracle labels eval <world>...`)
	os.Exit(2)
}

func runGenWorlds(args []string) error {
	flags := flag.NewFlagSet("gen-worlds", flag.ExitOnError)
	seed := flags.Uint64("seed", 1, "world generator seed")
	count := flags.Int("count", 10, "number of worlds")
	flags.Parse(args)
	if flags.NArg() != 1 {
		usage()
	}

	worlds, err := GenerateWorlds(flags.Arg(0), *seed, *count)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%s: %d worlds\n", flags.Arg(0), len(worlds))
	return nil
}

func runGen(args []string) error {
	flags := flag.NewFlagSet("gen", flag.ExitOnError)
	limit := flags.Int("limit", 0, "keep a seeded sample of at most N requests per world (0 keeps all)")
	seed := flags.Uint64("seed", 1, "sampling seed")
	flags.Parse(args)
	if flags.NArg() == 0 {
		usage()
	}

	for _, dir := range flags.Args() {
		world, err := LoadWorld(dir)
		if err != nil {
			return err
		}
		requests, err := GenerateRequests(world, *limit, *seed)
		if err != nil {
			return err
		}
		if err := writeNDJSON(filepath.Join(dir, requestsFile), requests); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "%s: %d requests\n", dir, len(requests))
	}
	return nil
}

func runEval(args []string) error {
	flags := flag.NewFlagSet("eval", flag.ExitOnError)
	flags.Parse(args)
	if flags.NArg() == 0 {
		usage()
	}

	for _, dir := range flags.Args() {
		if err := evalWorld(dir); err != nil {
			return err
		}
	}
	return nil
}

func evalWorld(dir string) error {
	world, err := LoadWorld(dir)
	if err != nil {
		return err
	}
	requests, err := readRequests(filepath.Join(dir, requestsFile))
	if err != nil {
		return err
	}

	oracle := NewOracle(world)
	if err := addCounterfactuals(oracle, dir); err != nil {
		return err
	}

	start := time.Now()
	decisions := make([]Decision, len(requests))
	allowed := 0
	for i := range requests {
		decisions[i], err = oracle.Decide(&requests[i])
		if err != nil {
			return err
		}
		if decisions[i].Allowed {
			allowed++
		}
	}
	elapsed := time.Since(start)

	if err := writeNDJSON(filepath.Join(dir, oracleFile), decisions); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%s: %d requests, %d allowed, %v\n", dir, len(requests), allowed, elapsed.Round(time.Millisecond))
	return nil
}

// counterfactuals are the world variants evalWorld explains denials with,
// in the order they are consulted.
var counterfactuals = []struct {
	tag      string
	variant  worldVariant
	fallback bool
}{
	{"denied-by-resource-names", withoutResourceNames, false},
	{"denied-by-aggregation-replacing-rules", aggregationKeepsOwnRules, false},
	// A rule that has resourceNames and is also discarded by aggregation
	// needs both.
	{"denied-by-resource-names-and-aggregation", withoutResourceNames | aggregationKeepsOwnRules, true},
}

// addCounterfactuals loads each counterfactual variant of the world in dir
// into oracle.
func addCounterfactuals(oracle *Oracle, dir string) error {
	for _, counterfactual := range counterfactuals {
		variantWorld, err := loadWorld(dir, counterfactual.variant)
		if err != nil {
			return err
		}
		oracle.AddCounterfactual(counterfactual.tag, variantWorld, counterfactual.fallback)
	}
	return nil
}
