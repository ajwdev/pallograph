// rbac-oracle answers Kubernetes RBAC authorization requests with the
// kube-apiserver RBAC authorizer, as ground truth for Pallograph's RBAC
// model.
//
// A world is a directory holding rbac.yaml. Subcommands:
//
//	rbac-oracle gen-worlds -seed S -count N <dir>      writes N random worlds under <dir>
//	rbac-oracle gen [-limit N] [-seed S] <world>...    writes <world>/requests.ndjson.zst
//	rbac-oracle eval <world>...                        writes <world>/oracle.ndjson.zst
//	rbac-oracle kind-verify [-context C] <world>...    checks the oracle against a live API server
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}

	var err error
	switch os.Args[1] {
	case "gen-worlds":
		err = runGenWorlds(os.Args[2:])
	case "gen":
		err = runGen(os.Args[2:])
	case "eval":
		err = runEval(os.Args[2:])
	case "kind-verify":
		err = runKindVerify(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "rbac-oracle:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage: rbac-oracle gen-worlds -seed S -count N <dir>
       rbac-oracle gen [-limit N] [-seed S] <world>...
       rbac-oracle eval <world>...
       rbac-oracle kind-verify [-context C] [-sample N] <world>...`)
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
		requests := GenerateRequests(world, *limit, *seed)
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
	for _, counterfactual := range []struct {
		tag      string
		variant  worldVariant
		fallback bool
	}{
		{"denied-by-resource-names", withoutResourceNames, false},
		{"denied-by-aggregation-replacing-rules", aggregationKeepsOwnRules, false},
		// A rule that has resourceNames and is also discarded by
		// aggregation needs both.
		{"denied-by-resource-names-and-aggregation", withoutResourceNames | aggregationKeepsOwnRules, true},
	} {
		variantWorld, err := loadWorld(dir, counterfactual.variant)
		if err != nil {
			return err
		}
		oracle.AddCounterfactual(counterfactual.tag, variantWorld, counterfactual.fallback)
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
