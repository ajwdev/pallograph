// rbac-oracle answers Kubernetes RBAC authorization requests with the
// kube-apiserver RBAC authorizer, as ground truth for Pallograph's RBAC
// model.
//
// A world is a directory holding rbac.yaml. Subcommands:
//
//	rbac-oracle gen [-limit N] [-seed S] <world>   writes <world>/requests.ndjson
//	rbac-oracle eval <world>                       writes <world>/oracle.ndjson
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
	case "gen":
		err = runGen(os.Args[2:])
	case "eval":
		err = runEval(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "rbac-oracle:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: rbac-oracle gen [-limit N] [-seed S] <world>\n       rbac-oracle eval <world>")
	os.Exit(2)
}

func runGen(args []string) error {
	flags := flag.NewFlagSet("gen", flag.ExitOnError)
	limit := flags.Int("limit", 0, "keep a seeded sample of at most N requests (0 keeps all)")
	seed := flags.Uint64("seed", 1, "sampling seed")
	flags.Parse(args)
	if flags.NArg() != 1 {
		usage()
	}
	dir := flags.Arg(0)

	world, err := LoadWorld(dir)
	if err != nil {
		return err
	}
	requests := GenerateRequests(world, *limit, *seed)
	if err := writeNDJSON(filepath.Join(dir, "requests.ndjson"), requests); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%s: %d requests\n", dir, len(requests))
	return nil
}

func runEval(args []string) error {
	flags := flag.NewFlagSet("eval", flag.ExitOnError)
	flags.Parse(args)
	if flags.NArg() != 1 {
		usage()
	}
	dir := flags.Arg(0)

	world, err := LoadWorld(dir)
	if err != nil {
		return err
	}
	requests, err := readRequests(filepath.Join(dir, "requests.ndjson"))
	if err != nil {
		return err
	}

	start := time.Now()
	oracle := NewOracle(world)
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

	if err := writeNDJSON(filepath.Join(dir, "oracle.ndjson"), decisions); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%s: %d requests, %d allowed, %v\n", dir, len(requests), allowed, elapsed.Round(time.Millisecond))
	return nil
}
