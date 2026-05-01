package policy_test

// Tests for the graph reachability rules in rules/graph.mg.
//
// graph.mg depends on selector_matches from labels.mg, so both rule files are
// loaded together. Tests use minimal synthetic objects (generic Kind names like
// "A", "B", "C") to keep fixtures readable — the rules are kind-agnostic.

import (
	"context"
	"os"
	"testing"

	"github.com/ajwdev/pallograph/pkg/policy"
	"github.com/google/mangle/ast"
	"github.com/google/mangle/parse"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---- Rule loading ----

func loadGraphRules(t *testing.T) []parse.SourceUnit {
	t.Helper()
	var units []parse.SourceUnit
	for _, path := range []string{"../../rules/labels.mg", "../../rules/graph.mg"} {
		f, err := os.Open(path)
		require.NoError(t, err)
		defer f.Close()
		unit, err := parse.Unit(f)
		require.NoError(t, err)
		units = append(units, unit)
	}
	return units
}

// ---- Engine builder ----

func graphEngine(t *testing.T, facts ...ast.Atom) *policy.Engine {
	t.Helper()
	engine, err := policy.New(makeStore(facts...), loadGraphRules(t), labelKnownPreds())
	require.NoError(t, err)
	return engine
}

// ---- Tests ----

// TestGraph_DirectEdge: reachable holds for a direct selector match (one hop).
func TestGraph_DirectEdge(t *testing.T) {
	engine := graphEngine(t,
		minimalK8s(t, "v1", "A", "default", "a"),
		matchLabelAtom("v1", "A", "default", "a", "app", "foo"),
		minimalK8s(t, "v1", "B", "default", "b"),
		objectLabelAtom("v1", "B", "default", "b", "app", "foo"),
	)

	h := &collectHandler{}
	require.NoError(t, engine.RegisterQuery(
		`reachable("v1", "A", "default", "a", "v1", "B", "default", "b")`, h))
	assert.NoError(t, engine.Evaluate(context.Background()))
	assert.Len(t, h.violations, 1)
}

// TestGraph_TwoHop: reachable holds transitively across two edges.
// Models Deployment → ReplicaSet → Pod.
func TestGraph_TwoHop(t *testing.T) {
	engine := graphEngine(t,
		// A selects B via label x=1
		minimalK8s(t, "v1", "A", "default", "a"),
		matchLabelAtom("v1", "A", "default", "a", "x", "1"),
		// B has label x=1 (selected by A) and its own selector y=2
		minimalK8s(t, "v1", "B", "default", "b"),
		objectLabelAtom("v1", "B", "default", "b", "x", "1"),
		matchLabelAtom("v1", "B", "default", "b", "y", "2"),
		// C has label y=2 (selected by B)
		minimalK8s(t, "v1", "C", "default", "c"),
		objectLabelAtom("v1", "C", "default", "c", "y", "2"),
	)

	direct := &collectHandler{}
	transitive := &collectHandler{}
	require.NoError(t, engine.RegisterQuery(
		`reachable("v1", "A", "default", "a", "v1", "B", "default", "b")`, direct))
	require.NoError(t, engine.RegisterQuery(
		`reachable("v1", "A", "default", "a", "v1", "C", "default", "c")`, transitive))
	assert.NoError(t, engine.Evaluate(context.Background()))

	assert.Len(t, direct.violations, 1)
	assert.Len(t, transitive.violations, 1)
}

// TestGraph_ThreeHop: reachable holds across three edges.
func TestGraph_ThreeHop(t *testing.T) {
	engine := graphEngine(t,
		// A → B via x=1
		minimalK8s(t, "v1", "A", "default", "a"),
		matchLabelAtom("v1", "A", "default", "a", "x", "1"),
		minimalK8s(t, "v1", "B", "default", "b"),
		objectLabelAtom("v1", "B", "default", "b", "x", "1"),
		matchLabelAtom("v1", "B", "default", "b", "y", "2"),
		// B → C via y=2
		minimalK8s(t, "v1", "C", "default", "c"),
		objectLabelAtom("v1", "C", "default", "c", "y", "2"),
		matchLabelAtom("v1", "C", "default", "c", "z", "3"),
		// C → D via z=3
		minimalK8s(t, "v1", "D", "default", "d"),
		objectLabelAtom("v1", "D", "default", "d", "z", "3"),
	)

	h := &collectHandler{}
	require.NoError(t, engine.RegisterQuery(
		`reachable("v1", "A", "default", "a", "v1", "D", "default", "d")`, h))
	assert.NoError(t, engine.Evaluate(context.Background()))
	assert.Len(t, h.violations, 1)
}

// TestGraph_NoPath: reachable does not hold when there is no edge chain.
func TestGraph_NoPath(t *testing.T) {
	engine := graphEngine(t,
		// A selects B
		minimalK8s(t, "v1", "A", "default", "a"),
		matchLabelAtom("v1", "A", "default", "a", "x", "1"),
		minimalK8s(t, "v1", "B", "default", "b"),
		objectLabelAtom("v1", "B", "default", "b", "x", "1"),
		// C is unrelated
		minimalK8s(t, "v1", "C", "default", "c"),
		objectLabelAtom("v1", "C", "default", "c", "z", "99"),
	)

	h := &collectHandler{}
	require.NoError(t, engine.RegisterQuery(
		`reachable("v1", "A", "default", "a", "v1", "C", "default", "c")`, h))
	assert.NoError(t, engine.Evaluate(context.Background()))
	assert.Empty(t, h.violations)
}

// TestGraph_ReverseNotReachable: reachable is directed — A reaching B does not
// imply B reaches A.
func TestGraph_ReverseNotReachable(t *testing.T) {
	engine := graphEngine(t,
		minimalK8s(t, "v1", "A", "default", "a"),
		matchLabelAtom("v1", "A", "default", "a", "x", "1"),
		minimalK8s(t, "v1", "B", "default", "b"),
		objectLabelAtom("v1", "B", "default", "b", "x", "1"),
	)

	h := &collectHandler{}
	require.NoError(t, engine.RegisterQuery(
		`reachable("v1", "B", "default", "b", "v1", "A", "default", "a")`, h))
	assert.NoError(t, engine.Evaluate(context.Background()))
	assert.Empty(t, h.violations)
}

// TestGraph_AllReachable: open query returns all objects reachable from a source.
func TestGraph_AllReachable(t *testing.T) {
	engine := graphEngine(t,
		// A → B and A → C (two direct edges)
		minimalK8s(t, "v1", "A", "default", "a"),
		matchLabelAtom("v1", "A", "default", "a", "owned-by", "a"),
		minimalK8s(t, "v1", "B", "default", "b"),
		objectLabelAtom("v1", "B", "default", "b", "owned-by", "a"),
		matchLabelAtom("v1", "B", "default", "b", "tier", "mid"),
		minimalK8s(t, "v1", "C", "default", "c"),
		objectLabelAtom("v1", "C", "default", "c", "owned-by", "a"),
		// B → D (transitive from A)
		minimalK8s(t, "v1", "D", "default", "d"),
		objectLabelAtom("v1", "D", "default", "d", "tier", "mid"),
	)

	h := &collectHandler{}
	require.NoError(t, engine.RegisterQuery(
		`reachable("v1", "A", "default", "a", X0, X1, X2, X3)`, h))
	assert.NoError(t, engine.Evaluate(context.Background()))

	names := make(map[string]bool)
	for _, v := range h.violations {
		names[v.Args[7].String()] = true
	}
	assert.True(t, names[`"b"`])
	assert.True(t, names[`"c"`])
	assert.True(t, names[`"d"`])
}
