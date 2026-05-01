package policy_test

// Tests for the label selector Datalog rules in rules/labels.mg.
//
// Each test builds a minimal set of EDB facts — object_label and selector_*
// atoms — runs the policy engine, and asserts that selector_matches (or an
// intermediate predicate) contains exactly the expected results.
//
// k8s/5 facts are also required so that object_exists/4 can be derived; the
// k8sAtom helper from rbac_rules_test.go covers this.

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

func loadLabelRules(t *testing.T) []parse.SourceUnit {
	t.Helper()
	f, err := os.Open("../../rules/labels.mg")
	require.NoError(t, err)
	defer f.Close()
	unit, err := parse.Unit(f)
	require.NoError(t, err)
	return []parse.SourceUnit{unit}
}

func labelKnownPreds() map[ast.PredicateSym]ast.Decl {
	decl := func(sym string, arity int) ast.Decl {
		pred := ast.PredicateSym{Symbol: sym, Arity: arity}
		return ast.Decl{DeclaredAtom: ast.Atom{Predicate: pred}}
	}
	return map[ast.PredicateSym]ast.Decl{
		{Symbol: "k8s", Arity: 5}:                    decl("k8s", 5),
		{Symbol: "object_label", Arity: 6}:            decl("object_label", 6),
		{Symbol: "selector_match_label", Arity: 6}:    decl("selector_match_label", 6),
		{Symbol: "selector_expr_in", Arity: 6}:        decl("selector_expr_in", 6),
		{Symbol: "selector_expr_notin", Arity: 6}:     decl("selector_expr_notin", 6),
		{Symbol: "selector_expr_exists", Arity: 5}:    decl("selector_expr_exists", 5),
		{Symbol: "selector_expr_notexists", Arity: 5}: decl("selector_expr_notexists", 5),
	}
}

// ---- Fact atom builders ----

func objectLabelAtom(apiVersion, kind, ns, name, key, val string) ast.Atom {
	return ast.Atom{
		Predicate: ast.PredicateSym{Symbol: "object_label", Arity: 6},
		Args: []ast.BaseTerm{
			ast.String(apiVersion), ast.String(kind),
			ast.String(ns), ast.String(name),
			ast.String(key), ast.String(val),
		},
	}
}

func matchLabelAtom(selAV, selKind, selNs, selName, key, val string) ast.Atom {
	return ast.Atom{
		Predicate: ast.PredicateSym{Symbol: "selector_match_label", Arity: 6},
		Args: []ast.BaseTerm{
			ast.String(selAV), ast.String(selKind),
			ast.String(selNs), ast.String(selName),
			ast.String(key), ast.String(val),
		},
	}
}

func exprInAtom(selAV, selKind, selNs, selName, key, val string) ast.Atom {
	return ast.Atom{
		Predicate: ast.PredicateSym{Symbol: "selector_expr_in", Arity: 6},
		Args: []ast.BaseTerm{
			ast.String(selAV), ast.String(selKind),
			ast.String(selNs), ast.String(selName),
			ast.String(key), ast.String(val),
		},
	}
}

func exprNotInAtom(selAV, selKind, selNs, selName, key, val string) ast.Atom {
	return ast.Atom{
		Predicate: ast.PredicateSym{Symbol: "selector_expr_notin", Arity: 6},
		Args: []ast.BaseTerm{
			ast.String(selAV), ast.String(selKind),
			ast.String(selNs), ast.String(selName),
			ast.String(key), ast.String(val),
		},
	}
}

func exprExistsAtom(selAV, selKind, selNs, selName, key string) ast.Atom {
	return ast.Atom{
		Predicate: ast.PredicateSym{Symbol: "selector_expr_exists", Arity: 5},
		Args: []ast.BaseTerm{
			ast.String(selAV), ast.String(selKind),
			ast.String(selNs), ast.String(selName),
			ast.String(key),
		},
	}
}

func exprNotExistsAtom(selAV, selKind, selNs, selName, key string) ast.Atom {
	return ast.Atom{
		Predicate: ast.PredicateSym{Symbol: "selector_expr_notexists", Arity: 5},
		Args: []ast.BaseTerm{
			ast.String(selAV), ast.String(selKind),
			ast.String(selNs), ast.String(selName),
			ast.String(key),
		},
	}
}

// minimalPod returns a k8s/5 fact for a pod with no spec data — just enough
// for object_exists to be derived.
func minimalK8s(t *testing.T, apiVersion, kind, ns, name string) ast.Atom {
	t.Helper()
	return k8sAtom(t, map[string]any{
		"apiVersion": apiVersion,
		"kind":       kind,
		"metadata":   map[string]any{"name": name, "namespace": ns},
	})
}

// ---- Engine builder ----

func labelEngine(t *testing.T, facts ...ast.Atom) *policy.Engine {
	t.Helper()
	engine, err := policy.New(makeStore(facts...), loadLabelRules(t), labelKnownPreds())
	require.NoError(t, err)
	return engine
}

// ---- Tests ----

// TestLabel_MatchLabels_Match: object has all required labels → matches.
func TestLabel_MatchLabels_Match(t *testing.T) {
	engine := labelEngine(t,
		minimalK8s(t, "v1", "Pod", "default", "mypod"),
		objectLabelAtom("v1", "Pod", "default", "mypod", "app", "nginx"),
		objectLabelAtom("v1", "Pod", "default", "mypod", "env", "prod"),
		// Deployment's selector
		minimalK8s(t, "apps/v1", "Deployment", "default", "mydeployment"),
		matchLabelAtom("apps/v1", "Deployment", "default", "mydeployment", "app", "nginx"),
		matchLabelAtom("apps/v1", "Deployment", "default", "mydeployment", "env", "prod"),
	)

	h := &collectHandler{}
	require.NoError(t, engine.RegisterQuery(
		`selector_matches("apps/v1", "Deployment", "default", "mydeployment", "v1", "Pod", "default", "mypod")`, h))
	assert.NoError(t, engine.Evaluate(context.Background()))
	assert.Len(t, h.violations, 1)
}

// TestLabel_MatchLabels_MissingLabel: object is missing one required label → no match.
func TestLabel_MatchLabels_MissingLabel(t *testing.T) {
	engine := labelEngine(t,
		minimalK8s(t, "v1", "Pod", "default", "mypod"),
		objectLabelAtom("v1", "Pod", "default", "mypod", "app", "nginx"),
		// "env" label is absent from the pod
		minimalK8s(t, "apps/v1", "Deployment", "default", "mydeployment"),
		matchLabelAtom("apps/v1", "Deployment", "default", "mydeployment", "app", "nginx"),
		matchLabelAtom("apps/v1", "Deployment", "default", "mydeployment", "env", "prod"),
	)

	h := &collectHandler{}
	require.NoError(t, engine.RegisterQuery(
		`selector_matches("apps/v1", "Deployment", "default", "mydeployment", "v1", "Pod", "default", "mypod")`, h))
	assert.NoError(t, engine.Evaluate(context.Background()))
	assert.Empty(t, h.violations)
}

// TestLabel_MatchLabels_WrongValue: object has the key but wrong value → no match.
func TestLabel_MatchLabels_WrongValue(t *testing.T) {
	engine := labelEngine(t,
		minimalK8s(t, "v1", "Pod", "default", "mypod"),
		objectLabelAtom("v1", "Pod", "default", "mypod", "app", "apache"), // wrong value
		minimalK8s(t, "apps/v1", "Deployment", "default", "mydeployment"),
		matchLabelAtom("apps/v1", "Deployment", "default", "mydeployment", "app", "nginx"),
	)

	h := &collectHandler{}
	require.NoError(t, engine.RegisterQuery(
		`selector_matches("apps/v1", "Deployment", "default", "mydeployment", "v1", "Pod", "default", "mypod")`, h))
	assert.NoError(t, engine.Evaluate(context.Background()))
	assert.Empty(t, h.violations)
}

// TestLabel_CrossGVK: selector on a Deployment matches a Pod AND a StatefulSet
// that both carry the required labels — demonstrating cross-GVK selection.
func TestLabel_CrossGVK(t *testing.T) {
	engine := labelEngine(t,
		// Selector owner
		minimalK8s(t, "apps/v1", "Deployment", "default", "mydeployment"),
		matchLabelAtom("apps/v1", "Deployment", "default", "mydeployment", "app", "nginx"),
		// Pod with matching label
		minimalK8s(t, "v1", "Pod", "default", "pod-a"),
		objectLabelAtom("v1", "Pod", "default", "pod-a", "app", "nginx"),
		// StatefulSet with matching label (different GVK)
		minimalK8s(t, "apps/v1", "StatefulSet", "default", "sts-a"),
		objectLabelAtom("apps/v1", "StatefulSet", "default", "sts-a", "app", "nginx"),
		// Pod without the label — should not match
		minimalK8s(t, "v1", "Pod", "default", "pod-b"),
		objectLabelAtom("v1", "Pod", "default", "pod-b", "app", "other"),
	)

	h := &collectHandler{}
	require.NoError(t, engine.RegisterQuery(
		`selector_matches("apps/v1", "Deployment", "default", "mydeployment", X0, X1, X2, X3)`, h))
	assert.NoError(t, engine.Evaluate(context.Background()))

	// Should match pod-a and sts-a (and the deployment itself since it's also an object_exists)
	// but NOT pod-b
	names := make(map[string]bool)
	for _, v := range h.violations {
		names[v.Args[7].String()] = true
	}
	assert.True(t, names[`"pod-a"`])
	assert.True(t, names[`"sts-a"`])
	assert.False(t, names[`"pod-b"`])
}

// TestLabel_ExprIn_Match: object has label key with one of the allowed values → matches.
func TestLabel_ExprIn_Match(t *testing.T) {
	engine := labelEngine(t,
		minimalK8s(t, "v1", "Pod", "default", "mypod"),
		objectLabelAtom("v1", "Pod", "default", "mypod", "tier", "frontend"),
		minimalK8s(t, "apps/v1", "Deployment", "default", "mydeployment"),
		exprInAtom("apps/v1", "Deployment", "default", "mydeployment", "tier", "frontend"),
		exprInAtom("apps/v1", "Deployment", "default", "mydeployment", "tier", "backend"),
	)

	h := &collectHandler{}
	require.NoError(t, engine.RegisterQuery(
		`selector_matches("apps/v1", "Deployment", "default", "mydeployment", "v1", "Pod", "default", "mypod")`, h))
	assert.NoError(t, engine.Evaluate(context.Background()))
	assert.Len(t, h.violations, 1)
}

// TestLabel_ExprIn_NoMatch: object has the key but none of the allowed values → no match.
func TestLabel_ExprIn_NoMatch(t *testing.T) {
	engine := labelEngine(t,
		minimalK8s(t, "v1", "Pod", "default", "mypod"),
		objectLabelAtom("v1", "Pod", "default", "mypod", "tier", "database"),
		minimalK8s(t, "apps/v1", "Deployment", "default", "mydeployment"),
		exprInAtom("apps/v1", "Deployment", "default", "mydeployment", "tier", "frontend"),
		exprInAtom("apps/v1", "Deployment", "default", "mydeployment", "tier", "backend"),
	)

	h := &collectHandler{}
	require.NoError(t, engine.RegisterQuery(
		`selector_matches("apps/v1", "Deployment", "default", "mydeployment", "v1", "Pod", "default", "mypod")`, h))
	assert.NoError(t, engine.Evaluate(context.Background()))
	assert.Empty(t, h.violations)
}

// TestLabel_ExprNotIn_Match: object does not have any of the excluded values → matches.
func TestLabel_ExprNotIn_Match(t *testing.T) {
	engine := labelEngine(t,
		minimalK8s(t, "v1", "Pod", "default", "mypod"),
		objectLabelAtom("v1", "Pod", "default", "mypod", "env", "staging"),
		minimalK8s(t, "apps/v1", "Deployment", "default", "mydeployment"),
		exprNotInAtom("apps/v1", "Deployment", "default", "mydeployment", "env", "prod"),
		exprNotInAtom("apps/v1", "Deployment", "default", "mydeployment", "env", "canary"),
	)

	h := &collectHandler{}
	require.NoError(t, engine.RegisterQuery(
		`selector_matches("apps/v1", "Deployment", "default", "mydeployment", "v1", "Pod", "default", "mypod")`, h))
	assert.NoError(t, engine.Evaluate(context.Background()))
	assert.Len(t, h.violations, 1)
}

// TestLabel_ExprNotIn_NoMatch: object has one of the excluded values → no match.
func TestLabel_ExprNotIn_NoMatch(t *testing.T) {
	engine := labelEngine(t,
		minimalK8s(t, "v1", "Pod", "default", "mypod"),
		objectLabelAtom("v1", "Pod", "default", "mypod", "env", "prod"),
		minimalK8s(t, "apps/v1", "Deployment", "default", "mydeployment"),
		exprNotInAtom("apps/v1", "Deployment", "default", "mydeployment", "env", "prod"),
		exprNotInAtom("apps/v1", "Deployment", "default", "mydeployment", "env", "canary"),
	)

	h := &collectHandler{}
	require.NoError(t, engine.RegisterQuery(
		`selector_matches("apps/v1", "Deployment", "default", "mydeployment", "v1", "Pod", "default", "mypod")`, h))
	assert.NoError(t, engine.Evaluate(context.Background()))
	assert.Empty(t, h.violations)
}

// TestLabel_ExprExists_Match: object has the required key → matches.
func TestLabel_ExprExists_Match(t *testing.T) {
	engine := labelEngine(t,
		minimalK8s(t, "v1", "Pod", "default", "mypod"),
		objectLabelAtom("v1", "Pod", "default", "mypod", "partition", "customer-a"),
		minimalK8s(t, "apps/v1", "Deployment", "default", "mydeployment"),
		exprExistsAtom("apps/v1", "Deployment", "default", "mydeployment", "partition"),
	)

	h := &collectHandler{}
	require.NoError(t, engine.RegisterQuery(
		`selector_matches("apps/v1", "Deployment", "default", "mydeployment", "v1", "Pod", "default", "mypod")`, h))
	assert.NoError(t, engine.Evaluate(context.Background()))
	assert.Len(t, h.violations, 1)
}

// TestLabel_ExprExists_NoMatch: object does not have the required key → no match.
func TestLabel_ExprExists_NoMatch(t *testing.T) {
	engine := labelEngine(t,
		minimalK8s(t, "v1", "Pod", "default", "mypod"),
		objectLabelAtom("v1", "Pod", "default", "mypod", "app", "nginx"), // no "partition" key
		minimalK8s(t, "apps/v1", "Deployment", "default", "mydeployment"),
		exprExistsAtom("apps/v1", "Deployment", "default", "mydeployment", "partition"),
	)

	h := &collectHandler{}
	require.NoError(t, engine.RegisterQuery(
		`selector_matches("apps/v1", "Deployment", "default", "mydeployment", "v1", "Pod", "default", "mypod")`, h))
	assert.NoError(t, engine.Evaluate(context.Background()))
	assert.Empty(t, h.violations)
}

// TestLabel_ExprDoesNotExist_Match: object lacks the key entirely → matches.
func TestLabel_ExprDoesNotExist_Match(t *testing.T) {
	engine := labelEngine(t,
		minimalK8s(t, "v1", "Pod", "default", "mypod"),
		objectLabelAtom("v1", "Pod", "default", "mypod", "app", "nginx"), // no "partition"
		minimalK8s(t, "apps/v1", "Deployment", "default", "mydeployment"),
		exprNotExistsAtom("apps/v1", "Deployment", "default", "mydeployment", "partition"),
	)

	h := &collectHandler{}
	require.NoError(t, engine.RegisterQuery(
		`selector_matches("apps/v1", "Deployment", "default", "mydeployment", "v1", "Pod", "default", "mypod")`, h))
	assert.NoError(t, engine.Evaluate(context.Background()))
	assert.Len(t, h.violations, 1)
}

// TestLabel_ExprDoesNotExist_NoMatch: object has the forbidden key → no match.
func TestLabel_ExprDoesNotExist_NoMatch(t *testing.T) {
	engine := labelEngine(t,
		minimalK8s(t, "v1", "Pod", "default", "mypod"),
		objectLabelAtom("v1", "Pod", "default", "mypod", "partition", "customer-a"),
		minimalK8s(t, "apps/v1", "Deployment", "default", "mydeployment"),
		exprNotExistsAtom("apps/v1", "Deployment", "default", "mydeployment", "partition"),
	)

	h := &collectHandler{}
	require.NoError(t, engine.RegisterQuery(
		`selector_matches("apps/v1", "Deployment", "default", "mydeployment", "v1", "Pod", "default", "mypod")`, h))
	assert.NoError(t, engine.Evaluate(context.Background()))
	assert.Empty(t, h.violations)
}

// TestLabel_ClusterScopedTarget: a namespace-scoped object's selector matches a
// cluster-scoped object (e.g. Pod nodeSelector → Node). Nodes have no namespace
// (namespace = ""), so the namespace fence must allow this case.
func TestLabel_ClusterScopedTarget(t *testing.T) {
	engine := labelEngine(t,
		// Node is cluster-scoped: namespace = "".
		minimalK8s(t, "v1", "Node", "", "node-1"),
		objectLabelAtom("v1", "Node", "", "node-1", "kubernetes.io/os", "linux"),
		// Pod in "default" namespace with a nodeSelector.
		minimalK8s(t, "v1", "Pod", "default", "mypod"),
		matchLabelAtom("v1", "Pod", "default", "mypod", "kubernetes.io/os", "linux"),
	)

	h := &collectHandler{}
	require.NoError(t, engine.RegisterQuery(
		`selector_matches("v1", "Pod", "default", "mypod", "v1", "Node", "", "node-1")`, h))
	assert.NoError(t, engine.Evaluate(context.Background()))
	assert.Len(t, h.violations, 1)
}

// TestLabel_CrossNamespace_NotAllowed: a selector must not match objects in a
// different namespace (neither is cluster-scoped).
func TestLabel_CrossNamespace_NotAllowed(t *testing.T) {
	engine := labelEngine(t,
		// Pod in "other" namespace — different from the selector owner's namespace.
		minimalK8s(t, "v1", "Pod", "other", "mypod"),
		objectLabelAtom("v1", "Pod", "other", "mypod", "app", "nginx"),
		// Deployment in "default" with a selector.
		minimalK8s(t, "apps/v1", "Deployment", "default", "mydeployment"),
		matchLabelAtom("apps/v1", "Deployment", "default", "mydeployment", "app", "nginx"),
	)

	h := &collectHandler{}
	require.NoError(t, engine.RegisterQuery(
		`selector_matches("apps/v1", "Deployment", "default", "mydeployment", "v1", "Pod", "other", "mypod")`, h))
	assert.NoError(t, engine.Evaluate(context.Background()))
	assert.Empty(t, h.violations)
}

// TestLabel_CombinedRequirements: matchLabels + matchExpressions must all be satisfied.
func TestLabel_CombinedRequirements(t *testing.T) {
	engine := labelEngine(t,
		// pod-good: satisfies all requirements
		minimalK8s(t, "v1", "Pod", "default", "pod-good"),
		objectLabelAtom("v1", "Pod", "default", "pod-good", "app", "nginx"),
		objectLabelAtom("v1", "Pod", "default", "pod-good", "tier", "frontend"),
		// pod-bad: satisfies matchLabels but fails the In requirement
		minimalK8s(t, "v1", "Pod", "default", "pod-bad"),
		objectLabelAtom("v1", "Pod", "default", "pod-bad", "app", "nginx"),
		objectLabelAtom("v1", "Pod", "default", "pod-bad", "tier", "database"),
		// Selector: app=nginx AND tier In [frontend, backend]
		minimalK8s(t, "apps/v1", "Deployment", "default", "mydeployment"),
		matchLabelAtom("apps/v1", "Deployment", "default", "mydeployment", "app", "nginx"),
		exprInAtom("apps/v1", "Deployment", "default", "mydeployment", "tier", "frontend"),
		exprInAtom("apps/v1", "Deployment", "default", "mydeployment", "tier", "backend"),
	)

	good := &collectHandler{}
	bad := &collectHandler{}
	require.NoError(t, engine.RegisterQuery(
		`selector_matches("apps/v1", "Deployment", "default", "mydeployment", "v1", "Pod", "default", "pod-good")`, good))
	require.NoError(t, engine.RegisterQuery(
		`selector_matches("apps/v1", "Deployment", "default", "mydeployment", "v1", "Pod", "default", "pod-bad")`, bad))
	assert.NoError(t, engine.Evaluate(context.Background()))

	assert.Len(t, good.violations, 1)
	assert.Empty(t, bad.violations)
}
