package policy_test

// Tests for the RBAC Datalog rules in rules/rbac.mg.
//
// Each test builds a minimal set of Kubernetes RBAC facts, runs the policy
// engine, and asserts that the derived predicates match known-correct
// expectations.  No real cluster or external RBAC evaluator is used.
//
// verb_type/1 is derived from verbs that appear in any Role or ClusterRole.
// Tests that exercise can_i wildcard-verb expansion include an unbound
// ClusterRole (not connected to any subject) whose sole purpose is to
// populate verb_type with the verbs being tested.

import (
	"context"
	"os"
	"testing"

	"github.com/ajwdev/pallograph/pkg/policy"
	"github.com/google/mangle/ast"
	"github.com/google/mangle/json2struct"
	"github.com/google/mangle/parse"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---- Rule loading ----

func loadRBACRules(t *testing.T) []parse.SourceUnit {
	t.Helper()
	f, err := os.Open("../../rules/rbac.mg")
	require.NoError(t, err)
	defer f.Close()
	unit, err := parse.Unit(f)
	require.NoError(t, err)
	return []parse.SourceUnit{unit}
}

func rbacKnownPreds() map[ast.PredicateSym]ast.Decl {
	decl := func(sym string, arity int) ast.Decl {
		pred := ast.PredicateSym{Symbol: sym, Arity: arity}
		return ast.Decl{DeclaredAtom: ast.Atom{Predicate: pred}}
	}
	return map[ast.PredicateSym]ast.Decl{
		{Symbol: "k8s", Arity: 5}:          decl("k8s", 5),
		{Symbol: "user_groups", Arity: 2}:  decl("user_groups", 2),
		{Symbol: "api_resource", Arity: 2}: decl("api_resource", 2),
	}
}

// ---- Fact atom builders ----

func k8sAtom(t *testing.T, obj map[string]any) ast.Atom {
	t.Helper()
	mangleStruct, err := json2struct.ConvertValue(obj)
	require.NoError(t, err)
	metadata := obj["metadata"].(map[string]any)
	namespace, _ := metadata["namespace"].(string)
	return ast.Atom{
		Predicate: ast.PredicateSym{Symbol: "k8s", Arity: 5},
		Args: []ast.BaseTerm{
			ast.String(obj["apiVersion"].(string)),
			ast.String(obj["kind"].(string)),
			ast.String(namespace),
			ast.String(metadata["name"].(string)),
			mangleStruct,
		},
	}
}

func apiResourceAtom(apiGroup, resource string) ast.Atom {
	return ast.Atom{
		Predicate: ast.PredicateSym{Symbol: "api_resource", Arity: 2},
		Args:      []ast.BaseTerm{ast.String(apiGroup), ast.String(resource)},
	}
}

func userGroupAtom(username, group string) ast.Atom {
	return ast.Atom{
		Predicate: ast.PredicateSym{Symbol: "user_groups", Arity: 2},
		Args:      []ast.BaseTerm{ast.String(username), ast.String(group)},
	}
}

// ---- Kubernetes object builders ----

func toAnySlice[T any](ss []T) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

func policyRule(apiGroups, resources, verbs []string) map[string]any {
	return map[string]any{
		"apiGroups": toAnySlice(apiGroups),
		"resources": toAnySlice(resources),
		"verbs":     toAnySlice(verbs),
	}
}

func clusterRoleObj(name string, rules ...map[string]any) map[string]any {
	return map[string]any{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "ClusterRole",
		"metadata":   map[string]any{"name": name},
		"rules":      toAnySlice(rules),
	}
}

func roleObj(namespace, name string, rules ...map[string]any) map[string]any {
	return map[string]any{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "Role",
		"metadata":   map[string]any{"name": name, "namespace": namespace},
		"rules":      toAnySlice(rules),
	}
}

func clusterRoleBindingObj(name, roleName string, subjects ...map[string]any) map[string]any {
	return map[string]any{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "ClusterRoleBinding",
		"metadata":   map[string]any{"name": name},
		"roleRef": map[string]any{
			"apiGroup": "rbac.authorization.k8s.io",
			"kind":     "ClusterRole",
			"name":     roleName,
		},
		"subjects": toAnySlice(subjects),
	}
}

func roleBindingObj(namespace, name, roleKind, roleName string, subjects ...map[string]any) map[string]any {
	return map[string]any{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "RoleBinding",
		"metadata":   map[string]any{"name": name, "namespace": namespace},
		"roleRef": map[string]any{
			"apiGroup": "rbac.authorization.k8s.io",
			"kind":     roleKind,
			"name":     roleName,
		},
		"subjects": toAnySlice(subjects),
	}
}

func userSubject(name string) map[string]any {
	return map[string]any{"kind": "User", "name": name, "apiGroup": "rbac.authorization.k8s.io"}
}

func groupSubject(name string) map[string]any {
	return map[string]any{"kind": "Group", "name": name, "apiGroup": "rbac.authorization.k8s.io"}
}

func saSubject(namespace, name string) map[string]any {
	return map[string]any{"kind": "ServiceAccount", "name": name, "namespace": namespace}
}

// ---- Engine builder ----

func rbacEngine(t *testing.T, facts ...ast.Atom) *policy.Engine {
	t.Helper()
	engine, err := policy.New(makeStore(facts...), loadRBACRules(t), rbacKnownPreds())
	require.NoError(t, err)
	return engine
}

// ---- Tests ----

// TestRBAC_UserClusterRoleBinding: user bound directly to a ClusterRole via
// ClusterRoleBinding gets the expected can_i results.
func TestRBAC_UserClusterRoleBinding(t *testing.T) {
	engine := rbacEngine(t,
		k8sAtom(t, clusterRoleObj("reader",
			policyRule([]string{""}, []string{"pods"}, []string{"get", "list"}),
		)),
		k8sAtom(t, clusterRoleBindingObj("alice-reader", "reader", userSubject("alice"))),
		apiResourceAtom("", "pods"),
	)

	get := &collectHandler{}
	list := &collectHandler{}
	require.NoError(t, engine.RegisterQuery(`can_i("alice", "pods", "get")`, get))
	require.NoError(t, engine.RegisterQuery(`can_i("alice", "pods", "list")`, list))
	assert.NoError(t, engine.Evaluate(context.Background()))

	assert.Len(t, get.violations, 1)
	assert.Len(t, list.violations, 1)
}

// TestRBAC_UserClusterRoleBinding_NoUnboundPerms: alice should not have
// permissions on resources she was never granted.
func TestRBAC_UserClusterRoleBinding_NoUnboundPerms(t *testing.T) {
	engine := rbacEngine(t,
		k8sAtom(t, clusterRoleObj("reader",
			policyRule([]string{""}, []string{"pods"}, []string{"get"}),
		)),
		k8sAtom(t, clusterRoleBindingObj("alice-reader", "reader", userSubject("alice"))),
		apiResourceAtom("", "pods"),
		apiResourceAtom("", "secrets"),
	)

	// alice was granted nothing on secrets
	h := &collectHandler{}
	require.NoError(t, engine.RegisterQuery(`all_user_perm("alice", X0, "secrets", X1)`, h))
	assert.NoError(t, engine.Evaluate(context.Background()))

	assert.Empty(t, h.violations)
}

// TestRBAC_UserRoleBinding: user bound to a namespace-scoped Role via
// RoleBinding gets namespace-scoped permissions only.
func TestRBAC_UserRoleBinding(t *testing.T) {
	engine := rbacEngine(t,
		k8sAtom(t, roleObj("dev", "config-reader",
			policyRule([]string{""}, []string{"configmaps"}, []string{"get", "list"}),
		)),
		k8sAtom(t, roleBindingObj("dev", "bob-binding", "Role", "config-reader",
			userSubject("bob"),
		)),
		apiResourceAtom("", "configmaps"),
	)

	nsScoped := &collectHandler{}
	clusterWide := &collectHandler{}
	require.NoError(t, engine.RegisterQuery(`user_role_perm("bob", "dev", "", "configmaps", "get")`, nsScoped))
	// RoleBinding should not produce cluster-wide perms
	require.NoError(t, engine.RegisterQuery(`user_crb_perm("bob", "", "configmaps", "get")`, clusterWide))
	assert.NoError(t, engine.Evaluate(context.Background()))

	assert.Len(t, nsScoped.violations, 1)
	assert.Empty(t, clusterWide.violations)
}

// TestRBAC_UserRoleBindingToClusterRole: binding a ClusterRole via a
// RoleBinding scopes its permissions to that namespace only.
func TestRBAC_UserRoleBindingToClusterRole(t *testing.T) {
	engine := rbacEngine(t,
		k8sAtom(t, clusterRoleObj("secret-reader",
			policyRule([]string{""}, []string{"secrets"}, []string{"get"}),
		)),
		k8sAtom(t, roleBindingObj("staging", "carol-binding", "ClusterRole", "secret-reader",
			userSubject("carol"),
		)),
		apiResourceAtom("", "secrets"),
	)

	nsScoped := &collectHandler{}
	clusterWide := &collectHandler{}
	require.NoError(t, engine.RegisterQuery(`user_rb_clusterrole_perm("carol", "staging", "", "secrets", "get")`, nsScoped))
	require.NoError(t, engine.RegisterQuery(`user_crb_perm("carol", "", "secrets", "get")`, clusterWide))
	assert.NoError(t, engine.Evaluate(context.Background()))

	assert.Len(t, nsScoped.violations, 1)
	assert.Empty(t, clusterWide.violations)
}

// TestRBAC_GroupInheritedPermissions: a user inherits permissions from groups
// listed in user_groups/2.
func TestRBAC_GroupInheritedPermissions(t *testing.T) {
	engine := rbacEngine(t,
		k8sAtom(t, clusterRoleObj("secret-reader",
			policyRule([]string{""}, []string{"secrets"}, []string{"get", "list"}),
		)),
		k8sAtom(t, clusterRoleBindingObj("developers-secret-reader", "secret-reader",
			groupSubject("developers"),
		)),
		userGroupAtom("dave", "developers"),
		apiResourceAtom("", "secrets"),
	)

	h := &collectHandler{}
	require.NoError(t, engine.RegisterQuery(`can_i("dave", "secrets", "get")`, h))
	assert.NoError(t, engine.Evaluate(context.Background()))

	assert.Len(t, h.violations, 1)
}

// TestRBAC_GroupInheritedPermissions_NonMember: a user not in the group
// does not inherit the group's permissions.
func TestRBAC_GroupInheritedPermissions_NonMember(t *testing.T) {
	engine := rbacEngine(t,
		k8sAtom(t, clusterRoleObj("secret-reader",
			policyRule([]string{""}, []string{"secrets"}, []string{"get"}),
		)),
		k8sAtom(t, clusterRoleBindingObj("developers-secret-reader", "secret-reader",
			groupSubject("developers"),
		)),
		// eve is NOT in the developers group
		apiResourceAtom("", "secrets"),
	)

	h := &collectHandler{}
	require.NoError(t, engine.RegisterQuery(`all_user_perm("eve", X0, "secrets", X1)`, h))
	assert.NoError(t, engine.Evaluate(context.Background()))

	assert.Empty(t, h.violations)
}

// TestRBAC_WildcardResource: a role with "*" resource grants access to all
// specific resource types via can_i wildcard expansion.
func TestRBAC_WildcardResource(t *testing.T) {
	engine := rbacEngine(t,
		k8sAtom(t, clusterRoleObj("all-reader",
			policyRule([]string{"*"}, []string{"*"}, []string{"get", "list"}),
		)),
		k8sAtom(t, clusterRoleBindingObj("eve-all", "all-reader", userSubject("eve"))),
		apiResourceAtom("", "pods"),
		apiResourceAtom("", "secrets"),
		apiResourceAtom("apps", "deployments"),
	)

	h := &collectHandler{}
	require.NoError(t, engine.RegisterQuery(`can_i("eve", "pods", "get")`, h))
	require.NoError(t, engine.RegisterQuery(`can_i("eve", "secrets", "get")`, h))
	require.NoError(t, engine.RegisterQuery(`can_i("eve", "deployments", "list")`, h))
	assert.NoError(t, engine.Evaluate(context.Background()))

	assert.Len(t, h.violations, 3)
}

// TestRBAC_WildcardVerb: a role with "*" verb grants access for all specific
// verbs via can_i wildcard expansion.
func TestRBAC_WildcardVerb(t *testing.T) {
	engine := rbacEngine(t,
		k8sAtom(t, clusterRoleObj("pod-admin",
			policyRule([]string{""}, []string{"pods"}, []string{"*"}),
		)),
		// Unbound role: populates verb_type so wildcard expansion has verbs to enumerate.
		k8sAtom(t, clusterRoleObj("__verbs",
			policyRule([]string{"*"}, []string{"*"}, []string{"get", "list", "delete"}),
		)),
		k8sAtom(t, clusterRoleBindingObj("frank-pod-admin", "pod-admin", userSubject("frank"))),
		apiResourceAtom("", "pods"),
	)

	h := &collectHandler{}
	require.NoError(t, engine.RegisterQuery(`can_i("frank", "pods", "get")`, h))
	require.NoError(t, engine.RegisterQuery(`can_i("frank", "pods", "delete")`, h))
	assert.NoError(t, engine.Evaluate(context.Background()))

	assert.Len(t, h.violations, 2)
}

// TestRBAC_NoBindings: a user with no bindings has no permissions.
func TestRBAC_NoBindings(t *testing.T) {
	engine := rbacEngine(t,
		// Some roles and bindings exist, but grace is not a subject in any.
		k8sAtom(t, clusterRoleObj("reader",
			policyRule([]string{""}, []string{"pods"}, []string{"get"}),
		)),
		k8sAtom(t, clusterRoleBindingObj("alice-reader", "reader", userSubject("alice"))),
		apiResourceAtom("", "pods"),
	)

	h := &collectHandler{}
	require.NoError(t, engine.RegisterQuery(`all_user_perm("grace", X0, X1, X2)`, h))
	assert.NoError(t, engine.Evaluate(context.Background()))

	assert.Empty(t, h.violations)
}

// TestRBAC_ServiceAccountPermissions: an SA bound to a ClusterRole via
// ClusterRoleBinding gets the expected permissions.
func TestRBAC_ServiceAccountPermissions(t *testing.T) {
	engine := rbacEngine(t,
		k8sAtom(t, clusterRoleObj("pod-reader",
			policyRule([]string{""}, []string{"pods"}, []string{"get", "list", "watch"}),
		)),
		k8sAtom(t, clusterRoleBindingObj("myapp-pod-reader", "pod-reader",
			saSubject("production", "myapp"),
		)),
		apiResourceAtom("", "pods"),
	)

	h := &collectHandler{}
	require.NoError(t, engine.RegisterQuery(`sa_crb_perm("production", "myapp", "", "pods", "get")`, h))
	assert.NoError(t, engine.Evaluate(context.Background()))

	assert.Len(t, h.violations, 1)
}
