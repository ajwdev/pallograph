package main

import (
	"testing"
)

const smokeWorld = "../../tests/rbac_compat/worlds/smoke"

// TestSmokeDecisions pins hand-checked decisions for the smoke world, so a
// change to world loading, aggregation or request attributes that bends
// the oracle away from kube-apiserver semantics fails here.
func TestSmokeDecisions(t *testing.T) {
	world, err := LoadWorld(smokeWorld)
	if err != nil {
		t.Fatal(err)
	}
	oracle := NewOracle(world)

	resource := func(username, namespace, group, resource, subresource, name, verb string) Request {
		return Request{User: username, Groups: authenticatedGroups(username), Namespace: namespace,
			APIGroup: group, Resource: resource, Subresource: subresource, Name: name, Verb: verb}
	}
	nonResource := func(username, path string, groups ...string) Request {
		return Request{User: username, Groups: authenticatedGroups(username, groups...), Path: path, Verb: "get"}
	}
	deployer := serviceAccountUsername("team-a", "deployer")

	tests := []struct {
		name    string
		request Request
		allowed bool
	}{
		{"role in its namespace", resource("alice", "team-a", "", "pods", "", "", "get"), true},
		{"role outside its namespace", resource("alice", "team-b", "", "pods", "", "", "get"), false},
		{"listed subresource", resource("alice", "team-a", "", "pods", "log", "", "list"), true},
		{"unlisted subresource", resource("alice", "team-a", "", "pods", "exec", "", "get"), false},
		{"serviceaccount namespace defaulted", resource(deployer, "team-a", "", "configmaps", "", "app-config", "get"), true},
		{"resourceNames excludes other name", resource(deployer, "team-a", "", "configmaps", "", "other", "get"), false},
		{"resourceNames excludes unnamed list", resource(deployer, "team-a", "", "configmaps", "", "", "list"), false},
		{"resourceNames for a user", resource("frank", "team-a", "", "configmaps", "", "app-config", "update"), true},
		{"resourceNames for a user excludes other name", resource("frank", "team-a", "", "configmaps", "", "other", "update"), false},
		{"wildcard subresource and verb", resource("bob", "team-b", "apps", "deployments", "scale", "", "patch"), true},
		{"wildcard subresource needs subresource", resource("bob", "team-b", "apps", "deployments", "", "", "get"), false},
		{"rolebinding to clusterrole is namespaced", resource("bob", "", "apps", "deployments", "scale", "", "get"), false},
		{"resource/* is not a wildcard", resource("bob", "team-b", "apps", "deployments", "log", "", "get"), false},
		{"nonResourceURL literal", nonResource("member-of-monitoring", "/metrics", "monitoring"), true},
		{"nonResourceURL prefix", nonResource("member-of-monitoring", "/debug/pprof/heap", "monitoring"), true},
		{"nonResourceURL prefix needs separator", nonResource("member-of-monitoring", "/debugger", "monitoring"), false},
		{"system:authenticated", nonResource("anyone", "/healthz"), true},
		{"anonymous is not authenticated", nonResource("system:anonymous", "/healthz"), false},
		{"system:serviceaccounts:<ns>", resource(serviceAccountUsername("team-b", "x"), "", "", "namespaces", "", "", "list"), true},
		{"system:serviceaccounts:<ns> other ns", resource(serviceAccountUsername("team-c", "x"), "", "", "namespaces", "", "", "list"), false},
		{"aggregation replaces own rules", resource("erin", "team-a", "", "secrets", "", "", "get"), false},
		{"aggregated rules", resource("erin", "team-a", "", "services", "", "", "delete"), true},
		{"chained aggregation", resource("carol", "team-a", "", "services", "", "", "create"), true},
		{"empty selector matches all clusterroles", resource("dave", "", "", "namespaces", "", "", "list"), true},
		{"empty selector pulls in superuser", resource("dave", "team-a", "x.example.com", "things", "", "", "delete"), true},
		{"full wildcard", resource(serviceAccountUsername("ops", "ops"), "team-a", "x.example.com", "things", "", "", "delete"), true},
		{"full wildcard nonResourceURL", nonResource(serviceAccountUsername("ops", "ops"), "/anything"), true},
		{"serviceaccount name in other namespace", resource(serviceAccountUsername("team-a", "ops"), "team-a", "", "pods", "", "", "get"), false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision, err := oracle.Decide(&test.request)
			if err != nil {
				t.Fatal(err)
			}
			if decision.Allowed != test.allowed {
				t.Errorf("allowed = %v, want %v (reason %q, tags %v)",
					decision.Allowed, test.allowed, decision.Reason, decision.Tags)
			}
		})
	}
}
