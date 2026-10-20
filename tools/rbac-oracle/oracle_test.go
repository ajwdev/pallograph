package main

import (
	"slices"
	"strings"
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

// TestCounterfactualTags checks that denials are attributed to the
// Kubernetes behavior that causes them, and only to it.
func TestCounterfactualTags(t *testing.T) {
	world, err := LoadWorld(smokeWorld)
	if err != nil {
		t.Fatal(err)
	}
	oracle := NewOracle(world)
	for _, counterfactual := range []struct {
		tag     string
		variant worldVariant
	}{
		{"denied-by-resource-names", withoutResourceNames},
		{"denied-by-aggregation-replacing-rules", aggregationKeepsOwnRules},
	} {
		variantWorld, err := loadWorld(smokeWorld, counterfactual.variant)
		if err != nil {
			t.Fatal(err)
		}
		oracle.AddCounterfactual(counterfactual.tag, variantWorld, false)
	}

	resource := func(username, resource, name, verb string) Request {
		return Request{User: username, Groups: authenticatedGroups(username), Namespace: "team-a",
			Resource: resource, Name: name, Verb: verb}
	}
	tests := []struct {
		name    string
		request Request
		tag     string
	}{
		{"resourceNames", resource("frank", "configmaps", "other", "get"), "denied-by-resource-names"},
		{"aggregation replaces own rules", resource("erin", "secrets", "", "get"), "denied-by-aggregation-replacing-rules"},
		{"plain denial", resource("alice", "secrets", "", "get"), ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision, err := oracle.Decide(&test.request)
			if err != nil {
				t.Fatal(err)
			}
			var explanations []string
			for _, tag := range decision.Tags {
				if strings.HasPrefix(tag, "denied-by-") {
					explanations = append(explanations, tag)
				}
			}
			var want []string
			if test.tag != "" {
				want = []string{test.tag}
			}
			if decision.Allowed || !slices.Equal(explanations, want) {
				t.Errorf("allowed = %v, explanations = %v, want denied with %v", decision.Allowed, explanations, want)
			}
		})
	}
}

// TestAggregationWithoutSources pins a case found against a live cluster:
// an aggregated ClusterRole whose selectors match nothing keeps its own
// rules, while one with a source has them replaced.
func TestAggregationWithoutSources(t *testing.T) {
	world, err := LoadWorld("../../tests/rbac_compat/worlds/aggregation-without-sources")
	if err != nil {
		t.Fatal(err)
	}
	oracle := NewOracle(world)
	tests := []struct {
		name    string
		user    string
		allowed bool
	}{
		{"no sources keeps own rules", "grace", true},
		{"a source replaces own rules", "heidi", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := Request{User: test.user, Groups: authenticatedGroups(test.user),
				Namespace: "default", Resource: "configmaps", Verb: "get"}
			decision, err := oracle.Decide(&request)
			if err != nil {
				t.Fatal(err)
			}
			if decision.Allowed != test.allowed {
				t.Errorf("allowed = %v, want %v (reason %q)", decision.Allowed, test.allowed, decision.Reason)
			}
		})
	}
}

// decisionCase is one hand-checked decision in a curated world.
type decisionCase struct {
	name    string
	request Request
	allowed bool
}

// resourceRequest and nonResourceRequest build requests the way the
// authenticator presents them: the username with its implicit groups,
// plus any extra ones.
func resourceRequest(username, namespace, group, resource, subresource, name, verb string, groups ...string) Request {
	return Request{User: username, Groups: authenticatedGroups(username, groups...), Namespace: namespace,
		APIGroup: group, Resource: resource, Subresource: subresource, Name: name, Verb: verb}
}

func nonResourceRequest(username, path string, groups ...string) Request {
	return Request{User: username, Groups: authenticatedGroups(username, groups...), Path: path, Verb: "get"}
}

// checkDecisions loads the curated world named world and checks each
// case's decision.
func checkDecisions(t *testing.T, world string, tests []decisionCase) {
	t.Helper()
	loaded, err := LoadWorld("../../tests/rbac_compat/worlds/" + world)
	if err != nil {
		t.Fatal(err)
	}
	oracle := NewOracle(loaded)
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

func TestNamesURLsSubresourcesDecisions(t *testing.T) {
	urlReader := func(path string) Request {
		return nonResourceRequest("member-of-url-readers", path, "url-readers")
	}
	checkDecisions(t, "names-urls-subresources", []decisionCase{
		{"empty resourceNames grants a name", resourceRequest("alice", "team-a", "", "configmaps", "", "anything", "get"), true},
		{"empty resourceNames grants no name", resourceRequest("alice", "team-a", "", "configmaps", "", "", "get"), true},
		{"resourceNames star is the literal name", resourceRequest("bob", "team-a", "", "secrets", "", "*", "get"), true},
		{"resourceNames star is not a wildcard", resourceRequest("bob", "team-a", "", "secrets", "", "db-password", "get"), false},
		{"resourceNames star needs a name", resourceRequest("bob", "team-a", "", "secrets", "", "", "get"), false},
		{"*/scale on a core resource", resourceRequest("carol", "team-a", "", "replicationcontrollers", "scale", "", "update"), true},
		{"*/scale on apps", resourceRequest("carol", "", "apps", "deployments", "scale", "web", "get"), true},
		{"*/scale is not the resource", resourceRequest("carol", "team-a", "apps", "deployments", "", "", "get"), false},
		{"*/scale is not another subresource", resourceRequest("carol", "team-a", "apps", "deployments", "status", "", "get"), false},
		{"pods/* matches the literal subresource", resourceRequest("carol", "team-a", "", "pods", "*", "", "get"), true},
		{"pods/* is not a wildcard", resourceRequest("carol", "team-a", "", "pods", "log", "", "get"), false},
		{"pods/* is not pods", resourceRequest("carol", "team-a", "", "pods", "", "", "get"), false},
		{"exact URL", urlReader("/healthz"), true},
		{"exact URL is not a prefix", urlReader("/healthz/ready"), false},
		{"prefix URL", urlReader("/debug/pprof"), true},
		{"prefix URL matches the bare prefix", urlReader("/debug/"), true},
		{"prefix URL needs the separator", urlReader("/debug"), false},
		{"double star strips both", urlReader("/double/x"), true},
		{"double star prefix", urlReader("/double/"), true},
		{"interior star is literal", urlReader("/foo/*/bar"), true},
		{"interior star is not a wildcard", urlReader("/foo/x/bar"), false},
		{"interior star with trailing prefix", urlReader("/logs/*/tail/today"), true},
		{"interior star with trailing prefix is literal", urlReader("/logs/app/tail/today"), false},
		{"URL rules need the group", nonResourceRequest("url-readers", "/healthz"), false},
		{"star URL", nonResourceRequest("dave", "/anything/at/all"), true},
		{"star URL with another verb", Request{User: "dave", Groups: authenticatedGroups("dave"), Path: "/healthz", Verb: "post"}, false},
		{"URL rules via a RoleBinding", nonResourceRequest("erin", "/metrics"), false},
		{"URL prefix via a RoleBinding", nonResourceRequest("erin", "/version/x"), false},
	})
}

func TestAggregationShapesDecisions(t *testing.T) {
	checkDecisions(t, "aggregation-shapes", []decisionCase{
		{"chain reaches the bottom", resourceRequest("alice", "team-a", "", "services", "", "", "get"), true},
		{"chain replaces the top's own rules", resourceRequest("alice", "team-a", "", "configmaps", "", "", "list"), false},
		{"chain replaces the middle's own rules", resourceRequest("alice", "team-a", "", "secrets", "", "", "get"), false},
		{"chain middle via a RoleBinding", resourceRequest("bob", "team-a", "", "services", "", "", "get"), true},
		{"chain middle loses its own rules", resourceRequest("bob", "team-a", "", "secrets", "", "", "get"), false},
		{"cycle member a gets the source", resourceRequest("carol", "", "", "endpoints", "", "", "get"), true},
		{"cycle member b gets the source", resourceRequest("dave", "", "", "endpoints", "", "", "get"), true},
		{"cycle adds nothing else", resourceRequest("dave", "", "", "endpoints", "", "", "list"), false},
		{"ruleless source keeps own rules", resourceRequest("erin", "team-a", "", "pods", "", "", "list"), true},
		{"aggregating a role that kept its own rules", resourceRequest("frank", "team-a", "", "pods", "", "", "get"), true},
		{"two selectors union", resourceRequest("grace", "team-a", "", "services", "", "", "get"), true},
		{"two selectors replace own rules", resourceRequest("grace", "team-a", "", "secrets", "", "", "list"), false},
	})
}

func TestAggregationMatchAllDecisions(t *testing.T) {
	checkDecisions(t, "aggregation-match-all", []decisionCase{
		{"empty selector gets an unlabelled source", resourceRequest("alice", "team-a", "", "pods", "", "", "get"), true},
		{"empty selector gets a labelled source", resourceRequest("alice", "", "apps", "deployments", "", "", "list"), true},
		{"empty selector gets URL rules", nonResourceRequest("alice", "/healthz"), true},
		{"empty selector grants nothing else", resourceRequest("alice", "team-a", "", "secrets", "", "", "get"), false},
		{"empty matchLabels gets an unlabelled source", resourceRequest("bob", "team-a", "", "pods", "", "", "get"), true},
		{"empty matchLabels gets a labelled source", resourceRequest("bob", "team-a", "apps", "deployments", "", "", "list"), true},
		{"empty matchLabels via a RoleBinding is namespaced", resourceRequest("bob", "team-b", "", "pods", "", "", "get"), false},
		{"empty matchLabels URL rules via a RoleBinding", nonResourceRequest("bob", "/healthz"), false},
	})
}

func TestSubjectsAndGroupsDecisions(t *testing.T) {
	serviceAccount := func(namespace, name, requestNamespace, resource, verb string) Request {
		return resourceRequest(serviceAccountUsername(namespace, name), requestNamespace, "", resource, "", "", verb)
	}
	checkDecisions(t, "subjects-and-groups", []decisionCase{
		{"user ops", resourceRequest("ops", "team-a", "", "pods", "", "", "get"), true},
		{"user ops is not group ops", resourceRequest("ops", "team-a", "", "secrets", "", "", "get"), false},
		{"group ops", resourceRequest("member-of-ops", "team-a", "", "secrets", "", "", "get", "ops"), true},
		{"group ops is not user ops", resourceRequest("member-of-ops", "team-a", "", "pods", "", "", "get", "ops"), false},
		{"system:serviceaccounts:<ns>", serviceAccount("team-a", "any", "team-b", "configmaps", "get"), true},
		{"system:serviceaccounts:<ns> other namespace", serviceAccount("team-b", "any", "team-b", "configmaps", "get"), false},
		{"system:serviceaccounts:<ns> needs a service account", resourceRequest("team-a", "team-a", "", "configmaps", "", "", "get"), false},
		{"system:serviceaccounts", serviceAccount("elsewhere", "any", "team-b", "services", "get"), true},
		{"system:serviceaccounts via a RoleBinding is namespaced", serviceAccount("elsewhere", "any", "team-a", "services", "get"), false},
		{"system:serviceaccounts needs a service account", resourceRequest("alice", "team-b", "", "services", "", "", "get"), false},
		{"system:authenticated includes service accounts", serviceAccount("elsewhere", "any", "", "namespaces", "list"), true},
		{"system:authenticated includes users", resourceRequest("alice", "", "", "namespaces", "", "", "list"), true},
		{"system:authenticated excludes anonymous", resourceRequest("system:anonymous", "", "", "namespaces", "", "", "list"), false},
		{"service account from another namespace", serviceAccount("team-b", "builder", "team-a", "pods", "get"), true},
		{"service account from another namespace, not its own", serviceAccount("team-b", "builder", "team-b", "pods", "get"), false},
		{"same service account name in the binding namespace", serviceAccount("team-a", "builder", "team-a", "pods", "get"), false},
	})
}
