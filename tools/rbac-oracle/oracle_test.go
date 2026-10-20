package main

import (
	"slices"
	"strings"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
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
// Kubernetes behavior that causes them, and only to it, using the
// counterfactuals evalWorld uses.
func TestCounterfactualTags(t *testing.T) {
	const cycleWorld = "../../tests/rbac_compat/worlds/aggregation-cycle-own-rules"
	oracles := map[string]*Oracle{}
	for _, dir := range []string{smokeWorld, cycleWorld} {
		world, err := LoadWorld(dir)
		if err != nil {
			t.Fatal(err)
		}
		oracles[dir] = NewOracle(world)
		if err := addCounterfactuals(oracles[dir], dir); err != nil {
			t.Fatal(err)
		}
	}

	resource := func(username, namespace, resource, name, verb string) Request {
		return Request{User: username, Groups: authenticatedGroups(username), Namespace: namespace,
			Resource: resource, Name: name, Verb: verb}
	}
	tests := []struct {
		name    string
		world   string
		request Request
		tags    []string
	}{
		{"resourceNames", smokeWorld, resource("frank", "team-a", "configmaps", "other", "get"),
			[]string{"denied-by-resource-names"}},
		{"aggregation replaces own rules", smokeWorld, resource("erin", "team-a", "secrets", "", "get"),
			[]string{"denied-by-aggregation-replacing-rules"}},
		{"plain denial", smokeWorld, resource("alice", "team-a", "secrets", "", "get"), nil},
		{"own rule lost below a cycle", cycleWorld, resource("dave", "", "services", "", "list"),
			[]string{"denied-by-aggregation-replacing-rules"}},
		{"own rule lost above a cycle", cycleWorld, resource("erin", "", "nodes", "", "list"),
			[]string{"denied-by-aggregation-replacing-rules"}},
		// A role on a cycle is not recomputed under any variant.
		{"cycle role is not recomputed", cycleWorld, resource("alice", "", "configmaps", "", "get"), nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision, err := oracles[test.world].Decide(&test.request)
			if err != nil {
				t.Fatal(err)
			}
			var explanations []string
			for _, tag := range decision.Tags {
				if strings.HasPrefix(tag, "denied-by-") {
					explanations = append(explanations, tag)
				}
			}
			if decision.Allowed || !slices.Equal(explanations, test.tags) {
				t.Errorf("allowed = %v, explanations = %v, want denied with %v", decision.Allowed, explanations, test.tags)
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
		{"resourceNames empty string matches no name", resourceRequest("frank", "team-a", "", "pods", "", "", "list"), true},
		{"resourceNames empty string is a name, not any name", resourceRequest("frank", "team-a", "", "pods", "", "web", "get"), false},
		{"resourceNames empty string with another verb", resourceRequest("frank", "team-a", "", "pods", "", "", "delete"), false},
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
		{"cycle member a keeps its stored rules", resourceRequest("carol", "", "", "endpoints", "", "", "get"), true},
		{"cycle member b keeps its stored rules", resourceRequest("dave", "", "", "endpoints", "", "", "get"), true},
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
	})
}

func TestAggregationMatchAllLabelsDecisions(t *testing.T) {
	checkDecisions(t, "aggregation-match-all-labels", []decisionCase{
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

func TestAggregationCycleOwnRulesDecisions(t *testing.T) {
	checkDecisions(t, "aggregation-cycle-own-rules", []decisionCase{
		{"cycle role keeps its stored rule", resourceRequest("alice", "", "", "secrets", "", "", "get"), true},
		{"cycle role gets nothing from its partner", resourceRequest("alice", "", "", "configmaps", "", "", "get"), false},
		{"other cycle role keeps its stored rule", resourceRequest("bob", "", "", "configmaps", "", "", "get"), true},
		{"other cycle role gets nothing from its partner", resourceRequest("bob", "", "", "secrets", "", "", "get"), false},
		{"aggregator of a cycle role gets its stored rule", resourceRequest("erin", "", "", "secrets", "", "", "get"), true},
		{"aggregator of a cycle role loses its own rule", resourceRequest("erin", "", "", "nodes", "", "", "list"), false},
		{"aggregator of a cycle role does not reach around it", resourceRequest("erin", "", "", "configmaps", "", "", "get"), false},
		{"cycle role above a chain keeps its stored rule", resourceRequest("grace", "", "", "pods", "", "", "get"), true},
		{"cycle role above a chain is not recomputed", resourceRequest("grace", "", "", "services", "", "", "list"), false},
		{"cycle role with empty stored rules grants nothing", resourceRequest("carol", "", "", "pods", "", "", "get"), false},
		{"role below the cycle loses its own rule", resourceRequest("dave", "", "", "services", "", "", "list"), false},
		{"role below the cycle gets its source", resourceRequest("dave", "", "", "pods", "", "", "get"), true},
		{"aggregating an empty cycle role keeps own rules", resourceRequest("frank", "", "", "nodes", "", "", "list"), true},
		{"aggregating an empty cycle role gets nothing else", resourceRequest("frank", "", "", "pods", "", "", "get"), false},
	})
}

// TestAggregationCycleVisitOrder shows why roles on an aggregation cycle
// keep their stored rules rather than being recomputed. Two ClusterRoles
// select each other, one with a secrets rule and one with a configmaps
// rule. Running the controller's sync over them, the rule that survives
// depends on which role it visits first, so there is no single answer to
// recompute. NewWorld leaves both roles as written.
func TestAggregationCycleVisitOrder(t *testing.T) {
	secrets := rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}}
	configmaps := rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get"}}
	role := func(name, selects string, rule rbacv1.PolicyRule) *rbacv1.ClusterRole {
		return &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{"cycle": name}},
			AggregationRule: &rbacv1.AggregationRule{ClusterRoleSelectors: []metav1.LabelSelector{
				{MatchLabels: map[string]string{"cycle": selects}},
			}},
			Rules: []rbacv1.PolicyRule{rule},
		}
	}
	roles := func() []*rbacv1.ClusterRole {
		return []*rbacv1.ClusterRole{role("a", "b", secrets), role("b", "a", configmaps)}
	}

	world, err := NewWorld([]runtime.Object{roles()[0], roles()[1]}, kubernetesSemantics)
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range world.ClusterRoles {
		if !world.AggregationCycleRoles[role.Name] || len(role.Rules) != 1 {
			t.Errorf("NewWorld: %s on cycle = %v with rules %v, want kept as written",
				role.Name, world.AggregationCycleRoles[role.Name], role.Rules)
		}
	}

	// Whichever role is visited first copies the other's rule, then the
	// other copies it back: the second role's rule survives on both.
	for _, test := range []struct {
		order    []string
		survivor rbacv1.PolicyRule
	}{
		{[]string{"a", "b"}, configmaps},
		{[]string{"b", "a"}, secrets},
	} {
		byName := map[string]*rbacv1.ClusterRole{}
		for _, role := range roles() {
			byName[role.Name] = role
		}
		simulated := &World{AggregatedRoles: map[string]bool{}}
		for _, name := range test.order {
			simulated.ClusterRoles = append(simulated.ClusterRoles, byName[name])
		}
		simulated.syncAggregatedRoles(nil, nil)
		for _, role := range simulated.ClusterRoles {
			if !equality.Semantic.DeepEqual(role.Rules, []rbacv1.PolicyRule{test.survivor}) {
				t.Errorf("visiting %v: %s has %v, want only %v", test.order, role.Name, role.Rules, test.survivor)
			}
		}
	}
}
