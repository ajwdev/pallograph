package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/yaml"
)

// The palette random worlds draw from. It is deliberately small, so that
// rules collide and overlap, and it covers every matching feature the
// authorizer has, including the ones that look like features but are not
// ("pods/*" is a literal subresource, "*" in resourceNames a literal name
// and an interior "*" in a URL a literal character, none of them
// wildcards). The group "user-1" shares its name with a user, which the
// authorizer keeps apart.
var (
	fuzzNamespaces   = []string{"ns-a", "ns-b"}
	fuzzAPIGroups    = []string{"", "", "apps", "batch", "example.com", rbacv1.APIGroupAll}
	fuzzResources    = []string{"pods", "configmaps", "secrets", "deployments", "jobs", "pods/exec", "pods/log", "deployments/scale", "*/scale", "pods/*", rbacv1.ResourceAll}
	fuzzVerbs        = []string{"get", "list", "create", "delete", "patch", rbacv1.VerbAll}
	fuzzNames        = []string{"alpha", "beta", "*"}
	fuzzURLs         = []string{"/healthz", "/metrics", "/debug/*", "/debug/**", "/api", "/api/*", "/api/*/status", rbacv1.NonResourceAll}
	fuzzUsers        = []string{"user-1", "user-2", "user-3"}
	fuzzGroups       = []string{"group-1", "group-2", "user-1", "system:authenticated", "system:unauthenticated", "system:serviceaccounts", "system:serviceaccounts:ns-a"}
	fuzzSAs          = []string{"sa-1", "sa-2"}
	fuzzLabelKeys    = []string{"fuzz.pallograph.dev/agg-x", "fuzz.pallograph.dev/agg-y"}
	fuzzMissingRoles = "missing-role"

	// Escalation rules: impersonation and writing RBAC objects, with
	// resourceNames that name the world's own identities and roles.
	fuzzEscalationAPIGroups = []string{"", rbacv1.GroupName, rbacv1.APIGroupAll}
	fuzzEscalationResources = []string{"users", "groups", "serviceaccounts", "clusterroles", "clusterrolebindings", "roles", "rolebindings", rbacv1.ResourceAll}
	fuzzEscalationVerbs     = []string{"impersonate", "bind", "escalate", "create", "update", "patch", rbacv1.VerbAll}
	fuzzEscalationNames     = []string{"user-1", "group-1", "sa-1", "clusterrole-0", "role-0"}
)

// fuzzWorld builds one random world from random. Every object it returns
// must pass API validation; LoadWorld enforces that when the world is read.
func fuzzWorld(random *rand.Rand) []runtime.Object {
	var objects []runtime.Object
	pick := func(values []string) string { return values[random.IntN(len(values))] }
	pickSome := func(values []string, maximum int) []string {
		count := 1 + random.IntN(maximum)
		chosen := map[string]bool{}
		var result []string
		for len(result) < count {
			value := pick(values)
			if !chosen[value] {
				chosen[value] = true
				result = append(result, value)
			}
			if len(chosen) == len(values) {
				break
			}
		}
		return result
	}
	chance := func(percent int) bool { return random.IntN(100) < percent }

	escalationRule := func() rbacv1.PolicyRule {
		rule := rbacv1.PolicyRule{
			APIGroups: pickSome(fuzzEscalationAPIGroups, 2),
			Resources: pickSome(fuzzEscalationResources, 2),
			Verbs:     pickSome(fuzzEscalationVerbs, 3),
		}
		if chance(25) {
			rule.ResourceNames = pickSome(fuzzEscalationNames, 2)
		}
		return rule
	}
	resourceRule := func() rbacv1.PolicyRule {
		if chance(20) {
			return escalationRule()
		}
		rule := rbacv1.PolicyRule{
			APIGroups: pickSome(fuzzAPIGroups, 2),
			Resources: pickSome(fuzzResources, 2),
			Verbs:     pickSome(fuzzVerbs, 3),
		}
		switch {
		case chance(25):
			rule.ResourceNames = pickSome(fuzzNames, 2)
		case chance(10):
			// Written as "resourceNames: []", which grants every name.
			rule.ResourceNames = []string{emptyResourceNames}
		}
		return rule
	}
	nonResourceRule := func() rbacv1.PolicyRule {
		return rbacv1.PolicyRule{NonResourceURLs: pickSome(fuzzURLs, 2), Verbs: pickSome(fuzzVerbs, 2)}
	}

	// ServiceAccount objects, which impersonation questions target.
	for _, namespace := range fuzzNamespaces {
		for _, name := range fuzzSAs {
			if chance(50) {
				objects = append(objects, &corev1.ServiceAccount{
					TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "ServiceAccount"},
					ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
				})
			}
		}
	}

	var roleNames = map[string][]string{}
	for _, namespace := range fuzzNamespaces {
		for i := range random.IntN(3) {
			role := &rbacv1.Role{
				TypeMeta:   metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "Role"},
				ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("role-%d", i), Namespace: namespace},
			}
			for range 1 + random.IntN(2) {
				role.Rules = append(role.Rules, resourceRule())
			}
			roleNames[namespace] = append(roleNames[namespace], role.Name)
			objects = append(objects, role)
		}
	}

	var clusterRoleNames []string
	for i := range 2 + random.IntN(4) {
		role := &rbacv1.ClusterRole{
			TypeMeta:   metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRole"},
			ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("clusterrole-%d", i)},
		}
		if chance(40) {
			role.Labels = map[string]string{pick(fuzzLabelKeys): "true"}
		}
		aggregated := chance(30)
		if aggregated {
			selector := metav1.LabelSelector{}
			if !chance(15) {
				selector.MatchLabels = map[string]string{pick(fuzzLabelKeys): "true"}
			}
			role.AggregationRule = &rbacv1.AggregationRule{ClusterRoleSelectors: []metav1.LabelSelector{selector}}
		}
		// The controller replaces an aggregated role's own rules, so give
		// some of them rules to be replaced.
		if !aggregated || chance(50) {
			for range 1 + random.IntN(2) {
				if chance(25) {
					role.Rules = append(role.Rules, nonResourceRule())
				} else {
					role.Rules = append(role.Rules, resourceRule())
				}
			}
		}
		clusterRoleNames = append(clusterRoleNames, role.Name)
		objects = append(objects, role)
	}

	subjects := func(namespaced bool) []rbacv1.Subject {
		var result []rbacv1.Subject
		for range 1 + random.IntN(2) {
			switch random.IntN(3) {
			case 0:
				result = append(result, rbacv1.Subject{Kind: rbacv1.UserKind, APIGroup: rbacv1.GroupName, Name: pick(fuzzUsers)})
			case 1:
				result = append(result, rbacv1.Subject{Kind: rbacv1.GroupKind, APIGroup: rbacv1.GroupName, Name: pick(fuzzGroups)})
			default:
				subject := rbacv1.Subject{Kind: rbacv1.ServiceAccountKind, Name: pick(fuzzSAs), Namespace: pick(fuzzNamespaces)}
				// Only a RoleBinding may omit the ServiceAccount namespace.
				if namespaced && chance(40) {
					subject.Namespace = ""
				}
				result = append(result, subject)
			}
		}
		return result
	}
	clusterRoleRef := func() rbacv1.RoleRef {
		name := pick(clusterRoleNames)
		if chance(5) {
			name = fuzzMissingRoles
		}
		return rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: name}
	}

	for _, namespace := range fuzzNamespaces {
		for i := range random.IntN(4) {
			binding := &rbacv1.RoleBinding{
				TypeMeta:   metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "RoleBinding"},
				ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("rolebinding-%d", i), Namespace: namespace},
				Subjects:   subjects(true),
				RoleRef:    clusterRoleRef(),
			}
			if len(roleNames[namespace]) > 0 && chance(50) {
				binding.RoleRef = rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: pick(roleNames[namespace])}
			}
			objects = append(objects, binding)
		}
	}
	for i := range 1 + random.IntN(3) {
		objects = append(objects, &rbacv1.ClusterRoleBinding{
			TypeMeta:   metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRoleBinding"},
			ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("clusterrolebinding-%d", i)},
			Subjects:   subjects(false),
			RoleRef:    clusterRoleRef(),
		})
	}
	return objects
}

// emptyResourceNames stands in for a rule fuzzWorld wants written as
// "resourceNames: []". The field is omitempty, so an empty list would not
// survive marshaling; marshalFuzzObject swaps the marker for one.
const emptyResourceNames = "pallograph-empty-resource-names"

// marshalFuzzObject marshals object to YAML the way yaml.Marshal does (via
// JSON), writing marked resourceNames as an empty list.
func marshalFuzzObject(object runtime.Object) ([]byte, error) {
	document, err := json.Marshal(object)
	if err != nil {
		return nil, err
	}
	document = bytes.ReplaceAll(document,
		[]byte(`"resourceNames":["`+emptyResourceNames+`"]`), []byte(`"resourceNames":[]`))
	return yaml.JSONToYAML(document)
}

// GenerateWorlds writes count random worlds under dir, named
// fuzz-<seed>-<index>, and validates each by loading it back.
func GenerateWorlds(dir string, seed uint64, count int) ([]string, error) {
	random := rand.New(rand.NewPCG(seed, 1))
	var worlds []string
	for index := range count {
		world := filepath.Join(dir, fmt.Sprintf("fuzz-%d-%03d", seed, index))
		if err := os.MkdirAll(world, 0o755); err != nil {
			return nil, err
		}

		var manifest bytes.Buffer
		fmt.Fprintf(&manifest, "# Random world %d from rbac-oracle gen-worlds -seed %d.\n", index, seed)
		for i, object := range fuzzWorld(random) {
			document, err := marshalFuzzObject(object)
			if err != nil {
				return nil, err
			}
			if i > 0 {
				manifest.WriteString("---\n")
			}
			manifest.Write(document)
		}
		if err := os.WriteFile(filepath.Join(world, worldFile), manifest.Bytes(), 0o644); err != nil {
			return nil, err
		}
		if _, err := LoadWorld(world); err != nil {
			return nil, fmt.Errorf("generated world %s is invalid (generator bug): %w", world, err)
		}
		worlds = append(worlds, world)
	}
	return worlds, nil
}
