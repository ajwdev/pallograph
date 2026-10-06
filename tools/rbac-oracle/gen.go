package main

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authentication/user"
)

// Near-miss values that never appear in a world. Each one probes the
// "does not match" side of a comparison the world does use.
const (
	unrelatedNamespace   = "pallograph-unrelated"
	unrelatedGroup       = "unrelated.example.com"
	unrelatedResource    = "unrelatedthings"
	unrelatedSubresource = "pallograph-subresource"
	unrelatedName        = "pallograph-other-name"
	unrelatedVerb        = "pallograph-verb"
	unrelatedPath        = "/pallograph-unrelated"
	unboundUser          = "pallograph-unbound-user"
)

// principal is a username plus the groups its authenticator would attach.
type principal struct {
	name   string
	groups []string
}

// probe is the part of a request a rule decides on: everything except the
// principal and, for resource requests, the namespace.
type probe struct {
	group, resource, subresource, name, verb, path string
}

// GenerateRequests builds requests around the world's bindings. For each
// binding: its subjects, in its namespace (cluster scope for a
// ClusterRoleBinding) and in an unrelated one, crossed with the probes of
// its role's rules (see ruleProbes), both as written and as aggregation
// leaves them, so rules aggregation discards are still probed. Outsiders no
// binding names get every probe, as negatives. Duplicates are dropped and
// the order is deterministic. If limit is positive and smaller than the
// result, a seeded sample of limit requests is kept instead.
func GenerateRequests(world *World, limit int, seed uint64) []Request {
	vocabulary := worldVocabulary(world)
	var requests []Request
	seen := sets.New[string]()
	add := func(principal principal, namespace string, probe probe) {
		if probe.path != "" {
			// Non-resource requests are never namespaced.
			namespace = ""
		}
		request := Request{
			User:        principal.name,
			Groups:      principal.groups,
			Namespace:   namespace,
			APIGroup:    probe.group,
			Resource:    probe.resource,
			Subresource: probe.subresource,
			Name:        probe.name,
			Verb:        probe.verb,
			Path:        probe.path,
		}
		key := fmt.Sprintf("%#v", request)
		if !seen.Has(key) {
			seen.Insert(key)
			requests = append(requests, request)
		}
	}
	probesOf := func(rules ...[]rbacv1.PolicyRule) []probe {
		var probes []probe
		for _, ruleList := range rules {
			for _, rule := range ruleList {
				probes = append(probes, ruleProbes(rule, vocabulary)...)
			}
		}
		return probes
	}
	clusterRoleProbes := func(name string) []probe {
		var effective []rbacv1.PolicyRule
		for _, role := range world.ClusterRoles {
			if role.Name == name {
				effective = role.Rules
			}
		}
		return probesOf(world.WrittenClusterRoleRules[name], effective)
	}
	roleRefProbes := func(roleRef rbacv1.RoleRef, namespace string) []probe {
		if roleRef.Kind == "ClusterRole" {
			return clusterRoleProbes(roleRef.Name)
		}
		for _, role := range world.Roles {
			if role.Name == roleRef.Name && role.Namespace == namespace {
				return probesOf(role.Rules)
			}
		}
		return nil
	}

	for _, binding := range world.RoleBindings {
		probes := roleRefProbes(binding.RoleRef, binding.Namespace)
		for _, principal := range subjectPrincipals(binding.Subjects, binding.Namespace) {
			for _, namespace := range []string{binding.Namespace, unrelatedNamespace} {
				for _, probe := range probes {
					add(principal, namespace, probe)
				}
			}
		}
	}
	for _, binding := range world.ClusterRoleBindings {
		probes := roleRefProbes(binding.RoleRef, "")
		for _, principal := range subjectPrincipals(binding.Subjects, "") {
			for _, namespace := range []string{"", unrelatedNamespace} {
				for _, probe := range probes {
					add(principal, namespace, probe)
				}
			}
		}
	}

	var allProbes []probe
	for _, role := range world.Roles {
		allProbes = append(allProbes, probesOf(role.Rules)...)
	}
	for _, role := range world.ClusterRoles {
		allProbes = append(allProbes, clusterRoleProbes(role.Name)...)
	}
	outsiders := []principal{
		{unboundUser, authenticatedGroups(unboundUser)},
		{user.Anonymous, authenticatedGroups(user.Anonymous)},
	}
	for _, principal := range outsiders {
		for _, namespace := range []string{"", unrelatedNamespace} {
			for _, probe := range allProbes {
				add(principal, namespace, probe)
			}
		}
	}

	if limit > 0 && len(requests) > limit {
		random := rand.New(rand.NewPCG(seed, 0))
		random.Shuffle(len(requests), func(i, j int) {
			requests[i], requests[j] = requests[j], requests[i]
		})
		requests = requests[:limit]
	}
	for i := range requests {
		requests[i].ID = i
	}
	return requests
}

// subjectPrincipals returns principals a binding's subjects match, plus a
// decoy for each service account: the same name in an unrelated namespace.
// A group subject is represented by a principal the authenticator would
// put in it.
func subjectPrincipals(subjects []rbacv1.Subject, bindingNamespace string) []principal {
	serviceAccount := func(namespace, name string) principal {
		username := serviceAccountUsername(namespace, name)
		return principal{username, authenticatedGroups(username)}
	}

	var principals []principal
	for _, subject := range subjects {
		switch subject.Kind {
		case rbacv1.UserKind:
			principals = append(principals, principal{subject.Name, authenticatedGroups(subject.Name)})
		case rbacv1.ServiceAccountKind:
			namespace := subject.Namespace
			if namespace == "" {
				namespace = bindingNamespace
			}
			if namespace != "" {
				principals = append(principals, serviceAccount(namespace, subject.Name),
					serviceAccount(unrelatedNamespace, subject.Name))
			}
		case rbacv1.GroupKind:
			switch namespace, isNamespaceGroup := strings.CutPrefix(subject.Name, "system:serviceaccounts:"); {
			case subject.Name == user.AllAuthenticated:
				principals = append(principals, principal{unboundUser, authenticatedGroups(unboundUser)})
			case subject.Name == user.AllUnauthenticated:
				principals = append(principals, principal{user.Anonymous, authenticatedGroups(user.Anonymous)})
			case subject.Name == "system:serviceaccounts":
				principals = append(principals, serviceAccount(unrelatedNamespace, "pallograph-sa"))
			case isNamespaceGroup:
				principals = append(principals, serviceAccount(namespace, "pallograph-sa"),
					serviceAccount(unrelatedNamespace, "pallograph-sa"))
			default:
				member := "member-of-" + subject.Name
				principals = append(principals, principal{member, authenticatedGroups(member, subject.Name)})
			}
		}
	}
	return principals
}

// vocabulary is every concrete value the world's rules mention, used to
// stand in for a wildcard.
type vocabulary struct {
	groups, resources, subresources, verbs sets.Set[string]
}

func worldVocabulary(world *World) vocabulary {
	vocabulary := vocabulary{
		groups:       sets.New[string](),
		resources:    sets.New[string](),
		subresources: sets.New[string](),
		verbs:        sets.New("get", "list", "watch", "create", "update", "patch", "delete", "deletecollection"),
	}
	for _, rule := range world.WrittenRules {
		for _, group := range rule.APIGroups {
			if group != rbacv1.APIGroupAll {
				vocabulary.groups.Insert(group)
			}
		}
		for _, resource := range rule.Resources {
			base, subresource, _ := strings.Cut(resource, "/")
			if base != rbacv1.ResourceAll {
				vocabulary.resources.Insert(base)
			}
			if subresource != "" && subresource != rbacv1.ResourceAll {
				vocabulary.subresources.Insert(subresource)
			}
		}
		for _, verb := range rule.Verbs {
			if verb != rbacv1.VerbAll {
				vocabulary.verbs.Insert(verb)
			}
		}
	}
	return vocabulary
}

// representatives stands in for a wildcard: the first world value, if any,
// and a value the world never mentions.
func representatives(values sets.Set[string], unrelated string) []string {
	if values.Len() == 0 {
		return []string{unrelated}
	}
	return []string{sets.List(values)[0], unrelated}
}

// firstVerbOutside returns a verb the rule does not grant.
func firstVerbOutside(verbs []string, vocabulary vocabulary) string {
	for _, verb := range sets.List(vocabulary.verbs) {
		if !slices.Contains(verbs, verb) {
			return verb
		}
	}
	return unrelatedVerb
}

// ruleProbes returns the requests that probe one rule. For a resource rule:
// every combination of its apiGroups, resources, verbs and names (exact
// matches, with each wildcard replaced by representatives), and for each
// resource entry a near miss per field: another apiGroup, resource,
// subresource, verb and, for resourceNames rules, another name and no name.
// For a non-resource rule: each URL, the boundaries of its prefix, and an
// unrelated path, with the rule's verbs and one it does not grant.
func ruleProbes(rule rbacv1.PolicyRule, vocabulary vocabulary) []probe {
	if len(rule.NonResourceURLs) > 0 {
		return nonResourceProbes(rule, vocabulary)
	}

	groups := rule.APIGroups
	wildcardGroup := slices.Contains(groups, rbacv1.APIGroupAll)
	if wildcardGroup {
		groups = representatives(vocabulary.groups, unrelatedGroup)
	}
	verbs := rule.Verbs
	wildcardVerb := slices.Contains(verbs, rbacv1.VerbAll)
	if wildcardVerb {
		verbs = representatives(vocabulary.verbs, unrelatedVerb)
	}
	// Without resourceNames a rule matches named and unnamed requests alike.
	names := rule.ResourceNames
	if len(names) == 0 {
		names = []string{"", unrelatedName}
	}

	var probes []probe
	for _, resource := range rule.Resources {
		base, subresource, hasSubresource := strings.Cut(resource, "/")
		bases := []string{base}
		if base == rbacv1.ResourceAll {
			bases = representatives(vocabulary.resources, unrelatedResource)
		}
		subresources := []string{subresource}
		switch {
		case base == rbacv1.ResourceAll && !hasSubresource:
			// "*" also matches every subresource.
			subresources = []string{"", sets.List(vocabulary.subresources.Clone().Insert(unrelatedSubresource))[0]}
		case subresource == rbacv1.ResourceAll:
			// "resource/*" is not a wildcard: it only matches the literal
			// subresource "*". Probe the literal and a real subresource.
			subresources = []string{rbacv1.ResourceAll, representatives(vocabulary.subresources, unrelatedSubresource)[0]}
		}

		for _, group := range groups {
			for _, base := range bases {
				for _, subresource := range subresources {
					for _, verb := range verbs {
						for _, name := range names {
							probes = append(probes, probe{group: group, resource: base,
								subresource: subresource, name: name, verb: verb})
						}
					}
				}
			}
		}

		exact := probe{group: groups[0], resource: bases[0], subresource: subresources[0],
			name: names[0], verb: verbs[0]}
		nearMiss := func(change func(*probe)) {
			changed := exact
			change(&changed)
			probes = append(probes, changed)
		}
		if !wildcardGroup {
			nearMiss(func(p *probe) { p.group = unrelatedGroup })
		}
		if base != rbacv1.ResourceAll {
			nearMiss(func(p *probe) { p.resource = unrelatedResource })
		}
		if exact.subresource == "" {
			nearMiss(func(p *probe) { p.subresource = unrelatedSubresource })
		} else {
			nearMiss(func(p *probe) { p.subresource = "" })
			nearMiss(func(p *probe) { p.subresource = unrelatedSubresource })
		}
		if !wildcardVerb {
			nearMiss(func(p *probe) { p.verb = firstVerbOutside(rule.Verbs, vocabulary) })
		}
		if len(rule.ResourceNames) > 0 {
			nearMiss(func(p *probe) { p.name = unrelatedName })
			nearMiss(func(p *probe) { p.name = "" })
		}
	}
	return probes
}

func nonResourceProbes(rule rbacv1.PolicyRule, vocabulary vocabulary) []probe {
	paths := []string{unrelatedPath}
	for _, url := range rule.NonResourceURLs {
		prefix, isPrefix := strings.CutSuffix(url, "*")
		switch {
		case !isPrefix:
			// A literal URL must not match the paths below it.
			paths = append(paths, url, strings.TrimSuffix(url, "/")+"/pallograph-child")
		case prefix == "":
			paths = append(paths, "/pallograph/any")
		default:
			// The prefix itself, a path below it, and a sibling that shares
			// its leading characters.
			paths = append(paths, prefix, prefix+"pallograph/child",
				fmt.Sprintf("%s-pallograph", strings.TrimSuffix(prefix, "/")))
		}
	}

	verbs := rule.Verbs
	if slices.Contains(verbs, rbacv1.VerbAll) {
		verbs = representatives(vocabulary.verbs, unrelatedVerb)
	} else {
		verbs = append(slices.Clone(verbs), firstVerbOutside(verbs, vocabulary))
	}

	var probes []probe
	for _, path := range paths {
		for _, verb := range verbs {
			probes = append(probes, probe{path: path, verb: verb})
		}
	}
	return probes
}
