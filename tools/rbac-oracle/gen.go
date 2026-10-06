package main

import (
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
	unrelatedNamespace = "pallograph-unrelated"
	unrelatedGroup     = "unrelated.example.com"
	unrelatedResource  = "unrelatedthings"
	unrelatedName      = "pallograph-other-name"
	unrelatedPath      = "/pallograph-unrelated"
	unboundUser        = "pallograph-unbound-user"
)

// principal is a username plus the groups its authenticator would attach.
type principal struct {
	name   string
	groups []string
}

// resourceTarget is the (apiGroup, resource, subresource) part of a
// resource request.
type resourceTarget struct {
	group, resource, subresource string
}

// GenerateRequests enumerates requests from the world's own vocabulary:
// every principal its bindings name, every namespace, every rule target,
// verb, resourceName and nonResourceURL, plus near misses around each.
// The full cross product is deterministic; if it is larger than limit, a
// seeded sample of limit requests is kept.
func GenerateRequests(world *World, limit int, seed uint64) []Request {
	principals := worldPrincipals(world)
	namespaces := worldNamespaces(world)
	targets := worldTargets(world)
	verbs := worldVerbs(world)
	names := worldNames(world)
	paths := worldPaths(world)

	var requests []Request
	for _, principal := range principals {
		for _, namespace := range namespaces {
			for _, target := range targets {
				for _, verb := range verbs {
					for _, name := range names {
						requests = append(requests, Request{
							User:        principal.name,
							Groups:      principal.groups,
							Namespace:   namespace,
							APIGroup:    target.group,
							Resource:    target.resource,
							Subresource: target.subresource,
							Name:        name,
							Verb:        verb,
						})
					}
				}
			}
		}
		// Non-resource requests are never namespaced.
		for _, path := range paths {
			for _, verb := range verbs {
				requests = append(requests, Request{
					User:   principal.name,
					Groups: principal.groups,
					Verb:   verb,
					Path:   path,
				})
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

func worldPrincipals(world *World) []principal {
	users := sets.New(unboundUser)
	groups := sets.New[string]()
	serviceAccounts := sets.New[string]()
	addSubjects := func(subjects []rbacv1.Subject, bindingNamespace string) {
		for _, subject := range subjects {
			switch subject.Kind {
			case rbacv1.UserKind:
				users.Insert(subject.Name)
			case rbacv1.GroupKind:
				groups.Insert(subject.Name)
			case rbacv1.ServiceAccountKind:
				namespace := subject.Namespace
				if namespace == "" {
					namespace = bindingNamespace
				}
				if namespace != "" {
					serviceAccounts.Insert(serviceAccountUsername(namespace, subject.Name))
					// Same name in another namespace must not match.
					serviceAccounts.Insert(serviceAccountUsername(unrelatedNamespace, subject.Name))
				}
			}
		}
	}
	for _, binding := range world.RoleBindings {
		addSubjects(binding.Subjects, binding.Namespace)
	}
	for _, binding := range world.ClusterRoleBindings {
		addSubjects(binding.Subjects, "")
	}

	var principals []principal
	for _, name := range sets.List(users) {
		principals = append(principals, principal{name, authenticatedGroups(name)})
	}
	for _, name := range sets.List(serviceAccounts) {
		principals = append(principals, principal{name, authenticatedGroups(name)})
	}
	// One member per bound group. System groups are only reachable through
	// the authenticator, so they get no synthetic member.
	for _, group := range sets.List(groups) {
		if strings.HasPrefix(group, "system:") {
			continue
		}
		principals = append(principals, principal{"member-of-" + group, authenticatedGroups("member-of-"+group, group)})
	}
	principals = append(principals, principal{user.Anonymous, authenticatedGroups(user.Anonymous)})
	return principals
}

func worldNamespaces(world *World) []string {
	namespaces := sets.New("", unrelatedNamespace)
	for _, role := range world.Roles {
		namespaces.Insert(role.Namespace)
	}
	for _, binding := range world.RoleBindings {
		namespaces.Insert(binding.Namespace)
	}
	return sets.List(namespaces)
}

// worldTargets pairs each rule's apiGroups with its resources, rather than
// taking the product across rules, so the request count tracks the world.
// "*" in a rule is replaced by concrete values from the rest of the world,
// since a request never carries a wildcard. Each target also gets near
// misses: an unrelated apiGroup, and every subresource seen elsewhere.
func worldTargets(world *World) []resourceTarget {
	rules := world.WrittenRules

	groups := sets.New("", unrelatedGroup)
	resources := sets.New(unrelatedResource)
	subresources := sets.New[string]()
	for _, rule := range rules {
		for _, group := range rule.APIGroups {
			if group != rbacv1.APIGroupAll {
				groups.Insert(group)
			}
		}
		for _, resource := range rule.Resources {
			base, subresource, _ := strings.Cut(resource, "/")
			if base != rbacv1.ResourceAll {
				resources.Insert(base)
			}
			if subresource != "" && subresource != rbacv1.ResourceAll {
				subresources.Insert(subresource)
			}
		}
	}

	targets := sets.New[resourceTarget]()
	addTarget := func(group, resource string) {
		targets.Insert(resourceTarget{group: group, resource: resource})
		targets.Insert(resourceTarget{group: unrelatedGroup, resource: resource})
		for _, subresource := range sets.List(subresources) {
			targets.Insert(resourceTarget{group: group, resource: resource, subresource: subresource})
		}
	}
	expand := func(values []string, wildcard string, vocabulary sets.Set[string]) []string {
		if slices.Contains(values, wildcard) {
			return sets.List(vocabulary)
		}
		return values
	}
	for _, rule := range rules {
		if len(rule.Resources) == 0 {
			continue
		}
		for _, group := range expand(rule.APIGroups, rbacv1.APIGroupAll, groups) {
			for _, resource := range rule.Resources {
				base, subresource, _ := strings.Cut(resource, "/")
				switch {
				case base == rbacv1.ResourceAll:
					for _, concrete := range sets.List(resources) {
						addTarget(group, concrete)
					}
				default:
					addTarget(group, base)
				}
				if subresource != "" && subresource != rbacv1.ResourceAll {
					targets.Insert(resourceTarget{group: group, resource: base, subresource: subresource})
				}
			}
		}
	}

	result := targets.UnsortedList()
	slices.SortFunc(result, func(a, b resourceTarget) int {
		return strings.Compare(a.group+"\x00"+a.resource+"\x00"+a.subresource,
			b.group+"\x00"+b.resource+"\x00"+b.subresource)
	})
	return result
}

func worldVerbs(world *World) []string {
	verbs := sets.New("get", "list", "watch", "create", "update", "patch", "delete", "deletecollection")
	for _, rule := range world.WrittenRules {
		for _, verb := range rule.Verbs {
			if verb != rbacv1.VerbAll {
				verbs.Insert(verb)
			}
		}
	}
	return sets.List(verbs)
}

func worldNames(world *World) []string {
	names := sets.New("", unrelatedName)
	for _, rule := range world.WrittenRules {
		names.Insert(rule.ResourceNames...)
	}
	return sets.List(names)
}

// worldPaths returns every literal nonResourceURL, and for each prefix
// rule ("/apis/*") the bare prefix and one path below it.
func worldPaths(world *World) []string {
	paths := sets.New(unrelatedPath)
	for _, rule := range world.WrittenRules {
		for _, url := range rule.NonResourceURLs {
			prefix, isPrefix := strings.CutSuffix(url, "*")
			if !isPrefix {
				paths.Insert(url)
				continue
			}
			if prefix == "" {
				continue
			}
			paths.Insert(prefix, prefix+"pallograph/child")
		}
	}
	return sets.List(paths)
}
