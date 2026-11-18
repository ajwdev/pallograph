package main

import (
	"context"
	"fmt"
	"slices"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authentication/user"
	rbacregistryvalidation "k8s.io/kubernetes/pkg/registry/rbac/validation"
)

// Helpers shared by the impersonation and RBAC write questions, which go
// through API server code outside the RBAC authorizer. Pallograph answers
// them with its escalation relations, which are about known principals:
// users and ServiceAccounts the loaded objects name. So the questions are
// asked for those principals only.

// roleRefRules returns the rules a roleRef grants in a binding in
// namespace, both as aggregation leaves them and as written.
func (w *World) roleRefRules(roleRef rbacv1.RoleRef, namespace string) []rbacv1.PolicyRule {
	var rules []rbacv1.PolicyRule
	if roleRef.Kind == "ClusterRole" {
		for _, role := range w.ClusterRoles {
			if role.Name == roleRef.Name {
				rules = append(rules, role.Rules...)
			}
		}
		return append(rules, w.WrittenClusterRoleRules[roleRef.Name]...)
	}
	for _, role := range w.Roles {
		if role.Name == roleRef.Name && role.Namespace == namespace {
			rules = append(rules, role.Rules...)
		}
	}
	return rules
}

// effectiveRoleRefRules returns the rules a roleRef grants in a binding in
// namespace, as aggregation leaves them.
func (w *World) effectiveRoleRefRules(roleRef rbacv1.RoleRef, namespace string) []rbacv1.PolicyRule {
	if roleRef.Kind == "ClusterRole" {
		for _, role := range w.ClusterRoles {
			if role.Name == roleRef.Name {
				return role.Rules
			}
		}
		return nil
	}
	for _, role := range w.Roles {
		if role.Name == roleRef.Name && role.Namespace == namespace {
			return role.Rules
		}
	}
	return nil
}

// binding is a RoleBinding or ClusterRoleBinding (namespace "").
type binding struct {
	namespace, name string
	roleRef         rbacv1.RoleRef
	subjects        []rbacv1.Subject
}

func (w *World) bindings() []binding {
	var bindings []binding
	for _, b := range w.RoleBindings {
		bindings = append(bindings, binding{b.Namespace, b.Name, b.RoleRef, b.Subjects})
	}
	for _, b := range w.ClusterRoleBindings {
		bindings = append(bindings, binding{"", b.Name, b.RoleRef, b.Subjects})
	}
	return bindings
}

// knownServiceAccounts returns the usernames of the ServiceAccounts a
// binding names or that exist as objects: the ones Pallograph knows
// (service_account_principal in rules/rbac_subjects.mg).
func (w *World) knownServiceAccounts() sets.Set[string] {
	known := sets.New[string]()
	for _, b := range w.bindings() {
		for _, subject := range b.subjects {
			if subject.Kind != rbacv1.ServiceAccountKind {
				continue
			}
			namespace := subject.Namespace
			if namespace == "" {
				namespace = b.namespace
			}
			if namespace != "" {
				known.Insert(serviceAccountUsername(namespace, subject.Name))
			}
		}
	}
	for _, account := range w.ServiceAccounts {
		known.Insert(serviceAccountUsername(account.Namespace, account.Name))
	}
	return known
}

// escalationPrincipals returns the principals of every binding whose role
// has a rule relevant says yes to, as written or after aggregation, with
// the decoys subjectPrincipals adds, plus the outsiders as negatives.
// ServiceAccounts Pallograph does not know are left out. A username always
// comes with the same groups.
func escalationPrincipals(world *World, relevant func(rbacv1.PolicyRule) bool) []principal {
	known := world.knownServiceAccounts()
	var principals []principal
	seen := sets.New[string]()
	add := func(p principal) {
		if _, _, isServiceAccount := splitServiceAccount(p.name); isServiceAccount && !known.Has(p.name) {
			return
		}
		if !seen.Has(p.name) {
			seen.Insert(p.name)
			principals = append(principals, p)
		}
	}
	for _, b := range world.bindings() {
		if !slices.ContainsFunc(world.roleRefRules(b.roleRef, b.namespace), relevant) {
			continue
		}
		for _, p := range subjectPrincipals(b.subjects, b.namespace) {
			add(p)
		}
		// subjectPrincipals stands in for a ServiceAccount group with a
		// made-up ServiceAccount; the known ones in it are asked about too.
		for _, subject := range b.subjects {
			if subject.Kind != rbacv1.GroupKind {
				continue
			}
			for _, username := range sets.List(known) {
				if slices.Contains(authenticatedGroups(username), subject.Name) {
					add(principal{username, authenticatedGroups(username)})
				}
			}
		}
	}
	add(principal{unboundUser, authenticatedGroups(unboundUser)})
	add(principal{user.Anonymous, authenticatedGroups(user.Anonymous)})
	return principals
}

// subjectsWithResourceGrants returns the users and groups that bindings
// name whose role grants a resource rule after aggregation: the ones that
// hold a grant of their own in Pallograph (direct_perm rows).
func subjectsWithResourceGrants(world *World) (users, groups []string) {
	userSet, groupSet := sets.New[string](), sets.New[string]()
	for _, b := range world.bindings() {
		rules := world.effectiveRoleRefRules(b.roleRef, b.namespace)
		if !slices.ContainsFunc(rules, func(rule rbacv1.PolicyRule) bool { return len(rule.Resources) > 0 }) {
			continue
		}
		for _, subject := range b.subjects {
			switch subject.Kind {
			case rbacv1.UserKind:
				userSet.Insert(subject.Name)
			case rbacv1.GroupKind:
				groupSet.Insert(subject.Name)
			}
		}
	}
	return sets.List(userSet), sets.List(groupSet)
}

func ruleHasVerb(rule rbacv1.PolicyRule, verb string) bool {
	return slices.Contains(rule.Verbs, verb) || slices.Contains(rule.Verbs, rbacv1.VerbAll)
}

func ruleHasAPIGroup(rule rbacv1.PolicyRule, group string) bool {
	return slices.Contains(rule.APIGroups, group) || slices.Contains(rule.APIGroups, rbacv1.APIGroupAll)
}

// boundRole is a role a binding grants a principal.
type boundRole struct {
	bindingKind, bindingNamespace, bindingName, roleKind, roleName string
}

// boundRoles returns the roles bindings grant p in namespace (cluster-wide
// ones too), as the rule resolver sees them. A role without rules is never
// visited, so it is missing.
func boundRoles(resolver *rbacregistryvalidation.DefaultRuleResolver, p principal, namespace string) ([]boundRole, error) {
	found := sets.New[boundRole]()
	var parseErr error
	resolver.VisitRulesFor(context.Background(), &user.DefaultInfo{Name: p.name, Groups: p.groups}, namespace,
		func(source fmt.Stringer, rule *rbacv1.PolicyRule, _ error) bool {
			if source == nil || rule == nil {
				return true
			}
			var role boundRole
			var subjectKind, subjectName string
			_, err := fmt.Sscanf(source.String(), "%s %q of %s %q to %s %q",
				&role.bindingKind, &role.bindingName, &role.roleKind, &role.roleName, &subjectKind, &subjectName)
			if err != nil {
				parseErr = fmt.Errorf("parse binding description %q: %w", source, err)
				return false
			}
			if name, bindingNamespace, ok := strings.Cut(role.bindingName, "/"); ok {
				role.bindingName, role.bindingNamespace = name, bindingNamespace
			}
			found.Insert(role)
			return true
		})
	roles := found.UnsortedList()
	slices.SortFunc(roles, func(a, b boundRole) int {
		return strings.Compare(fmt.Sprint(a), fmt.Sprint(b))
	})
	return roles, parseErr
}
