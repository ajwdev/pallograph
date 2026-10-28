package main

import (
	"context"
	"fmt"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/filters"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"
	"k8s.io/kubernetes/pkg/api/legacyscheme"
	"k8s.io/kubernetes/pkg/apis/rbac"
	rbacregistry "k8s.io/kubernetes/pkg/registry/rbac"
	clusterrolepolicy "k8s.io/kubernetes/pkg/registry/rbac/clusterrole/policybased"
	clusterrolebindingpolicy "k8s.io/kubernetes/pkg/registry/rbac/clusterrolebinding/policybased"
	rolepolicy "k8s.io/kubernetes/pkg/registry/rbac/role/policybased"
	rolebindingpolicy "k8s.io/kubernetes/pkg/registry/rbac/rolebinding/policybased"
	rbacregistryvalidation "k8s.io/kubernetes/pkg/registry/rbac/validation"
)

// Write questions ask whether a principal may create or update one RBAC
// object. The API server answers in two steps, and the oracle runs the
// code of both:
//
//  1. The authorization filter asks the authorizer for the plain verb on
//     the object, with attributes built from the request's RequestInfo
//     (filters.GetAuthorizerAttributes). A create has no name in its URL,
//     so resourceNames cannot grant it. An update is a PUT (update) or a
//     PATCH (patch); either verb will do.
//  2. The RBAC registry's policybased storage refuses the write unless the
//     principal is in system:masters, may bind the binding's role or
//     escalate the role (verbs bind and escalate, checked by
//     BindingAuthorized and RoleEscalationAuthorized), or already holds
//     every rule the object grants (ConfirmNoEscalation). The storage runs
//     here as in the API server, over a stand-in for etcd that accepts any
//     write (acceptingStorage).

// The names of the objects create questions write.
const (
	newBindingName = "pallograph-new-binding"
	newRoleName    = "pallograph-new-role"
)

// everythingRules is what a role write asks for: everything, as an
// escalating writer would.
var everythingRules = []rbacv1.PolicyRule{{
	APIGroups: []string{rbacv1.APIGroupAll}, Resources: []string{rbacv1.ResourceAll}, Verbs: []string{rbacv1.VerbAll},
}}

// acceptingStorage stands in for the generic registry store under a
// policybased storage. It accepts every write; an update applies the
// update to old, the stored object, which runs the policybased storage's
// escalation check.
type acceptingStorage struct {
	rest.StandardStorage
	old runtime.Object
}

func (s *acceptingStorage) Create(_ context.Context, obj runtime.Object, _ rest.ValidateObjectFunc, _ *metav1.CreateOptions) (runtime.Object, error) {
	return obj, nil
}

func (s *acceptingStorage) Update(ctx context.Context, _ string, info rest.UpdatedObjectInfo, _ rest.ValidateObjectFunc, _ rest.ValidateObjectUpdateFunc, _ bool, _ *metav1.UpdateOptions) (runtime.Object, bool, error) {
	obj, err := info.UpdatedObject(ctx, s.old)
	return obj, false, err
}

// writeStorage is what the four policybased storages have in common.
type writeStorage interface {
	Create(context.Context, runtime.Object, rest.ValidateObjectFunc, *metav1.CreateOptions) (runtime.Object, error)
	Update(context.Context, string, rest.UpdatedObjectInfo, rest.ValidateObjectFunc, rest.ValidateObjectUpdateFunc, bool, *metav1.UpdateOptions) (runtime.Object, bool, error)
}

// subjectFor is the binding subject naming the request's principal.
func subjectFor(r *Request) rbacv1.Subject {
	if namespace, name, ok := splitServiceAccount(r.User); ok {
		return rbacv1.Subject{Kind: rbacv1.ServiceAccountKind, Namespace: namespace, Name: name}
	}
	return rbacv1.Subject{Kind: rbacv1.UserKind, APIGroup: rbacv1.GroupName, Name: r.User}
}

// writeObjects returns the object a write question writes and, for an
// update, the stored object it replaces, as v1 objects. An update to a
// binding adds the principal as a subject; an update to a role replaces
// its rules.
func (w *World) writeObjects(r *Request) (written, old runtime.Object, err error) {
	meta := metav1.ObjectMeta{Name: r.Name, Namespace: r.Namespace}
	update := r.Verb == "update"
	missing := fmt.Errorf("request %d: no %s %s/%s to update", r.ID, r.Resource, r.Namespace, r.Name)
	switch r.Resource {
	case "clusterrolebindings":
		if !update {
			return &rbacv1.ClusterRoleBinding{ObjectMeta: meta, RoleRef: *r.RoleRef, Subjects: []rbacv1.Subject{subjectFor(r)}}, nil, nil
		}
		for _, stored := range w.ClusterRoleBindings {
			if stored.Name == r.Name {
				updated := stored.DeepCopy()
				updated.Subjects = append(updated.Subjects, subjectFor(r))
				return updated, stored, nil
			}
		}
	case "rolebindings":
		if !update {
			return &rbacv1.RoleBinding{ObjectMeta: meta, RoleRef: *r.RoleRef, Subjects: []rbacv1.Subject{subjectFor(r)}}, nil, nil
		}
		for _, stored := range w.RoleBindings {
			if stored.Name == r.Name && stored.Namespace == r.Namespace {
				updated := stored.DeepCopy()
				updated.Subjects = append(updated.Subjects, subjectFor(r))
				return updated, stored, nil
			}
		}
	case "clusterroles":
		if !update {
			return &rbacv1.ClusterRole{ObjectMeta: meta, Rules: r.Rules}, nil, nil
		}
		for _, stored := range w.ClusterRoles {
			if stored.Name == r.Name {
				updated := stored.DeepCopy()
				updated.Rules = r.Rules
				return updated, stored, nil
			}
		}
	case "roles":
		if !update {
			return &rbacv1.Role{ObjectMeta: meta, Rules: r.Rules}, nil, nil
		}
		for _, stored := range w.Roles {
			if stored.Name == r.Name && stored.Namespace == r.Namespace {
				updated := stored.DeepCopy()
				updated.Rules = r.Rules
				return updated, stored, nil
			}
		}
	default:
		return nil, nil, fmt.Errorf("request %d: cannot write %q", r.ID, r.Resource)
	}
	return nil, nil, missing
}

// toInternal converts a v1 RBAC object to the internal type the registry
// works with.
func toInternal(object runtime.Object) (runtime.Object, error) {
	var internal runtime.Object
	switch object.(type) {
	case *rbacv1.ClusterRoleBinding:
		internal = &rbac.ClusterRoleBinding{}
	case *rbacv1.RoleBinding:
		internal = &rbac.RoleBinding{}
	case *rbacv1.ClusterRole:
		internal = &rbac.ClusterRole{}
	case *rbacv1.Role:
		internal = &rbac.Role{}
	}
	return internal, legacyscheme.Scheme.Convert(object, internal, nil)
}

// writeAllowed decides a write question. Its tags say which check let an
// allowed write through, or why a denied one was refused.
func (d *decider) writeAllowed(r *Request) (bool, string, []string, error) {
	written, old, err := d.world.writeObjects(r)
	if err != nil {
		return false, "", nil, err
	}
	internal, err := toInternal(written)
	if err != nil {
		return false, "", nil, err
	}
	var internalOld runtime.Object
	if old != nil {
		if internalOld, err = toInternal(old); err != nil {
			return false, "", nil, err
		}
	}

	stored := &acceptingStorage{old: internalOld}
	var storage writeStorage
	switch r.Resource {
	case "clusterrolebindings":
		storage = clusterrolebindingpolicy.NewStorage(stored, d.authorizer, d.resolver)
	case "rolebindings":
		storage = rolebindingpolicy.NewStorage(stored, d.authorizer, d.resolver)
	case "clusterroles":
		storage = clusterrolepolicy.NewStorage(stored, d.authorizer, d.resolver)
	case "roles":
		storage = rolepolicy.NewStorage(stored, d.authorizer, d.resolver)
	}

	verbs := []string{r.Verb}
	if r.Verb == "update" {
		verbs = []string{"update", "patch"}
	}
	for _, verb := range verbs {
		info := &request.RequestInfo{
			IsResourceRequest: true, Verb: verb, APIGroup: rbacv1.GroupName, APIVersion: "v1",
			Resource: r.Resource, Namespace: r.Namespace,
		}
		if r.Verb == "update" {
			info.Name = r.Name
		}
		ctx := request.WithUser(context.Background(), &user.DefaultInfo{Name: r.User, Groups: r.Groups})
		ctx = request.WithRequestInfo(ctx, info)
		if r.Namespace != "" {
			ctx = request.WithNamespace(ctx, r.Namespace)
		}

		attributes, err := filters.GetAuthorizerAttributes(ctx)
		if err != nil {
			return false, "", nil, err
		}
		decision, _, err := d.authorizer.Authorize(ctx, attributes)
		if err != nil {
			return false, "", nil, err
		}
		if decision != authorizer.DecisionAllow {
			continue
		}

		if r.Verb == "update" {
			_, _, err = storage.Update(ctx, r.Name, rest.DefaultUpdatedObjectInfo(internal), nil, nil, false, &metav1.UpdateOptions{})
		} else {
			_, err = storage.Create(ctx, internal, nil, &metav1.CreateOptions{})
		}
		switch {
		case apierrors.IsForbidden(err):
			return false, err.Error(), []string{"write-escalation-refused"}, nil
		case err != nil:
			// The API server fails such a write too, e.g. one whose
			// roleRef names a role that does not exist.
			return false, err.Error(), []string{"write-storage-error"}, nil
		}
		return true, "", []string{d.writeAllowedBy(ctx, r)}, nil
	}
	return false, "no " + verbs[0] + " permission", []string{"write-missing-verb"}, nil
}

// writeAllowedBy names the check that let an allowed write through, trying
// them in the order the policybased storages do.
func (d *decider) writeAllowedBy(ctx context.Context, r *Request) string {
	if rbacregistry.EscalationAllowed(ctx) {
		return "write-allowed-by-system-masters"
	}
	switch r.Resource {
	case "clusterrolebindings", "rolebindings":
		roleRef := r.RoleRef
		if r.Verb == "update" {
			for _, b := range d.world.bindings() {
				if b.name == r.Name && b.namespace == r.Namespace {
					roleRef = &b.roleRef
				}
			}
		}
		internal := rbac.RoleRef{APIGroup: roleRef.APIGroup, Kind: roleRef.Kind, Name: roleRef.Name}
		if rbacregistry.BindingAuthorized(ctx, internal, r.Namespace, d.authorizer) {
			return "write-allowed-by-bind"
		}
	case "clusterroles", "roles":
		if rbacregistry.RoleEscalationAuthorized(ctx, d.authorizer) {
			return "write-allowed-by-escalate"
		}
	}
	return "write-allowed-by-covering-rules"
}

// GenerateWriteRequests asks every principal that might write RBAC objects
// (see escalationPrincipals: a rule on the rbac.authorization.k8s.io API
// group) about:
//
//   - creating a ClusterRoleBinding of each ClusterRole,
//   - adding itself to each ClusterRoleBinding,
//   - creating a ClusterRole that grants everything,
//   - rewriting each ClusterRole a ClusterRoleBinding grants it to grant
//     everything,
//
// and, in each namespace that has Roles or RoleBindings, the same for
// RoleBindings (of each Role there and each ClusterRole) and Roles.
// Rewriting a role is only asked about roles bound to the writer: the
// rewrite is how it gains, and Pallograph models nothing else.
func GenerateWriteRequests(world *World) ([]Request, error) {
	writes := func(rule rbacv1.PolicyRule) bool { return ruleHasAPIGroup(rule, rbacv1.GroupName) }
	_, static := rbacregistryvalidation.NewTestRuleResolver(
		world.Roles, world.RoleBindings, world.ClusterRoles, world.ClusterRoleBindings)
	resolver := rbacregistryvalidation.NewDefaultRuleResolver(static, static, static, static)

	namespaces := sets.New[string]()
	for _, role := range world.Roles {
		namespaces.Insert(role.Namespace)
	}
	for _, b := range world.RoleBindings {
		namespaces.Insert(b.Namespace)
	}
	roleRef := func(kind, name string) *rbacv1.RoleRef {
		return &rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: kind, Name: name}
	}

	var requests []Request
	for _, p := range escalationPrincipals(world, writes) {
		add := func(verb, resource, namespace, name string, ref *rbacv1.RoleRef, rules []rbacv1.PolicyRule) {
			requests = append(requests, Request{
				Kind: writeKind, User: p.name, Groups: p.groups, Verb: verb, APIGroup: rbacv1.GroupName,
				Resource: resource, Namespace: namespace, Name: name, RoleRef: ref, Rules: rules,
			})
		}

		for _, role := range world.ClusterRoles {
			add("create", "clusterrolebindings", "", newBindingName, roleRef("ClusterRole", role.Name), nil)
		}
		for _, b := range world.ClusterRoleBindings {
			add("update", "clusterrolebindings", "", b.Name, b.RoleRef.DeepCopy(), nil)
		}
		add("create", "clusterroles", "", newRoleName, nil, everythingRules)

		for _, namespace := range append([]string{""}, sets.List(namespaces)...) {
			bound, err := boundRoles(resolver, p, namespace)
			if err != nil {
				return nil, err
			}
			rewritten := sets.New[string]()
			for _, role := range bound {
				switch {
				case namespace == "" && role.bindingKind == "ClusterRoleBinding":
					rewritten.Insert("clusterroles/" + role.roleName)
				case namespace != "" && role.bindingKind == "RoleBinding" && role.roleKind == "Role":
					rewritten.Insert("roles/" + role.roleName)
				}
			}
			for _, key := range sets.List(rewritten) {
				resource, name, _ := strings.Cut(key, "/")
				add("update", resource, namespace, name, nil, everythingRules)
			}
			if namespace == "" {
				continue
			}

			for _, role := range world.Roles {
				if role.Namespace == namespace {
					add("create", "rolebindings", namespace, newBindingName, roleRef("Role", role.Name), nil)
				}
			}
			for _, role := range world.ClusterRoles {
				add("create", "rolebindings", namespace, newBindingName, roleRef("ClusterRole", role.Name), nil)
			}
			add("create", "roles", namespace, newRoleName, nil, everythingRules)
		}
		for _, b := range world.RoleBindings {
			add("update", "rolebindings", b.Namespace, b.Name, b.RoleRef.DeepCopy(), nil)
		}
	}
	return requests, nil
}
