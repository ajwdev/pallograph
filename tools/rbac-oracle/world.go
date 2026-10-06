package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/kubernetes/pkg/api/legacyscheme"
	"k8s.io/kubernetes/pkg/apis/rbac"
	_ "k8s.io/kubernetes/pkg/apis/rbac/install"
	rbacvalidation "k8s.io/kubernetes/pkg/apis/rbac/validation"
)

// World is one RBAC configuration: the objects the authorizer sees, after
// API server defaulting, validation and ClusterRole aggregation.
type World struct {
	Roles               []*rbacv1.Role
	RoleBindings        []*rbacv1.RoleBinding
	ClusterRoles        []*rbacv1.ClusterRole
	ClusterRoleBindings []*rbacv1.ClusterRoleBinding

	// AggregatedRoles names the ClusterRoles whose rules were filled in
	// by aggregation. Used only for tagging.
	AggregatedRoles map[string]bool

	// WrittenRules is every rule as written in the world file, before
	// aggregation replaced any. Requests are generated from these so that
	// rules aggregation discards are still probed.
	WrittenRules []rbacv1.PolicyRule
}

const worldFile = "rbac.yaml"

// LoadWorld reads <dir>/rbac.yaml, a multi-document YAML file of RBAC
// objects. Objects of any other kind are ignored, so a world can also carry
// the Namespaces and ServiceAccounts a live cluster needs.
func LoadWorld(dir string) (*World, error) {
	data, err := os.ReadFile(filepath.Join(dir, worldFile))
	if err != nil {
		return nil, err
	}

	world := &World{AggregatedRoles: map[string]bool{}}
	decoder := scheme.Codecs.UniversalDeserializer()
	reader := utilyaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(data)))
	for {
		document, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if len(bytes.TrimSpace(document)) == 0 {
			continue
		}

		object, _, err := decoder.Decode(document, nil, nil)
		if err != nil {
			if runtime.IsNotRegisteredError(err) {
				continue
			}
			return nil, err
		}
		if err := world.add(object); err != nil {
			return nil, err
		}
	}

	for _, role := range world.Roles {
		world.WrittenRules = append(world.WrittenRules, role.Rules...)
	}
	for _, role := range world.ClusterRoles {
		world.WrittenRules = append(world.WrittenRules, role.Rules...)
	}
	world.aggregate()
	return world, nil
}

// add defaults and validates object the way the API server would on
// create, then adds it to the world. Invalid objects are an error: a world
// the API server would reject tells us nothing.
func (w *World) add(object runtime.Object) error {
	legacyscheme.Scheme.Default(object)

	switch typed := object.(type) {
	case *rbacv1.Role:
		internal := &rbac.Role{}
		if err := legacyscheme.Scheme.Convert(typed, internal, nil); err != nil {
			return err
		}
		if errs := rbacvalidation.ValidateRole(internal); len(errs) > 0 {
			return fmt.Errorf("Role %s/%s: %v", typed.Namespace, typed.Name, errs.ToAggregate())
		}
		w.Roles = append(w.Roles, typed)
	case *rbacv1.ClusterRole:
		internal := &rbac.ClusterRole{}
		if err := legacyscheme.Scheme.Convert(typed, internal, nil); err != nil {
			return err
		}
		options := rbacvalidation.ClusterRoleValidationOptions{}
		if errs := rbacvalidation.ValidateClusterRole(internal, options); len(errs) > 0 {
			return fmt.Errorf("ClusterRole %s: %v", typed.Name, errs.ToAggregate())
		}
		w.ClusterRoles = append(w.ClusterRoles, typed)
	case *rbacv1.RoleBinding:
		internal := &rbac.RoleBinding{}
		if err := legacyscheme.Scheme.Convert(typed, internal, nil); err != nil {
			return err
		}
		if errs := rbacvalidation.ValidateRoleBinding(internal); len(errs) > 0 {
			return fmt.Errorf("RoleBinding %s/%s: %v", typed.Namespace, typed.Name, errs.ToAggregate())
		}
		w.RoleBindings = append(w.RoleBindings, typed)
	case *rbacv1.ClusterRoleBinding:
		internal := &rbac.ClusterRoleBinding{}
		if err := legacyscheme.Scheme.Convert(typed, internal, nil); err != nil {
			return err
		}
		if errs := rbacvalidation.ValidateClusterRoleBinding(internal); len(errs) > 0 {
			return fmt.Errorf("ClusterRoleBinding %s: %v", typed.Name, errs.ToAggregate())
		}
		w.ClusterRoleBindings = append(w.ClusterRoleBindings, typed)
	}
	return nil
}

// aggregate runs the clusterrole-aggregation controller's sync to a fixed
// point. It mirrors syncClusterRole in
// pkg/controller/clusterroleaggregation: an aggregated ClusterRole's rules
// are replaced (not extended) by the deduplicated rules of every other
// ClusterRole matching any of its selectors, visited in name order. The
// controller is level-triggered and resyncs whenever any ClusterRole
// changes, so chained aggregation settles the same way.
func (w *World) aggregate() {
	sort.Slice(w.ClusterRoles, func(i, j int) bool {
		return w.ClusterRoles[i].Name < w.ClusterRoles[j].Name
	})

	for changed := true; changed; {
		changed = false
		for _, aggregated := range w.ClusterRoles {
			if aggregated.AggregationRule == nil {
				continue
			}

			newRules := []rbacv1.PolicyRule{}
			for i := range aggregated.AggregationRule.ClusterRoleSelectors {
				selector, err := metav1.LabelSelectorAsSelector(&aggregated.AggregationRule.ClusterRoleSelectors[i])
				if err != nil {
					// Validation already rejected malformed selectors.
					panic(err)
				}
				for _, source := range w.ClusterRoles {
					if source.Name == aggregated.Name || !selector.Matches(labels.Set(source.Labels)) {
						continue
					}
					for _, rule := range source.Rules {
						if !ruleExists(newRules, rule) {
							newRules = append(newRules, rule)
						}
					}
				}
			}

			w.AggregatedRoles[aggregated.Name] = true
			if !equality.Semantic.DeepEqual(newRules, aggregated.Rules) {
				aggregated.Rules = newRules
				changed = true
			}
		}
	}
}

func ruleExists(haystack []rbacv1.PolicyRule, needle rbacv1.PolicyRule) bool {
	for _, current := range haystack {
		if equality.Semantic.DeepEqual(current, needle) {
			return true
		}
	}
	return false
}
