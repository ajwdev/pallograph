package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/kubernetes/pkg/api/legacyscheme"
	_ "k8s.io/kubernetes/pkg/apis/apps/install"
	_ "k8s.io/kubernetes/pkg/apis/batch/install"
	_ "k8s.io/kubernetes/pkg/apis/core/install"
	_ "k8s.io/kubernetes/pkg/apis/networking/install"
	"k8s.io/kubernetes/pkg/apis/policy"
	_ "k8s.io/kubernetes/pkg/apis/policy/install"
)

// A labels world is a directory holding objects.yaml, and optionally
// queries.ndjson: kubectl-style selectors to evaluate against it, the way
// Pallograph's k8s::match does.
const (
	labelsWorldFile   = "objects.yaml"
	labelsQueriesFile = "queries.ndjson"
	selectionsFile    = "selections.ndjson"
	queryResultsFile  = "query-results.ndjson"
)

// ObjectRef names an object the way Pallograph keys it.
type ObjectRef struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace"`
	Name       string `json:"name"`
}

// Selection is one object a selector selects. Selector says which of the
// owner's selectors it is: the path of the field it was read from, in the
// form apimachinery's field.Path prints and API server validation errors use
// (spec.selector, aggregationRule.clusterRoleSelectors[1]).
type Selection struct {
	Owner    ObjectRef `json:"owner"`
	Selector string    `json:"selector"`
	Object   ObjectRef `json:"object"`
}

// LabelQuery is a kubectl selector evaluated in one namespace. An empty
// Kind matches objects of every kind (k8s::match-all).
type LabelQuery struct {
	Namespace string `json:"namespace"`
	Kind      string `json:"kind,omitempty"`
	Selector  string `json:"selector"`
}

// QueryResult is the objects query number Query selects, in name order.
type QueryResult struct {
	Query   int         `json:"query"`
	Objects []ObjectRef `json:"objects"`
}

// selectorTarget is a kind of object a selector is evaluated against, and
// where: the owner's namespace, or cluster-scoped objects.
type selectorTarget struct {
	APIVersion, Kind string
	Cluster          bool
}

var (
	pods                = selectorTarget{"v1", "Pod", false}
	replicaSets         = selectorTarget{"apps/v1", "ReplicaSet", false}
	controllerRevisions = selectorTarget{"apps/v1", "ControllerRevision", false}
	persistentVolumes   = selectorTarget{"v1", "PersistentVolume", true}
	clusterRoles        = selectorTarget{"rbac.authorization.k8s.io/v1", "ClusterRole", true}
)

// ownedSelector is one selector, the object that owns it, the field it was
// read from and what it is evaluated against.
type ownedSelector struct {
	owner    ObjectRef
	field    string
	selector labels.Selector
	targets  []selectorTarget
}

func runLabels(command string, args []string) error {
	if command != "eval" || len(args) == 0 {
		usage()
	}
	for _, dir := range args {
		if err := evalLabelsWorld(dir); err != nil {
			return err
		}
	}
	return nil
}

func evalLabelsWorld(dir string) error {
	selections, results, err := EvaluateLabelsWorld(dir)
	if err != nil {
		return err
	}
	if err := writeNDJSON(filepath.Join(dir, selectionsFile), selections); err != nil {
		return err
	}
	if err := writeNDJSON(filepath.Join(dir, queryResultsFile), results); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%s: %d selections, %d queries\n", dir, len(selections), len(results))
	return nil
}

// EvaluateLabelsWorld gives what every selector in the world in dir
// selects, and what each of its queries matches, in sorted order.
func EvaluateLabelsWorld(dir string) ([]Selection, []QueryResult, error) {
	objects, err := readStoredObjects(filepath.Join(dir, labelsWorldFile))
	if err != nil {
		return nil, nil, err
	}
	owned, err := ownedSelectors(objects)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", dir, err)
	}

	selections := []Selection{}
	for _, selector := range owned {
		for _, object := range objects {
			if selectsObject(selector, object) {
				selections = append(selections, Selection{selector.owner, selector.field, objectRef(object)})
			}
		}
	}
	slices.SortFunc(selections, func(a, b Selection) int {
		if c := compareRefs(a.Owner, b.Owner); c != 0 {
			return c
		}
		if a.Selector != b.Selector {
			return strings.Compare(a.Selector, b.Selector)
		}
		return compareRefs(a.Object, b.Object)
	})

	queries, err := readLabelQueries(filepath.Join(dir, labelsQueriesFile))
	if err != nil {
		return nil, nil, err
	}
	results := make([]QueryResult, len(queries))
	for i, query := range queries {
		// labels.Parse is what kubectl -l sends the API server through.
		selector, err := labels.Parse(query.Selector)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: query %d: %w", dir, i, err)
		}
		results[i] = QueryResult{Query: i, Objects: []ObjectRef{}}
		for _, object := range objects {
			ref := objectRef(object)
			if ref.Namespace != query.Namespace || (query.Kind != "" && ref.Kind != query.Kind) {
				continue
			}
			if selector.Matches(labels.Set(accessor(object).GetLabels())) {
				results[i].Objects = append(results[i].Objects, ref)
			}
		}
		slices.SortFunc(results[i].Objects, compareRefs)
	}
	return selections, results, nil
}

// readStoredObjects reads a world's objects as the API server would store
// them: defaulted, then written out and read back as JSON, so that an empty
// map with omitempty (a Service's selector: {}) comes back nil, as it does
// from a live cluster.
func readStoredObjects(path string) ([]runtime.Object, error) {
	objects, err := readObjects(path)
	if err != nil {
		return nil, err
	}
	for i, object := range objects {
		legacyscheme.Scheme.Default(object)
		data, err := json.Marshal(object)
		if err != nil {
			return nil, err
		}
		stored, err := scheme.Scheme.New(object.GetObjectKind().GroupVersionKind())
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(data, stored); err != nil {
			return nil, err
		}
		objects[i] = stored
	}
	return objects, nil
}

// ownedSelectors gives every selector in objects, with the kinds and scope
// the controller that reads it lists objects in.
func ownedSelectors(objects []runtime.Object) ([]ownedSelector, error) {
	var owned []ownedSelector
	add := func(object runtime.Object, field string, selector labels.Selector, err error, targets ...selectorTarget) error {
		if err != nil {
			return fmt.Errorf("%v: %w", objectRef(object), err)
		}
		owned = append(owned, ownedSelector{objectRef(object), field, selector, targets})
		return nil
	}

	for _, object := range objects {
		var err error
		switch object := object.(type) {
		case *corev1.Service:
			// The EndpointSlice controller skips a Service without a
			// selector (pkg/controller/endpointslice) and lists Pods in
			// its namespace.
			if object.Spec.Selector != nil {
				err = add(object, field.NewPath("spec", "selector").String(), labels.SelectorFromSet(object.Spec.Selector), nil, pods)
			}
		case *corev1.ReplicationController:
			// pkg/controller/replication goes through the ReplicaSet
			// controller, which lists Pods in the namespace.
			err = add(object, field.NewPath("spec", "selector").String(), labels.SelectorFromSet(object.Spec.Selector), nil, pods)
		case *appsv1.ReplicaSet:
			selector, selectorErr := metav1.LabelSelectorAsSelector(object.Spec.Selector)
			err = add(object, field.NewPath("spec", "selector").String(), selector, selectorErr, pods)
		case *appsv1.Deployment:
			// The Deployment controller adopts ReplicaSets by selector
			// (getReplicaSetsForDeployment); its Pods hang off those.
			selector, selectorErr := metav1.LabelSelectorAsSelector(object.Spec.Selector)
			err = add(object, field.NewPath("spec", "selector").String(), selector, selectorErr, replicaSets)
		case *appsv1.StatefulSet:
			// Pods and the ControllerRevisions holding its history
			// (pkg/controller/history).
			selector, selectorErr := metav1.LabelSelectorAsSelector(object.Spec.Selector)
			err = add(object, field.NewPath("spec", "selector").String(), selector, selectorErr, pods, controllerRevisions)
		case *appsv1.DaemonSet:
			selector, selectorErr := metav1.LabelSelectorAsSelector(object.Spec.Selector)
			err = add(object, field.NewPath("spec", "selector").String(), selector, selectorErr, pods, controllerRevisions)
		case *batchv1.Job:
			selector, selectorErr := metav1.LabelSelectorAsSelector(object.Spec.Selector)
			err = add(object, field.NewPath("spec", "selector").String(), selector, selectorErr, pods)
		case *policyv1.PodDisruptionBudget:
			// The disruption controller (pkg/controller/disruption) lists
			// Pods in the namespace. A nil selector selects nothing and {}
			// every Pod.
			selector, selectorErr := metav1.LabelSelectorAsSelector(object.Spec.Selector)
			err = add(object, field.NewPath("spec", "selector").String(), selector, selectorErr, pods)
		case *policyv1beta1.PodDisruptionBudget:
			// policy/v1beta1 selected no Pods with {}. Converting to the
			// internal type applies the selector the API server rewrites
			// it to.
			var internal policy.PodDisruptionBudget
			if err = legacyscheme.Scheme.Convert(object, &internal, nil); err != nil {
				break
			}
			selector, selectorErr := metav1.LabelSelectorAsSelector(internal.Spec.Selector)
			err = add(object, field.NewPath("spec", "selector").String(), selector, selectorErr, pods)
		case *networkingv1.NetworkPolicy:
			// spec.podSelector picks the Pods the policy applies to; {}
			// is every Pod in the namespace.
			selector, selectorErr := metav1.LabelSelectorAsSelector(&object.Spec.PodSelector)
			err = add(object, field.NewPath("spec", "podSelector").String(), selector, selectorErr, pods)
		case *corev1.PersistentVolumeClaim:
			// The PV binder ignores labels when a claim has no selector.
			// Pallograph keeps no edge for that, so neither does the
			// oracle.
			if object.Spec.Selector != nil {
				selector, selectorErr := metav1.LabelSelectorAsSelector(object.Spec.Selector)
				err = add(object, field.NewPath("spec", "selector").String(), selector, selectorErr, persistentVolumes)
			}
		case *rbacv1.ClusterRole:
			if object.AggregationRule == nil {
				break
			}
			// Each clusterRoleSelectors entry is a selector of its own.
			for i := range object.AggregationRule.ClusterRoleSelectors {
				selector, selectorErr := metav1.LabelSelectorAsSelector(&object.AggregationRule.ClusterRoleSelectors[i])
				if selectorErr != nil {
					err = fmt.Errorf("%v: %w", objectRef(object), selectorErr)
					break
				}
				owned = append(owned, ownedSelector{
					owner:    objectRef(object),
					field:    field.NewPath("aggregationRule", "clusterRoleSelectors").Index(i).String(),
					selector: selector,
					targets:  []selectorTarget{clusterRoles},
				})
			}
		}
		if err != nil {
			return nil, err
		}
	}
	return owned, nil
}

func selectsObject(selector ownedSelector, object runtime.Object) bool {
	ref := objectRef(object)
	for _, target := range selector.targets {
		namespace := selector.owner.Namespace
		if target.Cluster {
			namespace = ""
		}
		if ref.APIVersion == target.APIVersion && ref.Kind == target.Kind && ref.Namespace == namespace {
			return selector.selector.Matches(labels.Set(accessor(object).GetLabels()))
		}
	}
	return false
}

func accessor(object runtime.Object) metav1.Object {
	accessor, err := meta.Accessor(object)
	if err != nil {
		panic(err)
	}
	return accessor
}

func objectRef(object runtime.Object) ObjectRef {
	apiVersion, kind := object.GetObjectKind().GroupVersionKind().ToAPIVersionAndKind()
	metadata := accessor(object)
	return ObjectRef{apiVersion, kind, metadata.GetNamespace(), metadata.GetName()}
}

func compareRefs(a, b ObjectRef) int {
	for _, pair := range [][2]string{
		{a.APIVersion, b.APIVersion}, {a.Kind, b.Kind}, {a.Namespace, b.Namespace}, {a.Name, b.Name},
	} {
		if pair[0] != pair[1] {
			if pair[0] < pair[1] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// readLabelQueries reads path, one LabelQuery per line. A world without
// queries has no file.
func readLabelQueries(path string) ([]LabelQuery, error) {
	file, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var queries []LabelQuery
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if len(scanner.Bytes()) == 0 {
			continue
		}
		var query LabelQuery
		if err := json.Unmarshal(scanner.Bytes(), &query); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		queries = append(queries, query)
	}
	return queries, scanner.Err()
}
