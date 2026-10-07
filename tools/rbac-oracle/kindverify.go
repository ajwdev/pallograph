package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// kind-verify checks the oracle itself against a live kube-apiserver: it
// applies a world to a cluster, then asks the API server each request as a
// SubjectAccessReview and compares the answer with the oracle's.
//
// The oracle decides over every RBAC object in the cluster afterwards, so
// the cluster's own bootstrap policy (which grants system:authenticated
// discovery, for example) is accounted for. That dump also carries the
// aggregation controller's results, which NewWorld discards and recomputes,
// so the comparison covers the oracle's aggregation too; aggregated rules
// are additionally compared directly once the controller settles.
func runKindVerify(args []string) error {
	flags := flag.NewFlagSet("kind-verify", flag.ExitOnError)
	kubeContext := flags.String("context", "kind-pallograph-rbac-compat", "kubeconfig context of the cluster")
	sample := flags.Int("sample", 2000, "check a seeded sample of at most N requests per world (0 checks all)")
	seed := flags.Uint64("seed", 1, "sampling seed")
	concurrency := flags.Int("concurrency", 32, "SubjectAccessReviews in flight")
	flags.Parse(args)
	if flags.NArg() == 0 {
		usage()
	}

	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		clientcmd.NewDefaultClientConfigLoadingRules(),
		&clientcmd.ConfigOverrides{CurrentContext: *kubeContext},
	).ClientConfig()
	if err != nil {
		return err
	}
	config.QPS = 1000
	config.Burst = 2000
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}

	ctx := context.Background()
	failed := 0
	for _, dir := range flags.Args() {
		mismatches, err := verifyWorld(ctx, client, dir, *sample, *seed, *concurrency)
		if err != nil {
			return fmt.Errorf("%s: %w", dir, err)
		}
		if mismatches > 0 {
			failed++
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d worlds disagree with the API server", failed, flags.NArg())
	}
	return nil
}

// verifyWorld applies one world, compares aggregation and a sample of its
// requests against the API server, deletes the world again and returns the
// number of mismatches. Each mismatch is printed to stdout as one JSON line.
func verifyWorld(ctx context.Context, client kubernetes.Interface, dir string, sample int, seed uint64, concurrency int) (int, error) {
	objects, err := readObjects(filepath.Join(dir, worldFile))
	if err != nil {
		return 0, err
	}
	world, err := NewWorld(objects, kubernetesSemantics)
	if err != nil {
		return 0, err
	}
	requests, err := readRequests(filepath.Join(dir, requestsFile))
	if err != nil {
		return 0, err
	}

	cleanup, err := applyWorld(ctx, client, world)
	defer cleanup()
	if err != nil {
		return 0, err
	}

	report := func(kind string, fields map[string]any) {
		fields["world"] = dir
		fields["kind"] = kind
		line, _ := json.Marshal(fields)
		fmt.Println(string(line))
	}

	live, aggregationMismatches, err := settledWorld(ctx, client, world)
	if err != nil {
		return 0, err
	}
	for name, mismatch := range aggregationMismatches {
		report("aggregation", map[string]any{"clusterRole": name, "apiserver": mismatch[0], "oracle": mismatch[1]})
	}

	requests = slices.DeleteFunc(requests, decidedBeforeRBAC)
	if sample > 0 && len(requests) > sample {
		random := rand.New(rand.NewPCG(seed, 2))
		random.Shuffle(len(requests), func(i, j int) { requests[i], requests[j] = requests[j], requests[i] })
		requests = requests[:sample]
	}

	oracle := NewOracle(live)
	decisions := make([]Decision, len(requests))
	for i := range requests {
		if decisions[i], err = oracle.Decide(&requests[i]); err != nil {
			return 0, err
		}
	}

	start := time.Now()
	statuses := make([]authorizationv1.SubjectAccessReviewStatus, len(requests))
	errs := make([]error, len(requests))
	var group sync.WaitGroup
	next := make(chan int)
	for range concurrency {
		group.Add(1)
		go func() {
			defer group.Done()
			for i := range next {
				review, err := client.AuthorizationV1().SubjectAccessReviews().Create(ctx,
					subjectAccessReview(&requests[i]), metav1.CreateOptions{})
				if err != nil {
					errs[i] = err
					continue
				}
				statuses[i] = review.Status
			}
		}()
	}
	for i := range requests {
		next <- i
	}
	close(next)
	group.Wait()
	if err := errors.Join(errs...); err != nil {
		return 0, err
	}

	requestMismatches, apiserverAllowed := 0, 0
	for i := range requests {
		if statuses[i].Allowed {
			apiserverAllowed++
		}
		if statuses[i].Allowed == decisions[i].Allowed {
			continue
		}
		requestMismatches++
		report("request", map[string]any{
			"request":         requests[i],
			"apiserver":       statuses[i].Allowed,
			"apiserverReason": statuses[i].Reason,
			"oracle":          decisions[i].Allowed,
			"oracleReason":    decisions[i].Reason,
		})
	}
	fmt.Fprintf(os.Stderr, "%s: %d requests checked in %v (%d allowed by the API server), %d mismatches, %d aggregation mismatches\n",
		dir, len(requests), time.Since(start).Round(time.Millisecond), apiserverAllowed, requestMismatches, len(aggregationMismatches))
	return requestMismatches + len(aggregationMismatches), nil
}

// decidedBeforeRBAC reports requests another authorizer in kind's chain
// (Node, then RBAC) or the system:masters short circuit answers first.
func decidedBeforeRBAC(request Request) bool {
	return strings.HasPrefix(request.User, "system:node:") ||
		slices.Contains(request.Groups, "system:masters") ||
		slices.Contains(request.Groups, "system:nodes")
}

func subjectAccessReview(request *Request) *authorizationv1.SubjectAccessReview {
	review := &authorizationv1.SubjectAccessReview{
		Spec: authorizationv1.SubjectAccessReviewSpec{User: request.User, Groups: request.Groups},
	}
	if request.Path != "" {
		review.Spec.NonResourceAttributes = &authorizationv1.NonResourceAttributes{Path: request.Path, Verb: request.Verb}
		return review
	}
	review.Spec.ResourceAttributes = &authorizationv1.ResourceAttributes{
		Namespace:   request.Namespace,
		Verb:        request.Verb,
		Group:       request.APIGroup,
		Resource:    request.Resource,
		Subresource: request.Subresource,
		Name:        request.Name,
	}
	return review
}

// applyWorld creates the world's namespaces and RBAC objects. The returned
// cleanup deletes the RBAC objects again (namespaces are left, since
// deleting them is slow and they hold nothing else).
func applyWorld(ctx context.Context, client kubernetes.Interface, world *World) (func(), error) {
	rbac := client.RbacV1()
	var cleanups []func()
	cleanup := func() {
		for _, cleanup := range slices.Backward(cleanups) {
			cleanup()
		}
	}
	ignoreNotFound := func(err error) {
		if err != nil && !apierrors.IsNotFound(err) {
			fmt.Fprintln(os.Stderr, "rbac-oracle: cleanup:", err)
		}
	}
	strip := func(meta *metav1.ObjectMeta) metav1.ObjectMeta {
		return metav1.ObjectMeta{Name: meta.Name, Namespace: meta.Namespace, Labels: meta.Labels}
	}

	namespaces := sets.New[string]()
	for _, role := range world.Roles {
		namespaces.Insert(role.Namespace)
	}
	for _, binding := range world.RoleBindings {
		namespaces.Insert(binding.Namespace)
	}
	for _, namespace := range sets.List(namespaces) {
		_, err := client.CoreV1().Namespaces().Create(ctx,
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}, metav1.CreateOptions{})
		if err != nil && !apierrors.IsAlreadyExists(err) {
			return cleanup, err
		}
	}

	// A world may hold objects the cluster already has: the bootstrap world
	// is the cluster's own default policy. Those are reused when they match
	// and left in place at cleanup; one that differs is an error, since the
	// oracle would then be judged against a world it was not given.
	adopt := func(kind, name string, createErr error, matches func() (bool, error)) (bool, error) {
		if !apierrors.IsAlreadyExists(createErr) {
			return false, createErr
		}
		same, err := matches()
		if err != nil {
			return false, err
		}
		if !same {
			return false, fmt.Errorf("%s %s already exists in the cluster and differs from the world's", kind, name)
		}
		return true, nil
	}

	for _, role := range world.ClusterRoles {
		// Create from the rules as written: aggregation is the
		// controller's job here.
		created := &rbacv1.ClusterRole{ObjectMeta: strip(&role.ObjectMeta),
			Rules: world.WrittenClusterRoleRules[role.Name], AggregationRule: role.AggregationRule}
		_, err := rbac.ClusterRoles().Create(ctx, created, metav1.CreateOptions{})
		if err != nil {
			adopted, err := adopt("ClusterRole", role.Name, err, func() (bool, error) {
				live, err := rbac.ClusterRoles().Get(ctx, role.Name, metav1.GetOptions{})
				if err != nil {
					return false, err
				}
				if created.AggregationRule != nil {
					// The live rules are the controller's output.
					return equality.Semantic.DeepEqual(live.AggregationRule, created.AggregationRule), nil
				}
				return sameRules(live.Rules, created.Rules), nil
			})
			if adopted {
				continue
			}
			return cleanup, err
		}
		cleanups = append(cleanups, func() {
			ignoreNotFound(rbac.ClusterRoles().Delete(context.Background(), role.Name, metav1.DeleteOptions{}))
		})
	}
	for _, role := range world.Roles {
		created := &rbacv1.Role{ObjectMeta: strip(&role.ObjectMeta), Rules: role.Rules}
		_, err := rbac.Roles(role.Namespace).Create(ctx, created, metav1.CreateOptions{})
		if err != nil {
			adopted, err := adopt("Role", role.Namespace+"/"+role.Name, err, func() (bool, error) {
				live, err := rbac.Roles(role.Namespace).Get(ctx, role.Name, metav1.GetOptions{})
				if err != nil {
					return false, err
				}
				return sameRules(live.Rules, created.Rules), nil
			})
			if adopted {
				continue
			}
			return cleanup, err
		}
		cleanups = append(cleanups, func() {
			ignoreNotFound(rbac.Roles(role.Namespace).Delete(context.Background(), role.Name, metav1.DeleteOptions{}))
		})
	}
	for _, binding := range world.ClusterRoleBindings {
		created := &rbacv1.ClusterRoleBinding{ObjectMeta: strip(&binding.ObjectMeta),
			Subjects: binding.Subjects, RoleRef: binding.RoleRef}
		_, err := rbac.ClusterRoleBindings().Create(ctx, created, metav1.CreateOptions{})
		if err != nil {
			adopted, err := adopt("ClusterRoleBinding", binding.Name, err, func() (bool, error) {
				live, err := rbac.ClusterRoleBindings().Get(ctx, binding.Name, metav1.GetOptions{})
				if err != nil {
					return false, err
				}
				return equality.Semantic.DeepEqual(live.Subjects, created.Subjects) &&
					live.RoleRef == created.RoleRef, nil
			})
			if adopted {
				continue
			}
			return cleanup, err
		}
		cleanups = append(cleanups, func() {
			ignoreNotFound(rbac.ClusterRoleBindings().Delete(context.Background(), binding.Name, metav1.DeleteOptions{}))
		})
	}
	for _, binding := range world.RoleBindings {
		created := &rbacv1.RoleBinding{ObjectMeta: strip(&binding.ObjectMeta),
			Subjects: binding.Subjects, RoleRef: binding.RoleRef}
		_, err := rbac.RoleBindings(binding.Namespace).Create(ctx, created, metav1.CreateOptions{})
		if err != nil {
			adopted, err := adopt("RoleBinding", binding.Namespace+"/"+binding.Name, err, func() (bool, error) {
				live, err := rbac.RoleBindings(binding.Namespace).Get(ctx, binding.Name, metav1.GetOptions{})
				if err != nil {
					return false, err
				}
				return equality.Semantic.DeepEqual(live.Subjects, created.Subjects) &&
					live.RoleRef == created.RoleRef, nil
			})
			if adopted {
				continue
			}
			return cleanup, err
		}
		cleanups = append(cleanups, func() {
			ignoreNotFound(rbac.RoleBindings(binding.Namespace).Delete(context.Background(), binding.Name, metav1.DeleteOptions{}))
		})
	}
	return cleanup, nil
}

// settledWorld waits for the aggregation controller to fill in the world's
// aggregated ClusterRoles the way the oracle computes them, then returns
// the oracle's world built from every RBAC object in the cluster. If they
// have not converged after a minute, it returns the world anyway with the
// differing roles, as [apiserver rules, oracle rules] pairs.
func settledWorld(ctx context.Context, client kubernetes.Interface, world *World) (*World, map[string][2][]rbacv1.PolicyRule, error) {
	var live *World
	var mismatches map[string][2][]rbacv1.PolicyRule
	poll := func(ctx context.Context) (bool, error) {
		objects, liveRules, err := dumpRBAC(ctx, client)
		if err != nil {
			return false, err
		}
		if live, err = NewWorld(objects, kubernetesSemantics); err != nil {
			return false, err
		}
		mismatches = map[string][2][]rbacv1.PolicyRule{}
		for _, role := range live.ClusterRoles {
			if !world.AggregatedRoles[role.Name] {
				continue
			}
			if !sameRules(liveRules[role.Name], role.Rules) {
				mismatches[role.Name] = [2][]rbacv1.PolicyRule{liveRules[role.Name], role.Rules}
			}
		}
		return len(mismatches) == 0, nil
	}
	err := wait.PollUntilContextTimeout(ctx, 500*time.Millisecond, time.Minute, true, poll)
	if err != nil && !wait.Interrupted(err) {
		return nil, nil, err
	}
	return live, mismatches, nil
}

// dumpRBAC lists every RBAC object in the cluster, and the live rules of
// each ClusterRole (NewWorld replaces aggregated ones).
func dumpRBAC(ctx context.Context, client kubernetes.Interface) ([]runtime.Object, map[string][]rbacv1.PolicyRule, error) {
	rbac := client.RbacV1()
	var objects []runtime.Object
	liveRules := map[string][]rbacv1.PolicyRule{}

	clusterRoles, err := rbac.ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, nil, err
	}
	for i := range clusterRoles.Items {
		objects = append(objects, &clusterRoles.Items[i])
		liveRules[clusterRoles.Items[i].Name] = clusterRoles.Items[i].Rules
	}
	roles, err := rbac.Roles("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, nil, err
	}
	for i := range roles.Items {
		objects = append(objects, &roles.Items[i])
	}
	clusterRoleBindings, err := rbac.ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, nil, err
	}
	for i := range clusterRoleBindings.Items {
		objects = append(objects, &clusterRoleBindings.Items[i])
	}
	roleBindings, err := rbac.RoleBindings("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, nil, err
	}
	for i := range roleBindings.Items {
		objects = append(objects, &roleBindings.Items[i])
	}
	return objects, liveRules, nil
}

// sameRules compares rule lists as sets: the controller and the oracle
// both deduplicate, but need not agree on order.
func sameRules(a, b []rbacv1.PolicyRule) bool {
	if len(a) != len(b) {
		return false
	}
	for _, rule := range a {
		if !ruleExists(b, rule) {
			return false
		}
	}
	return true
}
