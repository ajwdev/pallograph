package main

import (
	"fmt"
	"slices"
	"testing"
)

// selectionCase is the objects one owner selects, each written
// "Kind/name" and in sorted order. No objects means it selects nothing.
type selectionCase struct {
	owner   string // "Kind/namespace/name"
	objects []string
}

// checkSelections pins what the owners in tests select in a labels world,
// so a change to world loading or selector handling that bends the oracle
// away from Kubernetes fails here.
func checkSelections(t *testing.T, world string, tests []selectionCase) {
	t.Helper()
	selections, _, err := EvaluateLabelsWorld("../../tests/labels_compat/worlds/" + world)
	if err != nil {
		t.Fatal(err)
	}
	selected := map[string][]string{}
	for _, selection := range selections {
		owner := fmt.Sprintf("%s/%s/%s", selection.Owner.Kind, selection.Owner.Namespace, selection.Owner.Name)
		selected[owner] = append(selected[owner], selection.Object.Kind+"/"+selection.Object.Name)
	}
	for _, test := range tests {
		t.Run(test.owner, func(t *testing.T) {
			got := selected[test.owner]
			slices.Sort(got)
			if !slices.Equal(got, test.objects) {
				t.Errorf("selects %v, want %v", got, test.objects)
			}
		})
	}
}

func TestScopingSelections(t *testing.T) {
	checkSelections(t, "scoping", []selectionCase{
		{"Service/ns-a-0/web", []string{"Pod/web-0", "Pod/web-1"}},
		{"Service/ns-a-0/empty-sel", nil},
		{"Service/ns-a-0/external", nil},
		{"Deployment/ns-a-0/web", []string{"ReplicaSet/web-rs"}},
		{"ReplicaSet/ns-a-0/web-rs", []string{"Pod/web-0", "Pod/web-1"}},
		{"PodDisruptionBudget/ns-a-0/pdb-notin-db", []string{"Pod/fastpod", "Pod/nolabel", "Pod/web-0", "Pod/web-1"}},
		{"PodDisruptionBudget/ns-a-0/pdb-all", []string{"Pod/db-0", "Pod/db-1", "Pod/fastpod", "Pod/nolabel", "Pod/web-0", "Pod/web-1"}},
		{"PodDisruptionBudget/ns-a-0/pdb-twoin", []string{"Pod/db-0", "Pod/db-1"}},
		{"NetworkPolicy/ns-a-0/default-deny", []string{"Pod/db-0", "Pod/db-1", "Pod/fastpod", "Pod/nolabel", "Pod/web-0", "Pod/web-1"}},
		{"NetworkPolicy/ns-a-0/allow-web", []string{"Pod/web-0", "Pod/web-1"}},
		{"PersistentVolumeClaim/ns-a-0/claim", []string{"PersistentVolume/pv-fast"}},
		{"ClusterRoleAggregation/0/agg-admin", []string{"ClusterRole/src-role"}},
	})
}

func TestEmptySelectorSelections(t *testing.T) {
	everyPod := []string{"Pod/nolabel", "Pod/odd-label-key", "Pod/web"}
	checkSelections(t, "empty-selectors", []selectionCase{
		{"PodDisruptionBudget/empty/all", everyPod},
		{"PodDisruptionBudget/empty/all-match-labels", everyPod},
		{"PodDisruptionBudget/empty/no-selector", nil},
		{"PodDisruptionBudget/empty/beta-all", nil},
		{"PodDisruptionBudget/empty/beta-web", []string{"Pod/web"}},
		{"NetworkPolicy/empty/default-deny", everyPod},
		{"NetworkPolicy/empty/allow-web", []string{"Pod/web"}},
		{"Service/empty/empty-selector", nil},
		{"Service/empty/no-selector", nil},
		{"Service/empty/key-named-matchlabels", []string{"Pod/odd-label-key"}},
		{"ClusterRoleAggregation/0/aggregate-everything", []string{"ClusterRole/aggregate-everything", "ClusterRole/plain"}},
		{"ClusterRoleAggregation/1/aggregate-everything", nil},
	})
}

func TestExpressionSelections(t *testing.T) {
	checkSelections(t, "expressions", []selectionCase{
		{"PodDisruptionBudget/exprs/two-in", []string{"Pod/db"}},
		{"PodDisruptionBudget/exprs/in-and-label", []string{"Pod/cache"}},
		{"PodDisruptionBudget/exprs/two-notin", []string{"Pod/cache", "Pod/nolabel"}},
		{"PodDisruptionBudget/exprs/exists", []string{"Pod/cache", "Pod/db", "Pod/web"}},
		{"PodDisruptionBudget/exprs/does-not-exist", []string{"Pod/db", "Pod/nolabel", "Pod/web"}},
		{"PodDisruptionBudget/exprs/exists-and-not", []string{"Pod/web"}},
	})
}

func TestWorkloadSelections(t *testing.T) {
	checkSelections(t, "workloads", []selectionCase{
		{"Deployment/apps/web", []string{"ReplicaSet/web-5d8f"}},
		{"ReplicaSet/apps/web-5d8f", []string{"Pod/web-5d8f-a"}},
		{"StatefulSet/apps/db", []string{"ControllerRevision/db-7c9d", "Pod/db-0"}},
		{"DaemonSet/apps/agent", []string{"ControllerRevision/agent-1f2e", "Pod/agent-x"}},
		{"Job/apps/migrate", []string{"Pod/migrate-q7"}},
		{"ReplicationController/apps/legacy", []string{"Pod/legacy-a"}},
		{"Service/apps/web", []string{"Pod/web-5d8f-a", "Pod/web-old"}},
	})
}

func TestExpressionQueries(t *testing.T) {
	_, results, err := EvaluateLabelsWorld("../../tests/labels_compat/worlds/expressions")
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"Pod/db"},
		{"Pod/cache", "Pod/nolabel"},
		{"Pod/cache", "Pod/db", "Pod/nolabel"},
		{"Pod/db", "Pod/web"},
		{"Pod/cache"},
		{"ConfigMap/web-config", "Pod/web"},
		{"Pod/cache", "Pod/db", "Pod/nolabel",
			"PodDisruptionBudget/does-not-exist", "PodDisruptionBudget/exists", "PodDisruptionBudget/exists-and-not",
			"PodDisruptionBudget/in-and-label", "PodDisruptionBudget/two-in", "PodDisruptionBudget/two-notin"},
		nil, // a namespaced query never matches cluster-scoped objects
	}
	if len(results) != len(want) {
		t.Fatalf("%d query results, want %d", len(results), len(want))
	}
	for i, result := range results {
		var got []string
		for _, object := range result.Objects {
			got = append(got, object.Kind+"/"+object.Name)
		}
		slices.Sort(got)
		if !slices.Equal(got, want[i]) {
			t.Errorf("query %d matches %v, want %v", i, got, want[i])
		}
	}
}
