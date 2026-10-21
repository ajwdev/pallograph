# Access Diff: Expansion and Contraction

Demonstrates `\access-diff` flagging RBAC expansion (bad) and contraction (good)
in a single diff: one principal is tightened while another is granted new
access, and the escalation-aware analysis shows the new grant is far larger than
it looks.

## Scenario

- **alice@example.com** has broad "break glass" debug access in `kube-system`:
  `pods/exec`, `secrets` read, and full `configmap` CRUD. Her access is being
  tightened to read-only pods and configmaps.
- **bob@example.com** is being added with `pods/exec` access for on-call
  debugging.

Both changes ride in on the same review. One is a cleanup; the other hands out
cluster-admin without saying so.

## REPL Session

Start the REPL with the base cluster fixtures loaded:

```
cargo run --bin pallograph -- -C pallograph.toml.example --profile dev
```

Each permission is its own single-rule `role_rule` struct so the contraction
step can retract individual permissions with `-`.

### 1. Grant alice broad debug access

```
+binding_subject("kube-system", "rb-alice", /user, "alice@example.com").
+binding_roleref("kube-system", "rb-alice", "Role", "alice-debug").
+role_rule("kube-system", "alice-debug", {/apiGroups: [""], /resources: ["pods/exec"],  /verbs: ["create"]}).
+role_rule("kube-system", "alice-debug", {/apiGroups: [""], /resources: ["pods"],       /verbs: ["get"]}).
+role_rule("kube-system", "alice-debug", {/apiGroups: [""], /resources: ["pods"],       /verbs: ["list"]}).
+role_rule("kube-system", "alice-debug", {/apiGroups: [""], /resources: ["secrets"],    /verbs: ["get"]}).
+role_rule("kube-system", "alice-debug", {/apiGroups: [""], /resources: ["secrets"],    /verbs: ["list"]}).
+role_rule("kube-system", "alice-debug", {/apiGroups: [""], /resources: ["configmaps"], /verbs: ["get"]}).
+role_rule("kube-system", "alice-debug", {/apiGroups: [""], /resources: ["configmaps"], /verbs: ["list"]}).
+role_rule("kube-system", "alice-debug", {/apiGroups: [""], /resources: ["configmaps"], /verbs: ["create"]}).
+role_rule("kube-system", "alice-debug", {/apiGroups: [""], /resources: ["configmaps"], /verbs: ["update"]}).
+role_rule("kube-system", "alice-debug", {/apiGroups: [""], /resources: ["configmaps"], /verbs: ["delete"]}).
```

### 2. Snapshot the current state

```
\snapshot before
```

### 3. Tighten alice (contraction) and add bob (expansion)

Remove alice's dangerous permissions, leaving read-only pods and configmaps:

```
-role_rule("kube-system", "alice-debug", {/apiGroups: [""], /resources: ["pods/exec"],  /verbs: ["create"]}).
-role_rule("kube-system", "alice-debug", {/apiGroups: [""], /resources: ["secrets"],    /verbs: ["get"]}).
-role_rule("kube-system", "alice-debug", {/apiGroups: [""], /resources: ["secrets"],    /verbs: ["list"]}).
-role_rule("kube-system", "alice-debug", {/apiGroups: [""], /resources: ["configmaps"], /verbs: ["create"]}).
-role_rule("kube-system", "alice-debug", {/apiGroups: [""], /resources: ["configmaps"], /verbs: ["update"]}).
-role_rule("kube-system", "alice-debug", {/apiGroups: [""], /resources: ["configmaps"], /verbs: ["delete"]}).
```

Add bob's on-call access:

```
+binding_subject("kube-system", "rb-bob-oncall", /user, "bob@example.com").
+binding_roleref("kube-system", "rb-bob-oncall", "Role", "bob-oncall").
+role_rule("kube-system", "bob-oncall", {/apiGroups: [""], /resources: ["pods/exec"], /verbs: ["create"]}).
+role_rule("kube-system", "bob-oncall", {/apiGroups: [""], /resources: ["pods"],      /verbs: ["get"]}).
+role_rule("kube-system", "bob-oncall", {/apiGroups: [""], /resources: ["pods"],      /verbs: ["list"]}).
+role_rule("kube-system", "bob-oncall", {/apiGroups: [""], /resources: ["pods/log"],  /verbs: ["get"]}).
```

### 4. Run the diff

```
\access-diff before
```

## Expected Output

Counts depend on the fixture (`fixtures/testdata/small/`) and will shift as the
fixture or escalation rules change; the shape is what matters.

```
FAIL  55 new permission(s) granted
=== Access diff: 'before' → 'current' ===

  Per-principal:
    FAIL  bob@example.com    +55 gained / -0 lost
    PASS  alice@example.com  +0 gained / -57 lost

  CAN GAINED (4):
    bob@example.com  ns="kube-system"  apigroup=""  resource="pods/exec"  verb="create"
    bob@example.com  ns="kube-system"  apigroup=""  resource="pods"       verb="get"
    bob@example.com  ns="kube-system"  apigroup=""  resource="pods"       verb="list"
    bob@example.com  ns="kube-system"  apigroup=""  resource="pods/log"   verb="get"
  CAN LOST (6):
    alice@example.com  ns="kube-system"  apigroup=""  resource="pods/exec"   verb="create"
    alice@example.com  ns="kube-system"  apigroup=""  resource="secrets"     verb="get"
    alice@example.com  ns="kube-system"  apigroup=""  resource="secrets"     verb="list"
    alice@example.com  ns="kube-system"  apigroup=""  resource="configmaps"  verb="create"
    alice@example.com  ns="kube-system"  apigroup=""  resource="configmaps"  verb="update"
    alice@example.com  ns="kube-system"  apigroup=""  resource="configmaps"  verb="delete"
  EFFECTIVE GAINED (51) [escalation-aware]:
    bob@example.com  [direct]:
      ns="kube-system"  apigroup=""  resource="pods/exec"  verb="create"
      ns="kube-system"  apigroup=""  resource="pods/log"   verb="get"
    bob@example.com  via admin@example.com:
      ns=""  apigroup="*"  resource="*"  verb="*"
    bob@example.com  via system:serviceaccount:kube-system:default:
      ns=""  apigroup="*"  resource="*"  verb="*"
    ...
  EFFECTIVE LOST (51) [escalation-aware]:
    alice@example.com  [direct]:
      ns="kube-system"  apigroup=""  resource="pods/exec"  verb="create"
      ...
    alice@example.com  via system:serviceaccount:kube-system:default:
      ns=""  apigroup="*"  resource="*"  verb="*"
    ...
```

## What This Shows

- **alice (PASS)**: Contraction. She lost `pods/exec`, `secrets`, and
  `configmap` write access, and with `pods/exec` gone she also lost the
  escalation path to cluster-admin through kube-system's privileged pods. No
  new permissions gained. This is the desired tightening.
- **bob (FAIL)**: Expansion. He gained only 4 direct permissions, but because
  `pods/exec` in `kube-system` lets him exec into pods running as privileged
  service accounts, the escalation-aware analysis shows dozens of effective
  permissions gained, including cluster-admin via
  `system:serviceaccount:kube-system:default`.

The key insight: bob's handful of seemingly-modest permissions (`pods/exec`,
pods get/list, pods/log) translate to cluster-admin through the escalation
chain, and the diff surfaces that even though the review only showed a small
RoleBinding.
