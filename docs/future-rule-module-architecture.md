# Future: Lazy Rule Module Architecture

## Problem

Currently all rule files (RBAC, label selectors, policies, etc.) are loaded into
a single `policy.Engine` and evaluated together on every `Evaluate()` call. As
more rule files are added, startup time and memory grow even when the user only
wants to query one domain.

## Proposed Architecture

Split rules into independent **rule modules**, each with its own `Engine`
instance. Modules are lazily initialized — only instantiated and evaluated when
a query touches their predicates. Evaluated engines are cached and invalidated
when the underlying EDB changes (e.g. cluster re-sync).

```
Rule Modules (each independently evaluatable):
  ┌─────────────┐  ┌──────────────┐  ┌──────────────┐
  │  rbac.mg    │  │  labels.mg   │  │  policies.mg │
  │  can_i/3    │  │ selector_    │  │  violation/N │
  │  all_user_  │  │ matches/8    │  │  ...         │
  │  perm/4     │  │ ...          │  │              │
  └─────────────┘  └──────────────┘  └──────────────┘
        ↑                 ↑                 ↑
        └─────────────────┴─────────────────┘
                          │
                    Query Router
                    (maps predicate → module)
                          │
                    Shared EDB (k8s/5, object_label/6, ...)
```

Each module declares which predicates it owns. The REPL (and any query API)
parses the predicate name from the query string, looks up the owning module,
lazily evaluates it, and routes the query. EDB predicates (e.g. `object_label`)
map to `nil` — they can be queried directly without any engine evaluation.

## Benefits

- Startup is instant — nothing is evaluated until queried
- First query per domain pays the evaluation cost; subsequent queries hit the cache
- Rule domains are independently testable and deployable
- Natural extension point for multicluster: each cluster gets its own EDB, modules
  are evaluated per-cluster and results federated at the query layer

## Cross-Domain Dependencies

Policies that reference both RBAC and label results (e.g. "which subjects can
access pods selected by this selector?") need to declare upstream module
dependencies so both are evaluated before the dependent module runs. This is
essentially the same stratification concept already used within Mangle, lifted
to the module level.

## Cache Invalidation

On cluster re-sync, reset `engine = nil` for all modules. The next query to
each domain triggers re-evaluation against the fresh EDB.
