# Karpenter: Finding Coverage Gaps in NodePool Configuration

Demonstrates `\smt karpenter` - uses Z3 to synthesize concrete nodeSelectors
that fall through ALL Karpenter NodePools. Every label value individually exists
in some pool, but the combination is unsatisfiable.

## Why This Requires an SMT Solver

Karpenter NodePools define a **space** of provisionable nodes via requirement
constraints (In, NotIn, Exists, DoesNotExist) and guaranteed labels. The
question "is there a nodeSelector no pool can satisfy?" is a search over the
combinatorial product of all label values across all pools. Z3 finds concrete
witnesses or proves none exist (UNSAT = full coverage, a mathematical proof).

This is not set membership - it is constraint satisfiability over the
cross-product of pool vocabularies.

## Scenario

Two NodePools:
- **general**: amd64/arm64, on-demand/spot, m5/c5 instances, linux, `team=platform`
- **gpu**: amd64 only, on-demand, p3 instances with v100 GPUs, linux, `team=ml`

## REPL Session

```
cargo run
\load-k8s examples/karpenter-unschedulable
\smt karpenter
```

## Expected Output

```
FAIL  5 coverage gap(s) found - nodeSelectors no NodePool can satisfy:
  GAP 1  node.kubernetes.io/instance-type=p3.8xlarge, team=platform
  GAP 2  node.kubernetes.io/instance-type=p3.2xlarge, team=platform
  GAP 3  kubernetes.io/arch=arm64, node.kubernetes.io/instance-type=p3.8xlarge
  GAP 4  kubernetes.io/arch=arm64, team=ml
  GAP 5  kubernetes.io/arch=arm64, nvidia.com/gpu-type=v100

A pod with any of these nodeSelectors would be permanently Pending.
Values are drawn from the pools' own vocabularies - the gap is combinatorial.
```

## What This Shows

- **GAP 1**: GPU instance type (`p3.8xlarge`) + platform team label. The `gpu`
  pool has p3 instances but labels nodes `team=ml`. The `general` pool labels
  `team=platform` but only provisions m5/c5. Neither pool can satisfy both.
- **GAP 4**: `arm64` + `team=ml`. The `gpu` pool has `team=ml` but only
  provisions `amd64`. The `general` pool supports `arm64` but labels
  `team=platform`. Cross-pool constraint conflict.
- Z3 drew every value from the pools' own requirements and labels. The gaps
  are combinatorial, not obvious from reading either pool in isolation.
- UNSAT (empty output) would be a mathematical proof of full coverage.
