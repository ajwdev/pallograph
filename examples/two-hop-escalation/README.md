# Scenario: Two-Hop Escalation Through an Intermediate Service Account

## The Story

Two PRs, two teams, two code reviews. Neither team saw the combined effect.

**PR 1 — app team:** alice gets `pods/exec create` in the `app` namespace. She's
the on-call engineer for that service and needs exec access for debugging. Reviewed
and approved by the app team. Looks reasonable.

**PR 2 — platform team (months earlier):** the `app:worker` service account was
granted `serviceaccounts/token create` in kube-system. It was part of a legitimate
cross-namespace credential rotation setup. Reviewed and approved by the platform team.
Also looks reasonable.

Each grant was reviewed in isolation. Neither reviewer had visibility into the other.

## What a Reviewer Misses

The two grants compose into an escalation chain across namespace boundaries:

```
alice
  --[pods/exec create in app]-------------> exec into app:worker pod
  --[steal mounted token of]--------------> system:serviceaccount:app:worker
  --[serviceaccounts/token create in kube-system]--> mint token for kube-system:default
  --[cluster-admin CRB]-------------------> all permissions
```

This is the case static analysis is built for. A diff-based review can only see what
changed. pallograph sees the full graph of current state — including grants approved
by different teams at different times.

## What pallograph Shows

`\access-diff` surfaces the new `pods/exec create` for alice in `app`.

`\smt cluster-admin` traces the full two-hop chain. `\why` on any
`controls_identity` fact shows the shortest path, making the chain explicit.

## Demo

```
\snapshot baseline
\source examples/two-hop-escalation/alice-twohop.mg
\access-diff baseline
\smt cluster-admin
```
