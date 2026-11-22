# SBOM admission auditing and replacement planning

A standard-library-only, CPU-only Python 3.12 tool that

* **audits** a deployment of a synthetic software bill of materials, reporting
  the shortest dependency witness for every offending artifact root, and
* **solves** for the cheapest legal deployment that also changes as few
  components as possible, and
* **plans** a step-by-step replacement path from that deployment, with
  isolation-zone policies, atomic replacement groups and explicit artifact
  pauses, and can **replay** a recorded plan from SQLite.

All data in `examples/` and `tests/` is fictional and local. Nothing touches the
network, the clock or the file system outside the paths you pass in.

---

## 1. Quick start

```console
$ python -m solution audit examples/two_roots_shared.json
$ python -m solution solve examples/local_cheap_global_expensive.json
$ python -m solution plan  examples/migration_pause_capability.json
$ python -m solution plan  examples/migration_pause_capability.json --db /tmp/state.sqlite
$ python -m solution replay examples/migration_pause_capability.json --db /tmp/state.sqlite
$ python -m unittest discover -s tests -v
```

Every command reads one case document and writes one JSON document to stdout.
The same logical case always produces byte-identical UTF-8 JSON on stdout
(sorted keys, no ASCII escaping, no insignificant whitespace, one trailing
newline).

### Commands

| command   | meaning                                                                 |
|-----------|-------------------------------------------------------------------------|
| `audit`   | validate the case's `deployment` and report one witness per bad root     |
| `solve`   | find the optimal legal deployment from the published versions            |
| `plan`    | find a legal step sequence and its optimal final deployment              |
| `replay`  | re-execute a plan recorded in SQLite, independent of the planner         |
| `inspect` | show the component graph, potential universe and baseline reachability   |

### Options

| option        | effect                                                                  |
|---------------|-------------------------------------------------------------------------|
| `--db PATH`   | SQLite file for persistent state; **required by `replay`**               |
| `--target J`  | pin the plan's final deployment; `J` is a JSON file path or an inline object |
| `--plan-id I` | replay this plan id instead of the most recent plan for the case         |
| `--pretty`    | emit sorted, indented JSON (still deterministic)                         |

### Exit codes

| code | meaning                                                             |
|------|---------------------------------------------------------------------|
| `0`  | the command completed; a negative verdict is still a completed run   |
| `2`  | the case document or the invocation is invalid                      |
| `3`  | a configured search budget (`limits.max_nodes` / `limits.max_states`) was exhausted |

A structural failure always prints

```json
{"ok":false,"error":{"code":"E_...","path":"$/...","message":"..."}}
```

where `path` is a JSON-Pointer-style location into the input document, with
`~` and `/` escaped as `~0` and `~1`. Examples:

```json
{"code":"E_UNKNOWN_FIELD","path":"$/components/lib/versions/1.0.0/mystery"}
{"code":"E_TYPE","path":"$/components/lib/versions/1.0.0/cost"}
{"code":"E_UNKNOWN_VERSION","path":"$/components/app/versions/1.0.0/deps/0/max"}
{"code":"E_JSON","path":"$","message":"invalid JSON at line 1 column 24: ..."}
```

---

## 2. Case document

```jsonc
{
  "schema": "sbmom/v1",            // optional; if present it must be exactly this
  "description": "…",              // optional free text, never interpreted
  "as_of": "2026-07-15",           // required; approval expiry is compared to this date

  "components": {                  // required, non-empty
    "<component id>": {
      "version_order": ["1.0.0", "2.0.0"],   // optional; see §2.1
      "removal_cost": 0,                     // optional, default 0
      "versions": {                          // required, non-empty
        "<version label>": {
          "deps": [                          // optional, default []
            {
              "component": "<id>",           // required
              "min": "1.0.0",                // required, inclusive lower bound
              "max": "2.0.0",                // required, inclusive upper bound
              "min_exclusive": false,        // optional, default false
              "max_exclusive": false         // optional, default false
            }
          ],
          "regions": ["eu", "us"],           // optional, default []
          "requires_review": false,          // optional, default false
          "cost": 0                          // optional, default 0
        }
      }
    }
  },

  "roots": {                       // required, non-empty
    "<root id>": {
      "component": "<id>",         // required; the root's top component
      "region": "eu",              // required; the root's deployment region
      "halt_cost": 0               // optional, default 0; outage per step paused
    }
  },

  "approvals": [                   // optional, default []
    {"id": "ap-1", "component": "<id>", "version": "2.0.0", "region": "eu",
     "expires": "2027-01-01"}      // expires optional; absent means never expires
  ],

  "baseline": {"<id>": "<version>"},        // deployment that changes are measured from
  "deployment": {"<id>": "<version>"},      // used by `audit`

  "capabilities": [                // optional; used by `plan`
    {"id": "serve", "roots": ["<root id>", "…"]}
  ],

  "limits": {                      // optional
    "max_nodes": 3000000,          // solve search-node budget
    "max_changes": null,           // optional hard cap on changed components
    "max_states": 300000          // plan search-state budget
  },

  "migration": { /* see §4 */ }    // required by `plan` and `replay`
}
```

Unknown fields are rejected (`E_UNKNOWN_FIELD`) rather than ignored, so a
mistyped key can never silently change a result.

### 2.1 Version order

Versions are only ever compared, never parsed as semver. If a component supplies
`version_order`, that list is the total order and it must mention **every**
published version exactly once (`E_VERSION_ORDER_INCOMPLETE`,
`E_VERSION_ORDER_DUPLICATE`). Otherwise a natural order is derived by splitting
labels into digit and word runs, comparing digit runs numerically and word runs
case-insensitively. Two distinct labels with the same natural key are rejected
(`E_VERSION_AMBIGUOUS`) instead of being silently ordered.

Dependency interval endpoints (`min` / `max`) must be published versions of the
target component (`E_UNKNOWN_VERSION`). An interval whose lower bound is newer
than its upper bound is rejected (`E_RANGE_EMPTY`).

### 2.2 Validation error codes

| code | meaning |
|------|---------|
| `E_JSON` | the file is not valid UTF-8 JSON |
| `E_IO` | the file could not be read |
| `E_TYPE` | a JSON value has the wrong type |
| `E_VALUE` | a value is well-typed but not admissible |
| `E_DATE` | not an ISO `YYYY-MM-DD` calendar date |
| `E_SCHEMA` | `schema` is present but not `sbmom/v1` |
| `E_UNKNOWN_FIELD` | an unexpected field name |
| `E_MISSING_FIELD` | a required field is absent |
| `E_UNKNOWN_COMPONENT` / `E_UNKNOWN_VERSION` / `E_UNKNOWN_ROOT` | dangling reference |
| `E_RANGE_EMPTY` | dependency interval is inverted |
| `E_VERSION_ORDER_INCOMPLETE` / `E_VERSION_ORDER_DUPLICATE` / `E_VERSION_AMBIGUOUS` | see §2.1 |
| `E_DUPLICATE_ID` | two approvals, edges, groups, policies or capabilities share an id |
| `E_DUPLICATE_REGION` / `E_DUPLICATE_REF` | a list repeats a value |
| `E_RESERVED_ID` | an operation id uses the reserved `pause:` / `resume:` prefix |
| `E_GROUP_DUPLICATE_COMPONENT` | one atomic group moves the same component twice |
| `E_GROUP_EMPTY` | an atomic group has no moves |
| `E_CAPABILITY_EMPTY` | a capability lists no roots |
| `E_POLICY_STEPS` | a policy's step window is malformed |
| `E_NO_DEPLOYMENT` / `E_NO_BASELINE` / `E_NO_MIGRATION` / `E_NO_PLAN` / `E_UNKNOWN_PLAN` | the command needs data the case or database does not have |
| `E_USAGE` | bad command line |

---

## 3. Admission rules

### 3.1 Reachability and the deployment

A deployment is a mapping `component -> version`. Only components **reachable
from an artifact root** are part of it: start at each root's component and
follow the dependency edges declared by the selected versions. A component
that no root reaches is inert. It is not audited, never appears in a solution's
deployment, and never counts as a removal or a change.

Reachability depends on the versions chosen, so it is recomputed for each
candidate deployment.

### 3.2 Dependency intervals

For every reached component `C` with selected version `v`, every dependency edge
declared by `v` must point at a reached component whose selected version lies
inside the declared interval. Cycles are legal but not free: every member of a
cycle must satisfy every constraint simultaneously. `(a@1, b@1)` may be
rejected purely because `b@1` requires `a@2`.

### 3.3 Regions

Region rules propagate along the dependency chain. If root `R` (in region `r`)
reaches `C`, then `C`'s selected version must list `r` in `regions`. A component
that serves several roots must be approved in **every** one of their regions.

### 3.4 Review approvals

If a selected version has `requires_review: true`, there must exist an approval
bound to exactly `(component, version, region)` that has not expired relative to
`as_of`. A missing approval and an expired approval are both reported as
`APPROVAL_INVALID`; the `detail` and the `approval` field distinguish
`"missing"` from `"expired"`.

### 3.5 Violations and witnesses

`audit` reports at most one violation per failing root:

| kind | raised when |
|------|-------------|
| `VERSION_CONFLICT` | a reached component has no version, or a selected version is outside an interval required by a dependent |
| `REGION_UNAPPROVED` | a selected version is not approved for the root's region |
| `APPROVAL_INVALID` | a review-requiring version lacks an unexpired approval for the root's region |

The **witness** is the shortest dependency chain from the root to the offending
component, expressed as an id sequence starting at the root's component. Ties on
length are broken by the lexicographically smallest id sequence, and remaining
ties by the kind priority above. This is a strict, total order, so the witness is
unique for a given deployment.

```jsonc
{"root":"us","region":"us","kind":"APPROVAL_INVALID",
 "component":"shared","version":"2.0.0","witness":["us-app","shared"],
 "detail":"review approval for shared@2.0.0 in region 'us' has expired",
 "approval":"expired","region_required":"us"}
```

---

## 4. Migration block

```jsonc
"migration": {
  "max_steps": 12,                 // required, > 0; hard bound on plan length
  "pause_limit": 1,                // optional, default 0; max artifacts down at once

  "edges": [                       // directed, one component per edge
    {"id": "lib-1-2", "component": "lib", "from": "1.0.0", "to": "2.0.0", "cost": 1}
  ],

  "groups": [                      // registered atomic replacements
    {"id": "batch-a", "cost": 2,
     "moves": [{"component": "a", "from": "1.0.0", "to": "2.0.0"},
               {"component": "b", "from": "1.0.0", "to": "2.0.0"}]}
  ],

  "policies": [                    // isolation-zone admission, per step window
    {"id": "quarantine",
     "steps": [1, 3],              // inclusive; the last value may be null = open-ended
     "regions": ["eu"],            // optional; omitted means every region
     "allowed": {"app": ["1.0.0"]} // component -> the only versions admitted
    }
  ]
}
```

* An edge with `"from": null` installs a component; `"to": null` removes one.
  Exactly one of `from` / `to` may be null, never both.
* Operation ids must be unique across edges and groups, and may not begin with
  the reserved `pause:` / `resume:` prefixes.

### 4.1 Steps

A plan is a sequence of single steps. Each step is exactly one of:

| form | effect |
|------|--------|
| `<edge id>` | move one component along that edge |
| `<group id>` | apply every move in the group **simultaneously** |
| `pause:<root id>` | take one artifact root out of service |
| `resume:<root id>` | bring it back |

Because a group is a single step, a state where only part of the group has been
applied never exists. That is what makes a mutually pinned cycle movable at all.

### 4.2 State legality

After every step, for every **running** root:

1. the ordinary dependency / region / review rules of §3 hold, and
2. every isolation policy active at that step admits the selected versions of
   its listed components.

Paused artifacts are exempt from those rules — that is the point of pausing —
but a paused artifact still holds its components, so its versions are preserved
across the pause and resume.

The planner distinguishes two related notions:

* the **installation state** is the full `component -> version` map. A component
  that no root currently reaches is still installed, keeps its version, and can
  become reachable again later (for example when a dependent downgrades to a
  version that depends on it). The state key includes these components, so two
  states that differ only in an unreachable component's version are distinct.
* the **deployment** is the installation state restricted to components some
  root reaches. This is what a plan reports, what changes are measured against,
  and what a pinned target is compared to.

Keeping the distinction is what lets a plan revive a component that is installed
but temporarily out of reach, while still never counting such a component as a
change.

Additional constraints:

* at most `pause_limit` artifacts may be paused at once;
* every capability must have at least one running root at every step;
* only states that have actually been reached may be extended.

### 4.3 Cost

A step costs its operation cost plus the outage cost of **every artifact paused
once the step has completed**:

```
step_cost = edge_or_group_cost + Σ halt_cost(r) for r paused after the step
```

So `pause:<r>` pays `halt_cost(r)` immediately, each step spent with `r` down
pays it again, and `resume:<r>` pays only its (zero) operation cost.

### 4.4 Objective

The plan objective is lexicographic:

1. fewest components changed relative to the baseline (adds, removes and version
   changes each count once),
2. lowest total migration + outage cost,
3. fewest steps,
4. lexicographically smallest operation-id sequence.

With `--target`, the endpoint is fixed and the plan minimises (2, 3, 4) over
paths that actually reach it.

---

## 5. Output documents

All output is a single JSON object, printed compactly and deterministically.

### 5.1 `audit`

```jsonc
{
  "command": "audit",
  "ok": false,
  "case_hash": "…",                       // SHA-256 of the canonical case document
  "deployment": {"<id>": "<version>"},    // reachable subset only
  "reachable": {"<id>": ["<root>", "…"]}, // which roots reach each component
  "violations": [ …witnesses as in §3.5… ],
  "changed": 1,                           // changes vs. baseline
  "change_cost": 2,
  "changes": [{"component":"…","action":"change|add|remove","from":"…","to":"…","cost":2}],
  "baseline_reachable": ["…"]
}
```

### 5.2 `solve`

```jsonc
{
  "command": "solve",
  "ok": true,
  "case_hash": "…",
  "deployment": {"<id>": "<version>"},
  "changed": 1,
  "version_cost": 2,
  "removal_cost": 0,
  "total_cost": 2,
  "changes": [ … ]
}
```

If no legal deployment exists, `ok` is `false`, `reason` explains why, and
`deployment` is `{}`.

### 5.3 `plan`

```jsonc
{
  "command": "plan",
  "ok": true,
  "case_hash": "…",
  "pinned_target": false,
  "target_source": "planner",             // or "explicit"
  "target_deployment": {"<id>": "<version>"},
  "initial_deployment": {"<id>": "<version>"},
  "final_deployment": {"<id>": "<version>"},
  "changed": 2,
  "changes": [ … ],
  "migration_cost": 2,
  "outage_cost": 21,
  "total_cost": 23,
  "steps": [
    {"step": 1, "op": "pause:a", "kind": "pause",
     "migration_cost": 0, "outage_cost": 7,
     "paused": ["a"],
     "deployment": {"<id>": "<version>"},
     "diff": {"<id>": {"from": "…", "to": "…"}}}
  ],
  "ops": ["pause:a", "…"],
  "step_count": 4,
  "explored_states": 11,
  "reason": null
}
```

When a pinned target cannot be reached, `ok` is `false`,
`target_reachable` is `false`, and `reachable_legal_endpoint` shows a legal
endpoint that **is** reachable, so the two failure modes (bad target vs. bad
graph) can be told apart.

### 5.4 `replay`

```jsonc
{
  "command": "replay",
  "ok": true,
  "plan_id": "…",
  "case_hash": "…",
  "steps": 4,
  "matches_recorded_ops": true,
  "failures": [],
  "final_deployment": {"<id>": "<version>"},
  "final_audit": [],
  "reached": [
    {"step": 0, "deployment": {…}, "paused": [], "legal": true},
    {"step": 1, "op": "pause:a", "deployment": {…}, "paused": ["a"], "legal": true}
  ]
}
```

Replay re-derives every state from the operation ids and re-checks legality, so
it never trusts the search that produced the plan. A tampered prefix reports the
first offending step.

---

## 6. How the search works

### 6.1 `solve`: backtracking with forward propagation

Search is a depth-first assignment over **required** components only. The set of
required components starts as the roots and grows exactly as versions are chosen,
because choosing a version makes its dependency targets required. Unreachable
components therefore never enter the search at all — not as variables and not in
the change count.

For each partial assignment:

* every assigned reachable component is re-validated against all of its
  incoming intervals and against the regions of all roots that currently reach
  it;
* the serving-root set only grows as more components are reached, and the
  reachable set only grows as versions are chosen, so both constraints are
  monotone — a violated partial assignment can never become legal and is pruned;
* every required-but-unassigned component gets a domain check first; an empty
  domain prunes the branch before any branching;
* the most-constrained component is branched on first (fewest viable versions,
  ties by id), and versions are tried in the order *baseline version first, then
  cheapest, then version rank*;
* a lower bound on the final change count (the already-decided adds, removes and
  changes) prunes any branch that already exceeds the best known solution, which
  is what makes the lexicographic objective safe to optimise depth-first.

**Cycles** need no special casing: a cycle simply makes several components
required at once, and each is checked against every incoming edge and every
serving root until the partial assignment is consistent. A cycle in which each
member individually looks fine but the whole round does not is rejected as soon
as the last member is assigned.

At 35 components x 4 versions the raw product is 4^35; the layered scale case in
`tests/generators.py` (and `examples/solve_scale_35x4.json`) is solved in about
120 search nodes.

### 6.2 `plan`: uniform-cost search over reachable states

The planner is Dijkstra over canonical states `(deployment, paused-set)`:

* the frontier key is `(total cost, steps, ops)` and a state is expanded only
  under its best arrival key, which is sound because both additive components
  are non-negative and the future depends only on the state;
* the whole bounded state space is explored (up to `limits.max_states`), because
  the primary objective — the change count — is a property of the endpoint and
  cannot be used to stop at the first goal;
* goals are fully running, fully legal deployments; a pinned `--target` must be
  matched exactly (as a deployment view, so an unreachable entry in the target
  is ignored);
* state keys are the full installation state plus the paused set, so a component
  that is temporarily unreachable retains its version and can be revived;
* `max_steps` bounds the frontier depth, and `max_states` raises
  `E_SEARCH_LIMIT` (exit 3) instead of silently truncating.

---

## 7. Examples

| file | demonstrates |
|------|--------------|
| `examples/two_roots_shared.json` | each root solvable alone, but no shared version; `solve` reports infeasible and `audit` names the conflicting interval |
| `examples/cycle_mutual_ranges.json` | a 2-cycle where only the (2,2) pair satisfies both edges; single-pass validation would wrongly accept (1,2) |
| `examples/local_cheap_global_expensive.json` | lib 3.0.0 is the cheapest version but would force two dependent moves; the one-change optimum wins |
| `examples/shared_version_two_regions.json` | one review-gated version approved in two regions, with one unexpired approval per region |
| `examples/unreachable_legacy.json` | an installed but unreachable component is neither audited nor counted as a removal |
| `examples/approval_regions.json` | expired vs. missing review approvals, plus an inert component |
| `examples/migration_cycle_group.json` | moving either cycle member alone is illegal; only the registered atomic group works |
| `examples/migration_unreachable_target.json` | a legal final deployment that no legal path reaches |
| `examples/migration_pause_capability.json` | every intermediate state is illegal while root `a` runs; pausing is permitted because a capability is redundantly served |
| `examples/migration_stage_policy.json` | the cheapest atomic step is barred by a stage-1 isolation policy, forcing a longer route |
| `examples/migration_atomic_group.json` | a three-way atomic batch as the minimal safe step |
| `examples/solve_scale_35x4.json` | 35 components x 4 versions, fully reachable, solved by propagation in ~115 nodes |
| `examples/migration_scale_16x3.json` | 16 components x 3 versions, a ten-step pause-gated upgrade with atomic pair batches |

Reproduce every published result with:

```console
$ python -m solution audit examples/two_roots_shared.json
$ python -m solution solve examples/two_roots_shared.json
$ python -m solution solve examples/local_cheap_global_expensive.json
$ python -m solution plan  examples/migration_cycle_group.json
$ python -m solution plan  examples/migration_pause_capability.json
$ python -m solution plan  examples/migration_stage_policy.json --target '{"app-eu":"2.0.0","lib":"3.0.0"}'
$ python -m solution solve examples/solve_scale_35x4.json
$ python -m solution plan  examples/migration_scale_16x3.json
$ python -m solution inspect examples/approval_regions.json
```

---

## 8. Persistence

`--db` stores a canonical copy of each case and its results:

| table | key | content |
|-------|-----|---------|
| `cases` | SHA-256 of the canonical document | the document |
| `runs` | (case hash, command, options hash) | the result JSON |
| `plans` | plan id | the plan document |
| `plan_steps` | (plan id, index) | one row per step |

The case hash depends on the canonical JSON, so reordering keys or reformatting
the file does not create a second row. `plan` is idempotent: running it twice
over the same case and options returns byte-identical output. `replay` without
`--db`, or with a database that has no plan for the case, fails with a located
error rather than guessing.

---

## 9. Tests

```console
$ python -m unittest discover -s tests -v
```

Coverage highlights:

* `tests/test_model.py` — parsing, version order, and every structural error
  code with its path;
* `tests/test_audit.py` — reachability, cycles, region propagation, review
  approval validity, witness minimality and tie-breaking;
* `tests/test_solve.py` — the objective, plus exhaustive brute-force oracles for
  small cases (including unreachable-component invariance);
* `tests/test_plan_oracle.py` — an independent operation-sequence oracle that
  checks the planner's change count, cost, step count and op sequence;
* `tests/test_plan.py` — atomic groups, pause/capability interaction, stage
  policy, step and pause limits, and replay;
* `tests/test_scale.py` — 35x4 `solve` and 16x3 `plan` at the documented limits,
  with node/state budget enforcement;
* `tests/test_cli.py` and `tests/test_determinism.py` — exit codes, located
  errors, byte-identical output and SQLite idempotence.

The suite uses only the standard library and finishes in a few seconds.
