"""Dependency resolution, legality rules and shortest violation witnesses.

Normative summary (see README.md for the full specification):

* A deployment maps component ids to chosen version labels.  Only components
  reachable from an artifact root through the chosen versions' declared
  dependencies belong to the deployment; everything else is inert.
* Every dependency of every reachable chosen version must point at a
  reachable component whose chosen version is inside the declared closed
  interval.  Cycles are legal when every member satisfies every constraint.
* Region approval and independent-review rules apply per root: a component
  serving several roots must satisfy each of those roots' regions.
* A review-requiring version needs an unexpired approval bound to exactly
  (component, version, region).
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

from .model import Case, DepEdge

VERSION_CONFLICT = "VERSION_CONFLICT"
REGION_UNAPPROVED = "REGION_UNAPPROVED"
APPROVAL_INVALID = "APPROVAL_INVALID"
POLICY_DENIED = "POLICY_DENIED"

KIND_PRIORITY = {
    VERSION_CONFLICT: 0,
    REGION_UNAPPROVED: 1,
    APPROVAL_INVALID: 2,
    POLICY_DENIED: 3,
}


@dataclass(frozen=True)
class Violation:
    """One failing root and the shortest chain that demonstrates it."""

    root: str
    region: str
    kind: str
    component: str
    version: str | None
    path: tuple[str, ...]
    detail: str
    required: tuple[tuple[str, object], ...] = ()

    def sort_key(self) -> tuple:
        return (len(self.path), self.path, KIND_PRIORITY[self.kind], self.detail)

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "root": self.root,
            "region": self.region,
            "kind": self.kind,
            "component": self.component,
            "version": self.version,
            "witness": list(self.path),
            "detail": self.detail,
        }
        for key, value in self.required:
            payload[key] = value
        return payload


class Resolver:
    """Version-aware evaluation of deployments against a parsed case."""

    def __init__(self, case: Case) -> None:
        self.case = case
        self.active_approvals: set[tuple[str, str, str]] = {
            (ap.component, ap.version, ap.region)
            for ap in case.approvals
            if ap.active(case.as_of)
        }
        self.known_approvals: set[tuple[str, str, str]] = {
            (ap.component, ap.version, ap.region) for ap in case.approvals
        }
        # component -> version -> ordered unique dependency targets
        self.dep_targets: dict[str, dict[str, tuple[str, ...]]] = {}
        # component -> version -> all declared dependency edges
        self.dep_edges: dict[str, dict[str, tuple[DepEdge, ...]]] = {}
        for cid, comp in case.components.items():
            self.dep_targets[cid] = {}
            self.dep_edges[cid] = {}
            for label, version in comp.versions.items():
                targets: list[str] = []
                for dep in version.deps:
                    if dep.component not in targets:
                        targets.append(dep.component)
                self.dep_targets[cid][label] = tuple(targets)
                self.dep_edges[cid][label] = tuple(version.deps)

    # ------------------------------------------------------------------
    # reachability

    def reachable(
        self,
        assignment: Mapping[str, str],
        running_roots: Iterable[str] | None = None,
    ) -> dict[str, tuple[str, ...]]:
        """Map every reached component to the sorted roots that reach it.

        A component with no assigned version is still reported as reached; it
        cannot expand any further dependencies.
        """

        if running_roots is None:
            root_ids = sorted(self.case.roots)
        else:
            root_ids = sorted(running_roots)
        served: dict[str, set[str]] = {}
        queue: deque[tuple[str, str]] = deque()
        for rid in root_ids:
            queue.append((self.case.roots[rid].component, rid))
        while queue:
            cid, rid = queue.popleft()
            bucket = served.get(cid)
            if bucket is None:
                bucket = served[cid] = set()
            if rid in bucket:
                continue
            bucket.add(rid)
            label = assignment.get(cid)
            if label is None:
                continue
            for target in self.dep_targets.get(cid, {}).get(label, ()):
                if rid not in served.get(target, ()):  # type: ignore[arg-type]
                    queue.append((target, rid))
        return {cid: tuple(sorted(rids)) for cid, rids in served.items()}

    def reachable_components(
        self, assignment: Mapping[str, str], running_roots: Iterable[str] | None = None
    ) -> set[str]:
        return set(self.reachable(assignment, running_roots))

    def served_regions(
        self,
        served: Mapping[str, Sequence[str]],
        root_regions: Mapping[str, str] | None = None,
    ) -> dict[str, tuple[str, ...]]:
        regions = root_regions if root_regions is not None else {
            rid: root.region for rid, root in self.case.roots.items()
        }
        out: dict[str, tuple[str, ...]] = {}
        for cid, rids in served.items():
            out[cid] = tuple(sorted({regions[rid] for rid in rids}))
        return out

    def baseline_reachable(self) -> set[str]:
        if self.case.baseline is None:
            return set()
        return set(self.reachable(self.case.baseline))

    # ------------------------------------------------------------------
    # node and edge checks

    def edge_ok(self, parent: str, parent_label: str, child: str, child_label: str) -> DepEdge | None:
        """Return the first failing edge, or ``None`` when every edge is fine."""

        ranks = self.case.rank[child]
        child_rank = ranks[child_label]
        for edge in self.dep_edges[parent][parent_label]:
            if edge.component != child:
                continue
            if not edge.accepts(child_rank, ranks):
                return edge
        return None

    def node_problem(
        self,
        cid: str,
        label: str | None,
        regions: Sequence[str],
    ) -> tuple[str, str, tuple[tuple[str, object], ...]] | None:
        if label is None:
            return (
                VERSION_CONFLICT,
                f"component {cid!r} has no selected version",
                (),
            )
        comp = self.case.components.get(cid)
        if comp is None or label not in comp.versions:
            return (
                VERSION_CONFLICT,
                f"component {cid!r} has no published version {label!r}",
                (),
            )
        version = comp.versions[label]
        for region in regions:
            if region not in version.regions:
                return (
                    REGION_UNAPPROVED,
                    f"version {label!r} of {cid!r} is not approved for region {region!r}",
                    (("region_required", region),),
                )
        for region in regions:
            if version.requires_review and (cid, label, region) not in self.active_approvals:
                if (cid, label, region) in self.known_approvals:
                    return (
                        APPROVAL_INVALID,
                        f"review approval for {cid}@{label} in region {region!r} has expired",
                        (("approval", "expired"), ("region_required", region)),
                    )
                return (
                    APPROVAL_INVALID,
                    f"version {label!r} of {cid!r} requires review in region {region!r} "
                    "but no approval exists",
                    (("approval", "missing"), ("region_required", region)),
                )
        return None

    # ------------------------------------------------------------------
    # per-root shortest witness

    def _shortest_paths(
        self, start: str, assignment: Mapping[str, str]
    ) -> tuple[dict[str, int], dict[str, tuple[str, ...]]]:
        """BFS distances plus the lexicographically smallest shortest path."""

        dist = {start: 1}
        queue: deque[str] = deque([start])
        order = [start]
        while queue:
            cid = queue.popleft()
            label = assignment.get(cid)
            if label is None:
                continue
            for target in self.dep_targets.get(cid, {}).get(label, ()):
                if target in dist:
                    continue
                dist[target] = dist[cid] + 1
                order.append(target)
                queue.append(target)
        # Lexicographically smallest shortest path: process by distance and
        # take the minimum predecessor path.  A predecessor always has a
        # strictly smaller distance, so one pass in distance order suffices.
        path: dict[str, tuple[str, ...]] = {start: (start,)}
        parents: dict[str, list[str]] = {}
        for parent, per_version in self.dep_targets.items():
            parent_label = assignment.get(parent)
            if parent_label is None:
                continue
            for target in per_version.get(parent_label, ()):
                parents.setdefault(target, []).append(parent)
        for cid in sorted(order, key=lambda c: (dist[c], c)):
            if cid == start:
                continue
            best: tuple[str, ...] | None = None
            for parent in parents.get(cid, ()):
                if dist.get(parent, 10**9) != dist[cid] - 1:
                    continue
                candidate = path[parent] + (cid,)
                if best is None or candidate < best:
                    best = candidate
            if best is not None:
                path[cid] = best
        return dist, path

    def root_violation(
        self, assignment: Mapping[str, str], root_id: str
    ) -> Violation | None:
        root = self.case.roots[root_id]
        start = root.component
        region = root.region
        dist, path = self._shortest_paths(start, assignment)
        reached = sorted(dist, key=lambda c: (dist[c], c))

        candidates: list[tuple[int, tuple[str, ...], int, Violation]] = []

        def add(kind: str, cid: str, chain: tuple[str, ...], detail: str,
                required: tuple[tuple[str, object], ...]) -> None:
            violation = Violation(
                root=root_id,
                region=region,
                kind=kind,
                component=cid,
                version=assignment.get(cid),
                path=chain,
                detail=detail,
                required=required,
            )
            candidates.append((len(chain), chain, KIND_PRIORITY[kind], violation))

        # node-level rules: presence, region approval, review approval
        for cid in reached:
            problem = self.node_problem(cid, assignment.get(cid), (region,))
            if problem is not None:
                kind, detail, required = problem
                add(kind, cid, path[cid], detail, required)

        # edge-level interval rules, for every reached dependent
        for parent in reached:
            parent_label = assignment.get(parent)
            if parent_label is None:
                continue
            for edge in self.dep_edges[parent][parent_label]:
                child = edge.component
                child_label = assignment.get(child)
                if child_label is None or child not in dist:
                    continue
                if edge.accepts(self.case.rank[child][child_label], self.case.rank[child]):
                    continue
                chain = path[parent] + (child,)
                add(
                    VERSION_CONFLICT,
                    child,
                    chain,
                    f"{parent}@{parent_label} requires {child} in "
                    f"[{edge.min_version}, {edge.max_version}] but {child_label!r} is selected",
                    (
                        ("required_by", [parent, parent_label]),
                        ("allowed", [edge.min_version, edge.max_version]),
                    ),
                )

        if not candidates:
            return None
        candidates.sort(key=lambda item: (item[0], item[1], item[2]))
        return candidates[0][3]

    def audit(self, assignment: Mapping[str, str]) -> list[Violation]:
        out = []
        for rid in sorted(self.case.roots):
            violation = self.root_violation(assignment, rid)
            if violation is not None:
                out.append(violation)
        return out

    def is_legal(
        self,
        assignment: Mapping[str, str],
        running_roots: Iterable[str] | None = None,
    ) -> bool:
        roots = sorted(self.case.roots) if running_roots is None else sorted(running_roots)
        for rid in roots:
            if self.root_violation(assignment, rid) is not None:
                return False
        return True

    # ------------------------------------------------------------------
    # stage policies

    def policy_violation(
        self,
        assignment: Mapping[str, str],
        running_roots: Sequence[str],
        step: int,
    ) -> Violation | None:
        migration = self.case.migration
        if migration is None or not migration.policies:
            return None
        served = self.reachable(assignment, running_roots)
        violations: list[Violation] = []
        for policy in migration.policies:
            if not policy.applies_to_step(step):
                continue
            for rid in sorted(running_roots):
                root = self.case.roots[rid]
                if not policy.covers_region(root.region):
                    continue
                dist, chain = self._shortest_paths(root.component, assignment)
                reachable_from_root = set(dist)
                for cid in sorted(policy.allowed):
                    if cid not in reachable_from_root:
                        continue
                    label = assignment.get(cid)
                    if label is None:
                        continue
                    if label in policy.allowed[cid]:
                        continue
                    violations.append(
                        Violation(
                            root=rid,
                            region=root.region,
                            kind=POLICY_DENIED,
                            component=cid,
                            version=label,
                            path=chain[cid],
                            detail=(
                                f"policy {policy.pid!r} at step {step} admits only "
                                f"{sorted(policy.allowed[cid])!r} for {cid}, "
                                f"but {label!r} is selected"
                            ),
                            required=(("policy", policy.pid),),
                        )
                    )
        if not violations:
            return None
        violations.sort(key=lambda v: v.sort_key())
        return violations[0]

    def step_violation(
        self,
        assignment: Mapping[str, str],
        paused: Sequence[str],
        step: int,
    ) -> Violation | None:
        """The first reason a state may not exist after ``step``.

        Covers dependency/region/review rules for every running root as well as
        the stage policy.  Capability survival is checked by the planner.
        """

        paused_set = set(paused)
        running = [rid for rid in sorted(self.case.roots) if rid not in paused_set]
        base: list[Violation] = []
        for rid in running:
            violation = self.root_violation(assignment, rid)
            if violation is not None:
                base.append(violation)
        if base:
            base.sort(key=lambda v: (v.sort_key(), v.root))
            return base[0]
        return self.policy_violation(assignment, running, step)

    # ------------------------------------------------------------------
    # objective helpers

    def deployment_changes(
        self,
        assignment: Mapping[str, str],
        baseline: Mapping[str, str] | None,
    ) -> tuple[int, int, list[dict[str, object]]]:
        """Return (changed component count, replacement cost, change list).

        Only components reachable from a root in either deployment matter.
        Additions count once with the selected version's cost, removals once
        with the component's removal cost, and version changes once with the
        new version's cost.
        """

        final_reach = self.reachable_components(assignment)
        if baseline is None:
            base_reach: set[str] = set()
        else:
            base_reach = set(self.reachable(baseline))
        changes: list[dict[str, object]] = []
        total_cost = 0
        for cid in sorted(base_reach | final_reach):
            in_final = cid in final_reach
            in_base = cid in base_reach
            new_label = assignment.get(cid)
            old_label = baseline.get(cid) if baseline is not None else None
            if in_final and in_base:
                if new_label == old_label:
                    continue
                cost = self.case.components[cid].versions[new_label].cost  # type: ignore[index]
                changes.append(
                    {
                        "component": cid,
                        "action": "change",
                        "from": old_label,
                        "to": new_label,
                        "cost": cost,
                    }
                )
                total_cost += cost
            elif in_final:
                cost = self.case.components[cid].versions[new_label].cost  # type: ignore[index]
                changes.append(
                    {
                        "component": cid,
                        "action": "add",
                        "from": None,
                        "to": new_label,
                        "cost": cost,
                    }
                )
                total_cost += cost
            else:
                cost = self.case.components[cid].removal_cost
                changes.append(
                    {
                        "component": cid,
                        "action": "remove",
                        "from": old_label,
                        "to": None,
                        "cost": cost,
                    }
                )
                total_cost += cost
        return len(changes), total_cost, changes
