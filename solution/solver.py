"""Optimal legal deployment search.

The search is a depth-first constraint search with forward propagation:

* Only components reachable from an artifact root are ever assigned.  The
  reachable set is grown as versions are chosen, so a component that no root
  reaches is never part of a deployment and never counts as a replacement.
* When a version is chosen, its dependency edges make their targets *required*.
  Required components are the only ones branched on, which is what keeps
  unreachable components out of the answer and out of the change count.
* Every assigned reachable component is re-validated after each choice:
  dependency intervals against assigned children, region approval and review
  approval against the set of roots that currently reach it.  All of those
  constraints are monotone (the reachable set and the serving-root set only
  grow), so a violated partial assignment can never become legal and is pruned.
* Cyclic dependencies need no special casing: a cycle is simply a set of
  components that become required at once, and each member is checked against
  every incoming edge and every serving root until a fixed point is reached.

The objective is lexicographic: (changed components, total change cost,
ascending list of (component, version-rank) in the final deployment).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from .deps import Resolver
from .errors import SearchLimitError
from .model import Case


@dataclass(frozen=True)
class Solution:
    deployment: dict[str, str]
    changed: int
    version_cost: int
    removal_cost: int
    changes: tuple[dict[str, object], ...]
    serving: dict[str, tuple[str, ...]]

    @property
    def total_cost(self) -> int:
        return self.version_cost + self.removal_cost

    def order_key(self, case: Case) -> tuple:
        pairs = tuple(
            (cid, case.components[cid].versions[label].rank)
            for cid, label in sorted(self.deployment.items())
        )
        return (self.changed, self.total_cost, pairs)


@dataclass
class _Closure:
    reached: dict[str, None]  # ordered set of reached components
    rootsets: dict[str, set[str]]
    required: list[str]


def _closure(resolver: Resolver, assignment: Mapping[str, str]) -> _Closure:
    served = resolver.reachable(assignment)
    rootsets: dict[str, set[str]] = {}
    for cid, rids in served.items():
        rootsets[cid] = set(rids)
    required = [cid for cid in served if cid not in assignment]
    return _Closure({cid: None for cid in served}, rootsets, sorted(required))


class Solver:
    def __init__(self, case: Case) -> None:
        self.case = case
        self.resolver = Resolver(case)
        self.baseline = case.baseline if case.baseline is not None else {}
        self.baseline_reach = (
            set(self.resolver.reachable(self.case.baseline))
            if case.baseline is not None
            else set()
        )
        self.best: Solution | None = None
        self.best_key: tuple | None = None
        self.nodes = 0
        self.max_nodes = case.limits.max_nodes
        self.max_changes = case.limits.max_changes
        self.universe = self.compute_universe()

    # ------------------------------------------------------------------

    def solve(self) -> Solution | None:
        self._search({})
        return self.best

    # ------------------------------------------------------------------

    def _domains(self, cid: str, assignment: dict[str, str], rootsets: dict[str, set[str]]) -> list[str]:
        """Versions of ``cid`` that pass all constraints visible so far."""

        comp = self.case.components[cid]
        parents = self._parents(cid, assignment)
        regions = self._regions_for(rootsets.get(cid, set()))
        allowed: list[str] = []
        for label in comp.versions:
            ok = True
            for parent, parent_label in parents:
                for edge in self.resolver.dep_edges[parent][parent_label]:
                    if edge.component != cid:
                        continue
                    if not edge.accepts(comp.versions[label].rank, self.case.rank[cid]):
                        ok = False
                        break
                if not ok:
                    break
            if not ok:
                continue
            if self.resolver.node_problem(cid, label, regions) is not None:
                continue
            allowed.append(label)
        return allowed

    def _parents(self, cid: str, assignment: Mapping[str, str]) -> list[tuple[str, str]]:
        out = []
        for parent, per_version in self.resolver.dep_targets.items():
            label = assignment.get(parent)
            if label is None:
                continue
            if cid in per_version.get(label, ()):
                out.append((parent, label))
        out.sort()
        return out

    def _regions_for(self, rids: set[str]) -> tuple[str, ...]:
        return tuple(sorted({self.case.roots[rid].region for rid in rids}))

    # ------------------------------------------------------------------

    def _check_partial(self, assignment: dict[str, str], rootsets: dict[str, set[str]]) -> bool:
        """Validate every assigned reachable component against current facts."""

        for cid, label in assignment.items():
            rids = rootsets.get(cid)
            if not rids:
                continue
            regions = self._regions_for(rids)
            if self.resolver.node_problem(cid, label, regions) is not None:
                return False
            for parent, parent_label in self._parents(cid, assignment):
                for edge in self.resolver.dep_edges[parent][parent_label]:
                    if edge.component != cid:
                        continue
                    if not edge.accepts(
                        self.case.components[cid].versions[label].rank,
                        self.case.rank[cid],
                    ):
                        return False
        return True

    def _partial_change_floor(self, assignment: Mapping[str, str]) -> tuple[int, int]:
        """A lower bound on (changed, cost) for any completion.

        Every assigned component is already reached (only required components
        are branched on) and therefore final-reachable.  Its add/change is
        decided now; future choices can only add more changes, and removals of
        baseline-only components are unbounded below by zero.
        """

        changed = 0
        cost = 0
        for cid, label in assignment.items():
            version = self.case.components[cid].versions[label]
            if cid in self.baseline_reach and self.baseline.get(cid) == label:
                continue
            changed += 1
            cost += version.cost
        return changed, cost

    # ------------------------------------------------------------------

    def _search(self, assignment: dict[str, str]) -> None:
        self.nodes += 1
        if self.nodes > self.max_nodes:
            raise SearchLimitError(
                f"deployment search exceeded {self.max_nodes} nodes; "
                "narrow the case or raise limits.max_nodes"
            )
        closure = _closure(self.resolver, assignment)
        if not self._check_partial(assignment, closure.rootsets):
            return

        floor_changed, floor_cost = self._partial_change_floor(assignment)
        if self.max_changes is not None and floor_changed > self.max_changes:
            return
        if self.best_key is not None:
            best_changed, best_cost, _ = self.best_key
            if floor_changed > best_changed:
                return
            if floor_changed == best_changed and floor_cost > best_cost:
                return

        required = closure.required
        if not required:
            self._record(assignment)
            return

        # forward check: any required component with no viable version prunes
        domains: dict[str, list[str]] = {}
        for cid in required:
            domain = self._domains(cid, assignment, closure.rootsets)
            if not domain:
                return
            domains[cid] = domain

        # most-constrained variable first; ties by id for determinism
        cid = min(required, key=lambda c: (len(domains[c]), c))
        for label in self._ordered_versions(cid, domains[cid]):
            assignment[cid] = label
            self._search(assignment)
            del assignment[cid]

    def _ordered_versions(self, cid: str, domain: list[str]) -> list[str]:
        """Prefer the baseline version, then cheap versions, then version rank."""

        base = self.baseline.get(cid)

        def key(label: str) -> tuple:
            version = self.case.components[cid].versions[label]
            return (0 if label == base else 1, version.cost, version.rank, label)

        return sorted(domain, key=key)

    # ------------------------------------------------------------------

    def _record(self, assignment: dict[str, str]) -> None:
        reached = self.resolver.reachable(assignment)
        changed, version_cost, removal_cost, changes = self._changes(assignment, reached)
        if self.max_changes is not None and changed > self.max_changes:
            return
        solution = Solution(
            deployment={cid: assignment[cid] for cid in sorted(reached)},
            changed=changed,
            version_cost=version_cost,
            removal_cost=removal_cost,
            changes=tuple(changes),
            serving={cid: rids for cid, rids in sorted(reached.items())},
        )
        key = solution.order_key(self.case)
        if self.best_key is None or key < self.best_key:
            self.best = solution
            self.best_key = key

    def _changes(
        self, assignment: Mapping[str, str], reached: Mapping[str, tuple[str, ...]]
    ) -> tuple[int, int, int, list[dict[str, object]]]:
        changes: list[dict[str, object]] = []
        version_cost = 0
        removal_cost = 0
        for cid in sorted(set(self.baseline_reach) | set(reached)):
            in_final = cid in reached
            in_base = cid in self.baseline_reach
            new_label = assignment.get(cid)
            old_label = self.baseline.get(cid)
            if in_final and in_base:
                if new_label == old_label:
                    continue
                cost = self.case.components[cid].versions[new_label].cost  # type: ignore[index]
                version_cost += cost
                changes.append(
                    {"component": cid, "action": "change", "from": old_label, "to": new_label, "cost": cost}
                )
            elif in_final:
                cost = self.case.components[cid].versions[new_label].cost  # type: ignore[index]
                version_cost += cost
                changes.append(
                    {"component": cid, "action": "add", "from": None, "to": new_label, "cost": cost}
                )
            else:
                cost = self.case.components[cid].removal_cost
                removal_cost += cost
                changes.append(
                    {"component": cid, "action": "remove", "from": old_label, "to": None, "cost": cost}
                )
        return len(changes), version_cost, removal_cost, changes

    # ------------------------------------------------------------------

    def compute_universe(self) -> set[str]:
        """Components that any root could reach under some version choice."""

        reachable_all: set[str] = set()
        stack = [self.case.roots[rid].component for rid in sorted(self.case.roots)]
        while stack:
            cid = stack.pop()
            if cid in reachable_all:
                continue
            reachable_all.add(cid)
            for version in self.case.components[cid].versions.values():
                for dep in version.deps:
                    if dep.component not in reachable_all:
                        stack.append(dep.component)
        return reachable_all

    def prime(self) -> None:
        """Precompute the potential universe used by the change lower bound."""

        self.universe = self.compute_universe()


def solve_case(case: Case) -> Solution | None:
    solver = Solver(case)
    solver.prime()
    return solver.solve()
