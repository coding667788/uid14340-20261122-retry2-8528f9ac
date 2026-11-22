"""Replacement-path planning between deployments.

A plan is a sequence of single steps.  A step is exactly one of:

``<edge id>``
    Move one component along one allowed, directed migration edge.  An edge
    with ``"from": null`` installs a component; an edge with ``"to": null``
    removes one.
``<group id>``
    Move every member of a registered atomic group at once.  All moves in the
    group change simultaneously, so a state in which only part of the group
    has moved never exists.
``pause:<root id>`` / ``resume:<root id>``
    Take one artifact root out of service, or put it back.

The state after every step must satisfy the ordinary dependency, region and
review rules for every *running* root, every active isolation-zone policy, the
capability-survival rules and the pause-concurrency limit.  Only states that
were actually reached may be used to reach the next state.

Cost model: a step costs the migration cost of its operation plus the outage
cost of every artifact that is paused once the step has completed.  So the
pause step pays the outage cost and the matching resume step does not.

The objective is lexicographic: (changed components relative to the baseline,
total migration + outage cost, number of steps, operation-id sequence).

Search is uniform-cost (Dijkstra) over states ``(installation, paused)`` using
the path key ``(cost, steps, ops)`` for expansion.  A state's installation map
retains components that are installed but reachable from no root, so they can be
revived later; the *deployment view* used for reporting and for the change count
filters that map down to root-reachable components.  Because the final objective
starts with the change count, which is a property of the endpoint alone, the
search cannot stop at the first goal; it explores the whole bounded state space
and keeps the best goal key.
"""

from __future__ import annotations

import heapq
import itertools
from dataclasses import dataclass, field
from typing import Iterable, Mapping

from .deps import Resolver, Violation
from .errors import CaseError, SearchLimitError
from .model import Case


@dataclass(frozen=True)
class StepRecord:
    index: int
    op: str
    kind: str
    migration_cost: int
    outage_cost: int
    paused: tuple[str, ...]
    assignment: dict[str, str]
    deployment: dict[str, str]
    diff: dict[str, tuple[str | None, str | None]]

    def to_dict(self) -> dict[str, object]:
        return {
            "step": self.index,
            "op": self.op,
            "kind": self.kind,
            "migration_cost": self.migration_cost,
            "outage_cost": self.outage_cost,
            "paused": list(self.paused),
            "deployment": dict(sorted(self.deployment.items())),
            "diff": {
                cid: {"from": pair[0], "to": pair[1]}
                for cid, pair in sorted(self.diff.items())
            },
        }


@dataclass
class Plan:
    ok: bool
    final_deployment: dict[str, str]
    changed: int
    total_cost: int
    migration_cost: int
    outage_cost: int
    steps: list[StepRecord]
    ops: list[str]
    initial_deployment: dict[str, str] = field(default_factory=dict)
    changes: list[dict[str, object]] = field(default_factory=list)
    reason: str | None = None
    explored_states: int = 0
    pinned_target: bool = False


class Planner:
    def __init__(self, case: Case, target: Mapping[str, str] | None = None) -> None:
        if case.migration is None:
            raise CaseError("E_NO_MIGRATION", "$/migration", "case has no migration block")
        if case.baseline is None:
            raise CaseError(
                "E_NO_BASELINE", "$/baseline", "planning requires a baseline deployment"
            )
        self.case = case
        self.migration = case.migration
        self.resolver = Resolver(case)
        self.pinned = target is not None
        self.max_states = case.limits.max_states
        self.roots_all = sorted(case.roots)
        self.baseline_reach = set(self.resolver.reachable(case.baseline))
        # Installation state is the full assignment: a component that no root
        # currently reaches is still installed and keeps its version, so a
        # later change can make it reachable again.  The *deployment* view
        # (what a plan reports and what changes are measured against) filters
        # this down to root-reachable components.
        self.initial = dict(sorted(case.baseline.items()))
        self.target = (
            {cid: label for cid, label in sorted(target.items())} if target is not None else None
        )
        self.explored = 0

    # ------------------------------------------------------------------
    # state helpers

    def _deployment(self, assignment: Mapping[str, str]) -> dict[str, str]:
        reachable = self.resolver.reachable(assignment, self.roots_all)
        return {cid: assignment[cid] for cid in sorted(assignment) if cid in reachable}

    def _state_key(self, assignment: Mapping[str, str], paused: Iterable[str]) -> tuple:
        return (tuple(sorted(assignment.items())), tuple(sorted(paused)))

    def _outage(self, paused: Iterable[str]) -> int:
        return sum(self.case.roots[rid].halt_cost for rid in paused)

    def _capability_ok(self, paused: set[str]) -> bool:
        return all(
            any(rid not in paused for rid in capability.roots)
            for capability in self.case.capabilities
        )

    def _illegal(
        self, assignment: Mapping[str, str], paused: set[str], step: int
    ) -> Violation | None:
        if len(paused) > self.migration.pause_limit:
            return Violation(
                root="",
                region="",
                kind="PAUSE_LIMIT",
                component="",
                version=None,
                path=(),
                detail=(
                    f"{len(paused)} artifacts paused exceeds the concurrency "
                    f"limit {self.migration.pause_limit}"
                ),
            )
        if not self._capability_ok(paused):
            return Violation(
                root="",
                region="",
                kind="CAPABILITY_LOST",
                component="",
                version=None,
                path=(),
                detail="a critical capability would have no running root",
            )
        return self.resolver.step_violation(assignment, sorted(paused), step)

    # ------------------------------------------------------------------
    # operations

    def _ops(self, assignment: Mapping[str, str], paused: set[str]):
        """Yield (op id, kind, migration cost, new assignment, new paused)."""

        for edge in self.migration.edges:
            current = assignment.get(edge.component)
            if current != edge.from_version:
                continue
            if edge.to_version == edge.from_version:
                continue
            new_assignment = dict(assignment)
            if edge.to_version is None:
                new_assignment.pop(edge.component, None)
            else:
                new_assignment[edge.component] = edge.to_version
            yield edge.eid, "edge", edge.cost, new_assignment, set(paused)

        for group in self.migration.groups:
            if any(assignment.get(move.component) != move.from_version for move in group.moves):
                continue
            if any(
                move.to_version is not None and move.to_version == move.from_version
                for move in group.moves
            ):
                continue
            new_assignment = dict(assignment)
            for move in group.moves:
                if move.to_version is None:
                    new_assignment.pop(move.component, None)
                else:
                    new_assignment[move.component] = move.to_version
            yield group.gid, "group", group.cost, new_assignment, set(paused)

        for rid in self.roots_all:
            new_paused = set(paused)
            if rid in paused:
                new_paused.discard(rid)
                yield f"resume:{rid}", "resume", 0, dict(assignment), new_paused
            else:
                new_paused.add(rid)
                yield f"pause:{rid}", "pause", 0, dict(assignment), new_paused

    # ------------------------------------------------------------------
    # objective

    def changes(self, assignment: Mapping[str, str]) -> list[dict[str, object]]:
        """Differences between the reachable deployment and its baseline view.

        Components that are installed but reachable from no root are excluded
        on both sides, so a component that merely sits in the inventory never
        counts as a removal or a change.
        """

        deployment = self._deployment(assignment)
        final_reach = set(deployment)
        rows: list[dict[str, object]] = []
        baseline = self.case.baseline or {}
        for cid in sorted(self.baseline_reach | final_reach):
            in_final = cid in final_reach
            in_base = cid in self.baseline_reach
            new_label = deployment.get(cid)
            old_label = baseline.get(cid)
            if in_final and in_base:
                if new_label == old_label:
                    continue
                rows.append(
                    {
                        "component": cid,
                        "action": "change",
                        "from": old_label,
                        "to": new_label,
                        "cost": self.case.components[cid].versions[new_label].cost,  # type: ignore[index]
                    }
                )
            elif in_final:
                rows.append(
                    {
                        "component": cid,
                        "action": "add",
                        "from": None,
                        "to": new_label,
                        "cost": self.case.components[cid].versions[new_label].cost,  # type: ignore[index]
                    }
                )
            else:
                rows.append(
                    {
                        "component": cid,
                        "action": "remove",
                        "from": old_label,
                        "to": None,
                        "cost": self.case.components[cid].removal_cost,
                    }
                )
        return rows

    # ------------------------------------------------------------------
    # search

    def plan(self) -> Plan:
        start_assignment = dict(self.initial)
        start_paused: set[str] = set()
        start_key = self._state_key(start_assignment, start_paused)
        counter = itertools.count()
        # (cost, steps, ops, tiebreak, state_key, assignment, paused, path)
        heap: list[tuple] = [
            (0, 0, (), next(counter), start_key, start_assignment, start_paused, [])
        ]
        best: dict[tuple, tuple[int, int, tuple]] = {start_key: (0, 0, ())}
        best_goal: tuple | None = None
        best_goal_payload: tuple | None = None

        while heap:
            cost, steps, ops, _, state_key, assignment, paused, path = heapq.heappop(heap)
            if (cost, steps, ops) > best.get(state_key, (10**18, 10**18, ())):
                continue

            if not paused:
                if self.pinned:
                    # A pinned target is compared as a deployment view: an
                    # installed-but-unreachable component in the target is not
                    # part of the deployment and must not block a match.
                    is_goal = self._deployment(assignment) == self.target
                else:
                    is_goal = not self.resolver.audit(assignment)
                if is_goal:
                    changes = self.changes(assignment)
                    goal_key = (len(changes), cost, steps, ops)
                    if best_goal is None or goal_key < best_goal:
                        best_goal = goal_key
                        best_goal_payload = (
                            dict(assignment),
                            list(path),
                            changes,
                        )

            if steps >= self.migration.max_steps:
                continue

            self.explored += 1
            if self.explored > self.max_states:
                raise SearchLimitError(
                    f"migration search exceeded {self.max_states} states; "
                    "narrow the case or raise limits.max_states"
                )

            next_step = steps + 1
            for op, kind, op_cost, candidate, candidate_paused in self._ops(assignment, paused):
                new_assignment = dict(sorted(candidate.items()))
                new_key = self._state_key(new_assignment, candidate_paused)
                step_cost = op_cost + self._outage(candidate_paused)
                new_cost = cost + step_cost
                new_ops = ops + (op,)
                previous = best.get(new_key)
                if previous is not None and previous <= (new_cost, next_step, new_ops):
                    continue
                violation = self._illegal(new_assignment, candidate_paused, next_step)
                if violation is not None:
                    continue
                best[new_key] = (new_cost, next_step, new_ops)
                diff = {
                    cid: (assignment.get(cid), new_assignment.get(cid))
                    for cid in set(assignment) | set(new_assignment)
                    if assignment.get(cid) != new_assignment.get(cid)
                }
                record = StepRecord(
                    index=next_step,
                    op=op,
                    kind=kind,
                    migration_cost=op_cost,
                    outage_cost=self._outage(candidate_paused),
                    paused=tuple(sorted(candidate_paused)),
                    assignment=dict(new_assignment),
                    deployment=self._deployment(new_assignment),
                    diff=diff,
                )
                heapq.heappush(
                    heap,
                    (
                        new_cost,
                        next_step,
                        new_ops,
                        next(counter),
                        new_key,
                        new_assignment,
                        candidate_paused,
                        path + [record],
                    ),
                )

        if best_goal_payload is None:
            return Plan(
                ok=False,
                final_deployment={},
                changed=0,
                total_cost=0,
                migration_cost=0,
                outage_cost=0,
                steps=[],
                ops=[],
                initial_deployment=self._deployment(self.initial),
                reason=(
                    "the pinned target deployment cannot be reached by any legal path"
                    if self.pinned
                    else "no legal replacement path reaches a legal final deployment"
                ),
                explored_states=self.explored,
                pinned_target=self.pinned,
            )

        final_assignment, path, changes = best_goal_payload
        migration_cost = sum(step.migration_cost for step in path)
        outage_cost = sum(step.outage_cost for step in path)
        return Plan(
            ok=True,
            final_deployment=self._deployment(final_assignment),
            changed=len(changes),
            total_cost=migration_cost + outage_cost,
            migration_cost=migration_cost,
            outage_cost=outage_cost,
            steps=list(path),
            ops=[step.op for step in path],
            initial_deployment=self._deployment(self.initial),
            changes=changes,
            explored_states=self.explored,
            pinned_target=self.pinned,
        )
