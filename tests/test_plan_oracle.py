"""Planner optimality against an independent exhaustive path oracle."""

from __future__ import annotations

import itertools
import unittest
from collections import deque

from tests.support import case_from, minimal_case
from solution.deps import Resolver
from solution.planner import Planner


def oracle_plan(case, target=None):
    """Exhaustive breadth-first search over explicit operation sequences.

    This oracle shares no code with ``Planner`` beyond the parsed model: it
    enumerates legal operation applications, tracks reachable states by
    breadth-first expansion and keeps the lexicographic best goal key
    ``(changes, cost, steps, ops)``.  It is only viable for tiny cases, which
    is exactly what it is used for.
    """

    resolver = Resolver(case)
    migration = case.migration
    baseline = dict(case.baseline)
    root_ids = sorted(case.roots)
    universe = set()
    stack = [case.roots[rid].component for rid in root_ids]
    while stack:
        cid = stack.pop()
        if cid in universe:
            continue
        universe.add(cid)
        for version in case.components[cid].versions.values():
            for dep in version.deps:
                if dep.component not in universe:
                    stack.append(dep.component)

    def canonical(assignment):
        reached = resolver.reachable(assignment, root_ids)
        return {cid: assignment[cid] for cid in sorted(assignment) if cid in reached}

    def outage(paused):
        return sum(case.roots[rid].halt_cost for rid in paused)

    def ops(assignment, paused):
        for edge in migration.edges:
            if assignment.get(edge.component) != edge.from_version:
                continue
            if edge.to_version == edge.from_version:
                continue
            new = dict(assignment)
            if edge.to_version is None:
                new.pop(edge.component, None)
            else:
                new[edge.component] = edge.to_version
            yield edge.eid, edge.cost, new, set(paused)
        for group in migration.groups:
            if any(assignment.get(m.component) != m.from_version for m in group.moves):
                continue
            new = dict(assignment)
            for move in group.moves:
                if move.to_version is None:
                    new.pop(move.component, None)
                else:
                    new[move.component] = move.to_version
            yield group.gid, group.cost, new, set(paused)
        for rid in root_ids:
            newp = set(paused)
            if rid in paused:
                newp.discard(rid)
                yield f"resume:{rid}", 0, dict(assignment), newp
            else:
                newp.add(rid)
                yield f"pause:{rid}", 0, dict(assignment), newp

    def legal(assignment, paused):
        if len(paused) > migration.pause_limit:
            return False
        if not all(any(rid not in paused for rid in cap.roots) for cap in case.capabilities):
            return False
        return resolver.step_violation(assignment, sorted(paused), 0) is None

    def changes(assignment):
        reached = set(resolver.reachable(assignment, root_ids))
        base_reach = set(resolver.reachable(baseline, root_ids))
        rows = []
        for cid in sorted(base_reach | reached):
            if cid in reached and cid in base_reach:
                if assignment.get(cid) != baseline.get(cid):
                    rows.append(cid)
            elif cid in reached:
                rows.append(cid)
            else:
                rows.append(cid)
        return len(rows)

    start = canonical(baseline)
    start_state = (tuple(sorted(start.items())), ())
    best_by_state = {start_state: (0, 0, ())}
    queue = deque([(start, frozenset(), 0, 0, ())])
    best_goal = None
    while queue:
        assignment, paused, cost, steps, path = queue.popleft()
        state_now = (tuple(sorted(assignment.items())), tuple(sorted(paused)))
        if best_by_state.get(state_now, (10**18, 10**18, ())) < (cost, steps, path):
            continue
        if not paused:
            if target is None or assignment == target:
                if target is not None or resolver.audit(assignment) == []:
                    key = (changes(assignment), cost, steps, path)
                    if best_goal is None or key < best_goal[0]:
                        best_goal = (key, assignment, path)
        if steps >= migration.max_steps:
            continue
        for op, op_cost, candidate, candidate_paused in ops(assignment, paused):
            new = canonical(candidate)
            state = (tuple(sorted(new.items())), tuple(sorted(candidate_paused)))
            new_key = (cost + op_cost + outage(candidate_paused), steps + 1, path + (op,))
            previous = best_by_state.get(state)
            if previous is not None and previous <= new_key:
                continue
            if not legal(new, candidate_paused):
                continue
            best_by_state[state] = new_key
            queue.append((new, candidate_paused, new_key[0], new_key[1], new_key[2]))
    return best_goal


def simple_migration(**overrides):
    doc = minimal_case()
    doc["components"]["lib"].pop("version_order", None)
    doc["components"]["lib"]["versions"] = {
        "1.0.0": {"regions": ["eu"], "cost": 1},
        "2.0.0": {"regions": ["eu"], "cost": 1},
        "3.0.0": {"regions": ["eu"], "cost": 1},
    }
    doc["components"]["app"]["versions"]["1.0.0"]["deps"] = [
        {"component": "lib", "min": "1.0.0", "max": "3.0.0"}
    ]
    doc["baseline"] = {"app": "1.0.0", "lib": "1.0.0"}
    doc["deployment"] = {"app": "1.0.0", "lib": "1.0.0"}
    migration = {
        "max_steps": 5,
        "pause_limit": 1,
        "edges": [
            {"id": "l12", "component": "lib", "from": "1.0.0", "to": "2.0.0", "cost": 1},
            {"id": "l23", "component": "lib", "from": "2.0.0", "to": "3.0.0", "cost": 1},
            {"id": "l32", "component": "lib", "from": "3.0.0", "to": "2.0.0", "cost": 1},
            {"id": "a12", "component": "app", "from": "1.0.0", "to": "2.0.0", "cost": 2},
        ],
        "groups": [],
        "policies": [],
    }
    migration.update(overrides)
    doc["migration"] = migration
    doc["components"]["app"]["versions"]["2.0.0"] = {
        "regions": ["eu"],
        "deps": [{"component": "lib", "min": "3.0.0", "max": "3.0.0"}],
        "cost": 1,
    }
    return doc


class OracleAgreement(unittest.TestCase):
    def _compare(self, doc, target=None):
        case = case_from(doc)
        expected = oracle_plan(case, target)
        plan = Planner(case, target).plan()
        if expected is None:
            self.assertFalse(plan.ok)
            return
        key, assignment, path = expected
        self.assertTrue(plan.ok)
        self.assertEqual(plan.changed, key[0], (plan.ops, path))
        self.assertEqual(plan.total_cost, key[1], (plan.ops, path))
        self.assertEqual(tuple(plan.ops), key[3], (plan.ops, path))
        self.assertEqual(plan.final_deployment, assignment)

    def test_linear_upgrade_choice(self) -> None:
        # lib 3.0.0 is legal for app 1.0.0, and lib 2.0.0 as well.  The plan
        # can stop at one change either way; the tie-break prefers the cheaper
        # first step, which is lib 1 -> 2 (cost 1).
        self._compare(simple_migration())

    def test_pinned_target_needs_two_steps(self) -> None:
        self._compare(simple_migration(), {"app": "2.0.0", "lib": "3.0.0"})

    def test_atomic_group_is_preferred_when_cheaper(self) -> None:
        doc = simple_migration(
            groups=[
                {
                    "id": "both",
                    "moves": [
                        {"component": "lib", "from": "1.0.0", "to": "3.0.0"},
                        {"component": "app", "from": "1.0.0", "to": "2.0.0"},
                    ],
                    "cost": 1,
                }
            ]
        )
        self._compare(doc, {"app": "2.0.0", "lib": "3.0.0"})

    def test_pause_needed_when_no_path_without_it(self) -> None:
        doc = simple_migration()
        # Pin the app dependency to an exact range so no single move is legal
        # and there is no atomic group: only pausing root web helps.
        doc["components"]["app"]["versions"]["1.0.0"]["deps"] = [
            {"component": "lib", "min": "1.0.0", "max": "1.0.0"}
        ]
        doc["components"]["app"]["versions"]["2.0.0"]["deps"] = [
            {"component": "lib", "min": "3.0.0", "max": "3.0.0"}
        ]
        doc["roots"]["web"]["halt_cost"] = 2
        doc["migration"]["max_steps"] = 6
        self._compare(doc, {"app": "2.0.0", "lib": "3.0.0"})


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
