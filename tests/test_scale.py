"""Scale and invariants at the documented limits.

``solve`` is exercised at 35 components x 4 versions and ``plan`` at 16
components x 3 versions.  Both bounds are asserted to be reached by the
generators, so the tests cannot silently degrade into something smaller.
"""

from __future__ import annotations

import time
import unittest

from tests.generators import plan_scale_case, solve_scale_case
from tests.support import case_from
from solution.deps import Resolver
from solution.model import parse_case
from solution.planner import Planner
from solution.solver import Solver, solve_case


class SolveScale(unittest.TestCase):
    def test_generator_hits_documented_bounds(self) -> None:
        doc = solve_scale_case()
        self.assertEqual(len(doc["components"]), 35)
        self.assertTrue(
            all(len(entry["versions"]) == 4 for entry in doc["components"].values())
        )

    def test_every_component_is_potentially_reachable(self) -> None:
        doc = solve_scale_case()
        case = parse_case(doc)
        self.assertEqual(len(Solver(case).compute_universe()), 35)

    def test_solve_35_by_4_is_fast_and_legal(self) -> None:
        doc = solve_scale_case()
        case = parse_case(doc)
        started = time.perf_counter()
        solution = solve_case(case)
        elapsed = time.perf_counter() - started
        self.assertIsNotNone(solution)
        self.assertLess(elapsed, 10.0, f"solve took {elapsed:.2f}s")
        self.assertEqual(Resolver(case).audit(solution.deployment), [])
        self.assertLessEqual(len(solution.deployment), 35)

    def test_solve_respects_max_changes_limit(self) -> None:
        doc = solve_scale_case()
        # Allow fewer changes than the unconstrained optimum requires: the
        # solver must return None rather than an over-budget deployment.
        doc["limits"] = {"max_changes": 1}
        case = parse_case(doc)
        solution = solve_case(case)
        self.assertIsNone(solution)

    def test_solve_is_deterministic(self) -> None:
        first = solve_case(parse_case(solve_scale_case()))
        second = solve_case(parse_case(solve_scale_case()))
        self.assertEqual(first.deployment, second.deployment)
        self.assertEqual(first.changes, second.changes)

    def test_node_budget_is_enforced(self) -> None:
        from solution.errors import SearchLimitError

        doc = solve_scale_case()
        doc["limits"] = {"max_nodes": 1}
        case = parse_case(doc)
        with self.assertRaises(SearchLimitError):
            solve_case(case)


class PlanScale(unittest.TestCase):
    def test_generator_hits_documented_bounds(self) -> None:
        doc = plan_scale_case()
        self.assertEqual(len(doc["components"]), 16)
        self.assertTrue(
            all(len(entry["versions"]) == 3 for entry in doc["components"].values())
        )

    def test_plan_16_by_3_is_fast_and_legal(self) -> None:
        doc = plan_scale_case()
        case = parse_case(doc)
        started = time.perf_counter()
        plan = Planner(case).plan()
        elapsed = time.perf_counter() - started
        self.assertTrue(plan.ok)
        self.assertLess(elapsed, 20.0, f"plan took {elapsed:.2f}s")
        self.assertLessEqual(len(plan.steps), case.migration.max_steps)
        resolver = Resolver(case)
        for record in plan.steps:
            # Legality is only required for *running* roots; a paused artifact
            # is allowed to be mid-migration.
            running = [rid for rid in case.roots if rid not in record.paused]
            violations = [resolver.root_violation(record.assignment, rid) for rid in running]
            self.assertEqual([v for v in violations if v is not None], [])

    def test_plan_pauses_before_moving_and_resumes_at_end(self) -> None:
        doc = plan_scale_case()
        case = parse_case(doc)
        plan = Planner(case).plan()
        self.assertEqual(plan.ops[0], "pause:us")
        self.assertEqual(plan.ops[-1], "resume:us")
        self.assertTrue(any(op.startswith("batch-") for op in plan.ops))
        self.assertIn("gate-1.0.0-2.0.0", plan.ops)

    def test_plan_step_bound_is_respected(self) -> None:
        doc = plan_scale_case()
        doc["migration"]["max_steps"] = 4
        case = parse_case(doc)
        plan = Planner(case).plan()
        self.assertFalse(plan.ok)

    def test_plan_state_budget_is_enforced(self) -> None:
        from solution.errors import SearchLimitError

        doc = plan_scale_case()
        doc["limits"] = {"max_states": 5}
        case = parse_case(doc)
        with self.assertRaises(SearchLimitError):
            Planner(case).plan()

    def test_plan_is_deterministic(self) -> None:
        first = Planner(parse_case(plan_scale_case())).plan()
        second = Planner(parse_case(plan_scale_case())).plan()
        self.assertEqual(first.ops, second.ops)
        self.assertEqual(first.final_deployment, second.final_deployment)
        self.assertEqual(first.total_cost, second.total_cost)


class BacktrackingPropagation(unittest.TestCase):
    def test_propagation_prunes_without_exhausting_the_product(self) -> None:
        """Naive enumeration is 4**35; propagation must visit far fewer nodes."""

        doc = solve_scale_case()
        case = parse_case(doc)
        solver = Solver(case)
        solver.prime()
        solution = solver.solve()
        self.assertIsNotNone(solution)
        self.assertLess(solver.nodes, 200_000)
        self.assertGreater(solver.nodes, 0)

    def test_unreachable_component_is_ignored_by_solver(self) -> None:
        doc = solve_scale_case()
        doc["components"]["orphan"] = {
            "versions": {"1.0.0": {"regions": [], "cost": 999}},
            "removal_cost": 999,
        }
        doc["baseline"]["orphan"] = "1.0.0"
        doc["deployment"]["orphan"] = "1.0.0"
        case = parse_case(doc)
        solution = solve_case(case)
        self.assertNotIn("orphan", solution.deployment)
        self.assertTrue(all(change["component"] != "orphan" for change in solution.changes))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
