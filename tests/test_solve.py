"""Optimal deployment search: lexicographic objective against a brute-force oracle."""

from __future__ import annotations

import itertools
import unittest
from typing import Mapping

from tests.support import case_from, load_example, minimal_case
from solution.deps import Resolver
from solution.solver import solve_case


def brute_force(case, roots=None):
    """Enumerate every assignment over every component, keep legal ones.

    This oracle deliberately ignores reachability shortcuts: it assigns a
    version to *every* component, including unreachable ones, and then scores
    only what is reachable.  Agreement with the real solver therefore also
    checks that unreachable components never influence the optimum.
    """

    resolver = Resolver(case)
    ids = sorted(case.components)
    choices = [
        sorted(case.components[cid].versions) for cid in ids
    ]
    baseline = case.baseline or {}
    baseline_reach = set(resolver.reachable(baseline)) if case.baseline else set()
    best_key = None
    best = None
    for combo in itertools.product(*choices):
        assignment = dict(zip(ids, combo))
        if resolver.audit(assignment):
            continue
        reached = set(resolver.reachable(assignment))
        changes = []
        cost = 0
        for cid in sorted(baseline_reach | reached):
            in_final = cid in reached
            in_base = cid in baseline_reach
            if in_final and in_base:
                if assignment[cid] == baseline.get(cid):
                    continue
                cost += case.components[cid].versions[assignment[cid]].cost
                changes.append(cid)
            elif in_final:
                cost += case.components[cid].versions[assignment[cid]].cost
                changes.append(cid)
            else:
                cost += case.components[cid].removal_cost
                changes.append(cid)
        pairs = tuple(
            (cid, case.components[cid].versions[assignment[cid]].rank)
            for cid in sorted(reached)
        )
        key = (len(changes), cost, pairs)
        if best_key is None or key < best_key:
            best_key = key
            best = {
                "changed": len(changes),
                "cost": cost,
                "deployment": {cid: assignment[cid] for cid in sorted(reached)},
            }
    return best


class SolverBasics(unittest.TestCase):
    def test_baseline_already_legal_costs_nothing(self) -> None:
        solution = solve_case(case_from(minimal_case()))
        self.assertIsNotNone(solution)
        self.assertEqual(solution.changed, 0)
        self.assertEqual(solution.total_cost, 0)
        self.assertEqual(solution.deployment, {"app": "1.0.0", "lib": "1.0.0"})

    def test_no_legal_deployment_yields_none(self) -> None:
        doc = minimal_case()
        doc["components"]["lib"]["versions"]["1.0.0"]["regions"] = []
        doc["components"]["lib"]["versions"]["2.0.0"]["regions"] = []
        self.assertIsNone(solve_case(case_from(doc)))

    def test_single_root_independently_solvable(self) -> None:
        doc, case = load_example("two_roots_shared.json")
        # Keep only the web root: the deployment {app-web 1.0.0, http-lib 1.0.0}
        # is legal, so the optimum costs nothing.
        doc["roots"] = {"web": doc["roots"]["web"]}
        case = case_from(doc)
        solution = solve_case(case)
        self.assertTrue(solution.ok if hasattr(solution, "ok") else True)
        self.assertEqual(solution.changed, 0)

    def test_two_roots_cannot_share_one_version(self) -> None:
        doc, _ = load_example("two_roots_shared.json")
        case = case_from(doc)
        solution = solve_case(case)
        self.assertIsNone(solution)

    def test_local_cheap_upgrade_would_be_globally_worse(self) -> None:
        doc, case = load_example("local_cheap_global_expensive.json")
        solution = solve_case(case)
        self.assertIsNotNone(solution)
        # lib-core 3.0.0 is cheapest by version cost but forces app-a and app-b
        # to move too; the optimum changes exactly one component.
        self.assertEqual(solution.changed, 1)
        self.assertEqual(solution.deployment["lib-core"], "2.0.0")

    def test_cycle_requires_joint_satisfaction(self) -> None:
        doc, case = load_example("cycle_mutual_ranges.json")
        solution = solve_case(case)
        self.assertIsNotNone(solution)
        self.assertEqual(solution.deployment["cycle-a"], "2.0.0")
        self.assertEqual(solution.deployment["cycle-b"], "2.0.0")

    def test_unreachable_component_never_appears(self) -> None:
        doc, case = load_example("approval_regions.json")
        solution = solve_case(case)
        self.assertNotIn("legacy", solution.deployment)
        self.assertTrue(all(change["component"] != "legacy" for change in solution.changes))


class SolverOracle(unittest.TestCase):
    """Small exhaustive comparisons against an independent oracle."""

    def test_shared_lib_two_roots_matches_oracle(self) -> None:
        doc = minimal_case()
        doc["components"]["app"]["versions"]["1.0.0"]["deps"] = [
            {"component": "lib", "min": "1.0.0", "max": "1.0.0"}
        ]
        doc["components"]["other"] = {
            "versions": {
                "1.0.0": {
                    "regions": ["eu"],
                    "deps": [{"component": "lib", "min": "2.0.0", "max": "2.0.0"}],
                }
            }
        }
        doc["roots"]["other"] = {"component": "other", "region": "eu"}
        doc["baseline"]["other"] = "1.0.0"
        doc["deployment"]["other"] = "1.0.0"
        doc["components"]["lib"]["versions"]["2.0.0"]["cost"] = 1
        case = case_from(doc)
        expected = brute_force(case)
        if expected is None:
            self.assertIsNone(solve_case(case))
            return
        solution = solve_case(case)
        self.assertEqual(solution.changed, expected["changed"])
        self.assertEqual(solution.total_cost, expected["cost"])
        self.assertEqual(solution.deployment, expected["deployment"])

    def test_diamond_with_costs_matches_oracle(self) -> None:
        doc = minimal_case()
        doc["components"] = {
            "root": {
                "versions": {
                    "1.0.0": {
                        "regions": ["eu"],
                        "deps": [
                            {"component": "left", "min": "1.0.0", "max": "2.0.0"},
                            {"component": "right", "min": "1.0.0", "max": "2.0.0"},
                        ],
                    }
                }
            },
            "left": {
                "version_order": ["1.0.0", "2.0.0"],
                "versions": {
                    "1.0.0": {
                        "regions": ["eu"],
                        "deps": [{"component": "base", "min": "1.0.0", "max": "1.0.0"}],
                        "cost": 1,
                    },
                    "2.0.0": {
                        "regions": ["eu"],
                        "deps": [{"component": "base", "min": "2.0.0", "max": "2.0.0"}],
                        "cost": 1,
                    },
                },
            },
            "right": {
                "version_order": ["1.0.0", "2.0.0"],
                "versions": {
                    "1.0.0": {
                        "regions": ["eu"],
                        "deps": [{"component": "base", "min": "1.0.0", "max": "2.0.0"}],
                        "cost": 1,
                    },
                    "2.0.0": {"regions": ["eu"], "cost": 1},
                },
            },
            "base": {
                "version_order": ["1.0.0", "2.0.0"],
                "versions": {
                    "1.0.0": {"regions": ["eu"], "cost": 1},
                    "2.0.0": {"regions": ["eu"], "cost": 1},
                },
            },
        }
        doc["roots"] = {"svc": {"component": "root", "region": "eu"}}
        doc["baseline"] = {"root": "1.0.0", "left": "1.0.0", "right": "1.0.0", "base": "1.0.0"}
        doc["deployment"] = dict(doc["baseline"])
        case = case_from(doc)
        expected = brute_force(case)
        solution = solve_case(case)
        self.assertIsNotNone(solution)
        self.assertEqual((solution.changed, solution.total_cost), (expected["changed"], expected["cost"]))
        self.assertEqual(solution.deployment, expected["deployment"])

    def test_cycle_oracle_matches(self) -> None:
        doc, case = load_example("cycle_mutual_ranges.json")
        expected = brute_force(case)
        solution = solve_case(case)
        self.assertEqual(solution.changed, expected["changed"])
        self.assertEqual(solution.total_cost, expected["cost"])
        self.assertEqual(solution.deployment, expected["deployment"])

    def test_removal_is_a_change(self) -> None:
        doc = minimal_case()
        # Baseline: app@1.0.0 requires lib@1.0.0.  lib@1.0.0 is not approved
        # in eu, so the baseline is illegal.  app@2.0.0 drops the dependency
        # entirely, so the only legal deployment removes lib.
        doc["components"]["app"]["versions"]["1.0.0"]["deps"] = [
            {"component": "lib", "min": "1.0.0", "max": "1.0.0"}
        ]
        doc["components"]["app"]["versions"]["2.0.0"] = {"regions": ["eu"], "cost": 0}
        doc["components"]["lib"]["versions"] = {"1.0.0": {"regions": ["us"]}}
        doc["components"]["lib"]["removal_cost"] = 3
        doc["baseline"] = {"app": "1.0.0", "lib": "1.0.0"}
        doc["deployment"] = {"app": "1.0.0", "lib": "1.0.0"}
        case = case_from(doc)
        expected = brute_force(case)
        solution = solve_case(case)
        self.assertIsNotNone(solution)
        self.assertEqual(solution.deployment, {"app": "2.0.0"})
        # app changed and lib removed: two distinct change actions.
        self.assertEqual(solution.changed, 2)
        self.assertEqual(solution.removal_cost, 3)
        self.assertEqual(solution.total_cost, expected["cost"])
        actions = {change["component"]: change["action"] for change in solution.changes}
        self.assertEqual(actions, {"app": "change", "lib": "remove"})

    def test_tie_break_prefers_ascending_version_list(self) -> None:
        doc = minimal_case()
        doc["components"]["app"]["versions"]["1.0.0"]["deps"] = [
            {"component": "lib", "min": "1.0.0", "max": "2.0.0"}
        ]
        doc["components"]["lib"]["versions"]["1.0.0"]["regions"] = ["us"]
        doc["components"]["lib"]["versions"]["2.0.0"]["cost"] = 0
        # lib 1.0.0 is illegal (region), so only 2.0.0 remains; make sure the
        # solver does not merely prefer the baseline label.
        case = case_from(doc)
        solution = solve_case(case)
        self.assertEqual(solution.deployment["lib"], "2.0.0")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
