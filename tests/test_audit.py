"""Dependency semantics: reachability, cycles, regions, approvals, witnesses."""

from __future__ import annotations

import unittest

from tests.support import case_from, minimal_case
from solution.deps import (
    APPROVAL_INVALID,
    REGION_UNAPPROVED,
    VERSION_CONFLICT,
    Resolver,
)


def audit(doc, deployment=None):
    case = case_from(doc)
    assignment = deployment if deployment is not None else doc["deployment"]
    return case, Resolver(case).audit(assignment)


class ReachabilityTests(unittest.TestCase):
    def test_unreachable_component_is_excluded(self) -> None:
        doc = minimal_case()
        doc["components"]["legacy"] = {"versions": {"1.0.0": {"regions": ["eu"]}}}
        doc["baseline"]["legacy"] = "1.0.0"
        doc["deployment"]["legacy"] = "1.0.0"
        case = case_from(doc)
        resolver = Resolver(case)
        reached = resolver.reachable(doc["deployment"])
        self.assertNotIn("legacy", reached)
        self.assertEqual(resolver.audit(doc["deployment"]), [])

    def test_unreachable_old_component_does_not_count_as_change(self) -> None:
        doc = minimal_case()
        doc["components"]["legacy"] = {"versions": {"0.1.0": {"regions": ["eu"]}}}
        doc["baseline"]["legacy"] = "0.1.0"
        # legacy is not in the new deployment and is not reachable in the
        # baseline either, so it must not be counted as a removal.
        doc["deployment"]["lib"] = "2.0.0"
        case = case_from(doc)
        resolver = Resolver(case)
        changed, cost, changes = resolver.deployment_changes(doc["deployment"], doc["baseline"])
        self.assertEqual([c["component"] for c in changes], ["lib"])
        self.assertEqual(changed, 1)

    def test_cycle_is_reachable_both_ways(self) -> None:
        doc = minimal_case()
        doc["components"]["app"]["versions"]["1.0.0"]["deps"] = [
            {"component": "lib", "min": "1.0.0", "max": "1.0.0"}
        ]
        doc["components"]["lib"]["versions"]["1.0.0"]["deps"] = [
            {"component": "app", "min": "1.0.0", "max": "1.0.0"}
        ]
        case = case_from(doc)
        reached = Resolver(case).reachable(doc["deployment"])
        self.assertEqual(sorted(reached), ["app", "lib"])


class ViolationTests(unittest.TestCase):
    def test_version_conflict_witness_is_shortest(self) -> None:
        case, violations = audit(minimal_case())
        # lib 2.0.0 is outside app's [1.0.0, 2.0.0]? No: it is inside.
        self.assertEqual(violations, [])

    def test_version_conflict_detected(self) -> None:
        doc = minimal_case()
        doc["components"]["lib"]["versions"]["2.0.0"]["regions"] = ["eu"]
        doc["components"]["app"]["versions"]["1.0.0"]["deps"] = [
            {"component": "lib", "min": "1.0.0", "max": "1.0.0"}
        ]
        case, violations = audit(doc, {"app": "1.0.0", "lib": "2.0.0"})
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].kind, VERSION_CONFLICT)
        self.assertEqual(violations[0].path, ("app", "lib"))

    def test_region_unapproved(self) -> None:
        doc = minimal_case()
        doc["components"]["lib"]["versions"]["2.0.0"]["regions"] = ["us"]
        case, violations = audit(doc, {"app": "1.0.0", "lib": "2.0.0"})
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].kind, REGION_UNAPPROVED)
        self.assertEqual(violations[0].version, "2.0.0")

    def test_shared_component_needs_every_region(self) -> None:
        doc = minimal_case()
        doc["components"]["lib"]["versions"] = {
            "1.0.0": {"regions": ["eu"], "cost": 1},
            "2.0.0": {"regions": ["eu", "us"], "cost": 1},
        }
        doc["components"]["us-app"] = {
            "versions": {
                "1.0.0": {
                    "regions": ["us"],
                    "deps": [{"component": "lib", "min": "1.0.0", "max": "2.0.0"}],
                }
            }
        }
        doc["roots"]["us"] = {"component": "us-app", "region": "us"}
        doc["baseline"].update({"us-app": "1.0.0", "lib": "1.0.0"})
        doc["deployment"].update({"us-app": "1.0.0", "lib": "1.0.0"})
        case = case_from(doc)
        resolver = Resolver(case)
        violation = resolver.root_violation(doc["deployment"], "us")
        self.assertIsNotNone(violation)
        self.assertEqual(violation.kind, REGION_UNAPPROVED)
        self.assertEqual(violation.path, ("us-app", "lib"))

    def test_same_version_approved_in_both_regions(self) -> None:
        doc = minimal_case()
        doc["components"]["lib"]["versions"] = {
            "1.0.0": {"regions": ["eu"], "cost": 1},
            "2.0.0": {"regions": ["eu", "us"], "cost": 1},
        }
        doc["components"]["us-app"] = {
            "versions": {
                "1.0.0": {
                    "regions": ["us"],
                    "deps": [{"component": "lib", "min": "2.0.0", "max": "2.0.0"}],
                }
            }
        }
        doc["roots"]["us"] = {"component": "us-app", "region": "us"}
        doc["baseline"].update({"us-app": "1.0.0", "lib": "2.0.0"})
        doc["deployment"].update({"us-app": "1.0.0", "lib": "2.0.0"})
        doc["components"]["app"]["versions"]["1.0.0"]["deps"] = [
            {"component": "lib", "min": "2.0.0", "max": "2.0.0"}
        ]
        case = case_from(doc)
        self.assertEqual(Resolver(case).audit(doc["deployment"]), [])

    def test_expired_approval_is_approval_invalid(self) -> None:
        doc = minimal_case()
        doc["components"]["lib"]["versions"]["1.0.0"]["requires_review"] = True
        doc["approvals"] = [
            {"id": "a1", "component": "lib", "version": "1.0.0", "region": "eu", "expires": "2025-12-31"}
        ]
        case, violations = audit(doc)
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].kind, APPROVAL_INVALID)
        self.assertIn(("approval", "expired"), violations[0].required)

    def test_missing_approval_is_approval_invalid(self) -> None:
        doc = minimal_case()
        doc["components"]["lib"]["versions"]["1.0.0"]["requires_review"] = True
        case, violations = audit(doc)
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].kind, APPROVAL_INVALID)
        self.assertIn(("approval", "missing"), violations[0].required)

    def test_unexpired_approval_satisfies_review(self) -> None:
        doc = minimal_case()
        doc["components"]["lib"]["versions"]["1.0.0"]["requires_review"] = True
        doc["approvals"] = [
            {"id": "a1", "component": "lib", "version": "1.0.0", "region": "eu", "expires": "2027-01-01"}
        ]
        case, violations = audit(doc)
        self.assertEqual(violations, [])

    def test_approval_must_bind_version_and_region(self) -> None:
        doc = minimal_case()
        doc["components"]["lib"]["versions"]["1.0.0"]["requires_review"] = True
        doc["approvals"] = [
            {"id": "a1", "component": "lib", "version": "2.0.0", "region": "eu"},
            {"id": "a2", "component": "lib", "version": "1.0.0", "region": "us"},
        ]
        case, violations = audit(doc)
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].kind, APPROVAL_INVALID)


class WitnessTests(unittest.TestCase):
    def test_tie_broken_by_smallest_id_sequence(self) -> None:
        doc = minimal_case()
        # Two equally deep offenders under the same root; "alpha" must win.
        doc["components"]["app"]["versions"]["1.0.0"]["deps"] = [
            {"component": "zulu", "min": "1.0.0", "max": "1.0.0"},
            {"component": "alpha", "min": "1.0.0", "max": "1.0.0"},
        ]
        for name in ("alpha", "zulu"):
            doc["components"][name] = {
                "versions": {
                    "1.0.0": {"regions": ["eu"]},
                    "2.0.0": {"regions": ["eu"]},
                }
            }
        doc["deployment"].update({"alpha": "2.0.0", "zulu": "2.0.0"})
        case = case_from(doc)
        violation = Resolver(case).root_violation(doc["deployment"], "web")
        self.assertIsNotNone(violation)
        self.assertEqual(violation.path, ("app", "alpha"))

    def test_shorter_witness_preferred_over_deeper(self) -> None:
        doc = minimal_case()
        doc["components"]["app"]["versions"]["1.0.0"]["deps"] = [
            {"component": "mid", "min": "1.0.0", "max": "1.0.0"},
            {"component": "zulu", "min": "1.0.0", "max": "1.0.0"},
        ]
        doc["components"]["mid"] = {
            "versions": {
                "1.0.0": {
                    "regions": ["eu"],
                    "deps": [{"component": "deep", "min": "1.0.0", "max": "1.0.0"}],
                }
            }
        }
        doc["components"]["deep"] = {"versions": {"1.0.0": {"regions": ["us"]}}}
        doc["components"]["zulu"] = {"versions": {"1.0.0": {"regions": ["us"]}}}
        doc["deployment"].update({"mid": "1.0.0", "deep": "1.0.0", "zulu": "1.0.0"})
        case = case_from(doc)
        violation = Resolver(case).root_violation(doc["deployment"], "web")
        self.assertEqual(violation.path, ("app", "zulu"))

    def test_kind_priority_after_length_and_path(self) -> None:
        doc = minimal_case()
        doc["components"]["lib"]["versions"]["1.0.0"]["regions"] = []
        doc["approvals"] = []
        doc["components"]["lib"]["versions"]["1.0.0"]["requires_review"] = True
        case = case_from(doc)
        violation = Resolver(case).root_violation(doc["deployment"], "web")
        # Region is checked before review approval at the same node.
        self.assertEqual(violation.kind, REGION_UNAPPROVED)

    def test_cycle_conflict_needs_full_round(self) -> None:
        doc = minimal_case()
        doc["components"]["lib"]["versions"]["1.0.0"]["deps"] = [
            {"component": "app", "min": "1.0.0", "max": "1.0.0"}
        ]
        doc["components"]["lib"]["versions"]["2.0.0"]["deps"] = [
            {"component": "app", "min": "1.0.0", "max": "1.0.0"}
        ]
        doc["components"]["app"]["versions"]["1.0.0"]["deps"] = [
            {"component": "lib", "min": "2.0.0", "max": "2.0.0"}
        ]
        case = case_from(doc)
        doc["deployment"]["lib"] = "2.0.0"
        self.assertEqual(Resolver(case).audit(doc["deployment"]), [])
        doc["deployment"]["lib"] = "1.0.0"
        violations = Resolver(case).audit(doc["deployment"])
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].component, "lib")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()


class WitnessPathSelectionTests(unittest.TestCase):
    """Equal-length chains: the smallest id sequence that actually conflicts."""

    def test_interval_conflict_uses_smallest_conflicting_parent(self) -> None:
        doc = minimal_case()
        doc["components"]["app"]["versions"]["1.0.0"]["deps"] = [
            {"component": "asrc", "min": "1.0.0", "max": "1.0.0"},
            {"component": "bsrc", "min": "1.0.0", "max": "1.0.0"},
        ]
        # asrc tolerates lib@1, bsrc does not: only the bsrc chain is a witness.
        doc["components"]["asrc"] = {
            "versions": {
                "1.0.0": {
                    "regions": ["eu"],
                    "deps": [{"component": "lib", "min": "1.0.0", "max": "2.0.0"}],
                }
            }
        }
        doc["components"]["bsrc"] = {
            "versions": {
                "1.0.0": {
                    "regions": ["eu"],
                    "deps": [{"component": "lib", "min": "2.0.0", "max": "2.0.0"}],
                }
            }
        }
        doc["deployment"].update({"asrc": "1.0.0", "bsrc": "1.0.0", "lib": "1.0.0"})
        case = case_from(doc)
        violation = Resolver(case).root_violation(doc["deployment"], "web")
        self.assertEqual(violation.path, ("app", "bsrc", "lib"))

    def test_smaller_id_wins_when_both_chains_conflict(self) -> None:
        doc = minimal_case()
        doc["components"]["app"]["versions"]["1.0.0"]["deps"] = [
            {"component": "asrc", "min": "1.0.0", "max": "1.0.0"},
            {"component": "bsrc", "min": "1.0.0", "max": "1.0.0"},
        ]
        for name in ("asrc", "bsrc"):
            doc["components"][name] = {
                "versions": {
                    "1.0.0": {
                        "regions": ["eu"],
                        "deps": [{"component": "lib", "min": "2.0.0", "max": "2.0.0"}],
                    }
                }
            }
        doc["deployment"].update({"asrc": "1.0.0", "bsrc": "1.0.0", "lib": "1.0.0"})
        case = case_from(doc)
        violation = Resolver(case).root_violation(doc["deployment"], "web")
        self.assertEqual(violation.path, ("app", "asrc", "lib"))

    def test_missing_version_is_a_witness(self) -> None:
        doc = minimal_case()
        doc["components"]["app"]["versions"]["1.0.0"]["deps"] = [
            {"component": "lib", "min": "1.0.0", "max": "2.0.0"}
        ]
        case = case_from(doc)
        violation = Resolver(case).root_violation({"app": "1.0.0"}, "web")
        self.assertIsNotNone(violation)
        self.assertEqual(violation.kind, VERSION_CONFLICT)
        self.assertEqual(violation.path, ("app", "lib"))
        self.assertIsNone(violation.version)
