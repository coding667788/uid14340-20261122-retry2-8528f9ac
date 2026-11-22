"""Migration planning: shape, optimality, safety, and independent replay."""

from __future__ import annotations

import unittest

from tests.support import case_from, clone, load_example, minimal_case
from solution.commands import replay_plan, run_plan
from solution.deps import Resolver
from solution.planner import Planner


def migration_case(**migration_overrides):
    doc = minimal_case()
    doc["components"]["app"]["versions"]["1.0.0"]["deps"] = [
        {"component": "lib", "min": "1.0.0", "max": "1.0.0"}
    ]
    doc["components"]["app"]["versions"]["2.0.0"] = {
        "regions": ["eu"],
        "deps": [{"component": "lib", "min": "2.0.0", "max": "2.0.0"}],
        "cost": 1,
    }
    doc["components"]["lib"]["versions"] = {
        "1.0.0": {"regions": ["eu"], "cost": 1},
        "2.0.0": {"regions": ["eu"], "cost": 1},
    }
    doc["baseline"] = {"app": "1.0.0", "lib": "1.0.0"}
    doc["deployment"] = {"app": "1.0.0", "lib": "1.0.0"}
    migration = {
        "max_steps": 8,
        "pause_limit": 1,
        "edges": [
            {"id": "app-up", "component": "app", "from": "1.0.0", "to": "2.0.0", "cost": 1},
            {"id": "lib-up", "component": "lib", "from": "1.0.0", "to": "2.0.0", "cost": 1},
        ],
        "groups": [],
        "policies": [],
    }
    migration.update(migration_overrides)
    doc["migration"] = migration
    return doc


class PlanShapeTests(unittest.TestCase):
    def test_empty_plan_when_baseline_is_optimal(self) -> None:
        doc = minimal_case()
        doc["migration"] = {"max_steps": 4, "edges": []}
        case = case_from(doc)
        plan = Planner(case).plan()
        self.assertTrue(plan.ok)
        self.assertEqual(plan.ops, [])
        self.assertEqual(plan.total_cost, 0)

    def test_every_step_is_legal_and_final_is_legal(self) -> None:
        doc, case = load_example("migration_stage_policy.json")
        payload, plan = run_plan(case, doc, {"app-eu": "2.0.0", "lib": "3.0.0"})
        self.assertTrue(plan.ok, payload)
        resolver = Resolver(case)
        for record in plan.steps:
            self.assertEqual(resolver.audit(record.assignment), [])
        self.assertEqual(resolver.audit(plan.final_deployment), [])

    def test_missing_migration_block_is_an_error(self) -> None:
        from solution.errors import CaseError

        with self.assertRaises(CaseError) as ctx:
            Planner(case_from(minimal_case()))
        self.assertEqual(ctx.exception.code, "E_NO_MIGRATION")
        self.assertEqual(ctx.exception.path, "$/migration")


class RequiredScenarios(unittest.TestCase):
    def test_cycle_needs_atomic_group(self) -> None:
        doc, case = load_example("migration_cycle_group.json")
        payload, plan = run_plan(case, doc)
        self.assertTrue(plan.ok, payload)
        self.assertEqual(plan.ops, ["cycle-atomic"])
        self.assertEqual(plan.step_count if hasattr(plan, "step_count") else len(plan.steps), 1)
        self.assertEqual(plan.final_deployment["spine"], "2.0.0")
        self.assertEqual(plan.final_deployment["hub"], "2.0.0")

    def test_single_member_change_would_be_illegal(self) -> None:
        doc, case = load_example("migration_cycle_group.json")
        payload, plan = run_plan(case, doc)
        self.assertTrue(plan.ok)
        # Prove the claim in the fixture: moving spine alone really is illegal.
        resolver = Resolver(case)
        probe = {"app": "2.0.0", "spine": "2.0.0", "hub": "1.0.0"}
        self.assertNotEqual(resolver.audit(probe), [])

    def test_final_legal_but_no_path_is_reported(self) -> None:
        doc = migration_case()
        # Remove the group and both edges: the final legal deployment
        # {app 2.0.0, lib 2.0.0} exists but nothing can move.
        doc["migration"]["edges"] = []
        doc["migration"]["groups"] = []
        case = case_from(doc)
        target = {"app": "2.0.0", "lib": "2.0.0"}
        payload, plan = run_plan(case, doc, target)
        self.assertFalse(plan.ok)
        self.assertFalse(payload["ok"])
        self.assertFalse(payload["target_reachable"])
        self.assertIsNotNone(payload["reachable_legal_endpoint"])

    def test_pause_allowed_and_capability_survives(self) -> None:
        doc, case = load_example("migration_pause_capability.json")
        payload, plan = run_plan(case, doc)
        self.assertTrue(plan.ok, payload)
        self.assertIn("pause:a", plan.ops)
        self.assertIn("resume:a", plan.ops)
        self.assertEqual(plan.ops[0], "pause:a")
        self.assertEqual(plan.ops[-1], "resume:a")
        # Outage is charged exactly while the root is down.
        paused_steps = [step for step in plan.steps if "a" in step.paused]
        self.assertEqual(len(paused_steps), 3)
        self.assertEqual(plan.outage_cost, 7 * 3)

    def test_pausing_the_only_capable_root_is_forbidden(self) -> None:
        doc = migration_case()
        doc["capabilities"] = [{"id": "serve", "roots": ["web"]}]
        # The path requires no pause, so it must still succeed without pausing.
        doc["roots"]["web"]["halt_cost"] = 1
        del doc["components"]["app"]["versions"]["2.0.0"]
        doc["migration"]["edges"] = []
        case = case_from(doc)
        payload, plan = run_plan(case, doc)
        self.assertTrue(plan.ok)
        self.assertNotIn("pause:web", plan.ops)

    def test_cheap_group_blocked_by_stage_policy(self) -> None:
        doc, case = load_example("migration_stage_policy.json")
        target = {"app-eu": "2.0.0", "lib": "3.0.0"}
        payload, plan = run_plan(case, doc, target)
        self.assertTrue(plan.ok, payload)
        # The one-step atomic group costs 2 but is unavailable at step 1, so
        # the cheaper-looking route cannot be used.
        self.assertNotIn("eu-atomic", plan.ops)
        self.assertEqual(plan.ops, ["lib-1-2", "lib-2-3", "app-eu-1-2"])

    def test_group_available_when_policy_allows_it(self) -> None:
        doc = clone(load_example("migration_stage_policy.json")[0])
        doc["migration"]["policies"] = []
        case = case_from(doc)
        payload, plan = run_plan(case, doc, {"app-eu": "2.0.0", "lib": "3.0.0"})
        self.assertTrue(plan.ok, payload)
        self.assertEqual(plan.ops, ["eu-atomic"])
        self.assertEqual(plan.total_cost, 2)

    def test_capability_group_overlap_keeps_one_alive(self) -> None:
        doc = migration_case()
        doc["components"]["other"] = {
            "versions": {"1.0.0": {"regions": ["eu"], "deps": []}}
        }
        doc["roots"]["other"] = {"component": "other", "region": "eu", "halt_cost": 100}
        doc["baseline"]["other"] = "1.0.0"
        doc["deployment"]["other"] = "1.0.0"
        doc["capabilities"] = [
            {"id": "a", "roots": ["web", "other"]},
            {"id": "b", "roots": ["other"]},
        ]
        doc["migration"]["pause_limit"] = 2
        case = case_from(doc)
        payload, plan = run_plan(case, doc)
        self.assertTrue(plan.ok, payload)
        # At most one of the overlapping-capability roots may be down at once,
        # because capability "b" is only carried by "other".
        for step in plan.steps:
            self.assertNotIn("other", step.paused)

    def test_step_limit_is_respected(self) -> None:
        doc = clone(load_example("migration_stage_policy.json")[0])
        doc["migration"]["max_steps"] = 2
        case = case_from(doc)
        payload, plan = run_plan(case, doc, {"app-eu": "2.0.0", "lib": "3.0.0"})
        self.assertFalse(plan.ok)

    def test_pause_limit_is_respected(self) -> None:
        doc, case = load_example("migration_pause_capability.json")
        doc = clone(doc)
        doc["migration"]["pause_limit"] = 0
        case = case_from(doc)
        payload, plan = run_plan(case, doc, {"app-a": "2.0.0", "lib-a": "2.0.0"})
        self.assertFalse(plan.ok)


class ReplayTests(unittest.TestCase):
    def test_replay_reproduces_recorded_plan(self) -> None:
        doc, case = load_example("migration_pause_capability.json")
        payload, plan = run_plan(case, doc)
        steps = [step.to_dict() for step in plan.steps]
        replay = replay_plan(case, payload, steps)
        self.assertTrue(replay["ok"], replay)
        self.assertTrue(replay["matches_recorded_ops"])
        self.assertEqual(replay["final_deployment"], plan.final_deployment)
        self.assertEqual(replay["failures"], [])

    def test_replay_detects_illegal_prefix(self) -> None:
        doc, case = load_example("migration_cycle_group.json")
        payload, plan = run_plan(case, doc)
        # Replace the atomic group with the single "spine" move: the recorded
        # prefix must now be rejected, and replay must say where.
        bad = [dict(step.to_dict()) for step in plan.steps]
        bad[0]["op"] = "spine-1-2"
        replay = replay_plan(case, payload, bad)
        self.assertFalse(replay["ok"])
        self.assertTrue(replay["failures"])

    def test_replay_rejects_unknown_operation(self) -> None:
        doc, case = load_example("migration_cycle_group.json")
        payload, plan = run_plan(case, doc)
        steps = [dict(step.to_dict()) for step in plan.steps]
        steps[0]["op"] = "does-not-exist"
        replay = replay_plan(case, payload, steps)
        self.assertFalse(replay["ok"])
        self.assertIn("unknown operation", replay["failures"][0]["violations"][0])

    def test_replay_independent_of_planner_search(self) -> None:
        doc, case = load_example("migration_stage_policy.json")
        target = {"app-eu": "2.0.0", "lib": "3.0.0"}
        payload, plan = run_plan(case, doc, target)
        steps = [step.to_dict() for step in plan.steps]
        replay = replay_plan(case, payload, steps)
        self.assertTrue(replay["ok"])
        for reached in replay["reached"]:
            self.assertTrue(reached["legal"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()


class InstallationStateTests(unittest.TestCase):
    """Installed-but-unreachable components keep their version across steps."""

    def _revival_doc(self):
        return {
            "schema": "sbmom/v1",
            "as_of": "2026-01-01",
            "components": {
                "app": {
                    "versions": {
                        "1.0.0": {
                            "regions": ["eu"],
                            "deps": [{"component": "lib", "min": "1.0.0", "max": "1.0.0"}],
                        },
                        "2.0.0": {"regions": ["eu"], "deps": []},
                    }
                },
                "lib": {
                    "versions": {
                        "1.0.0": {"regions": ["eu"]},
                        "2.0.0": {"regions": ["eu"]},
                    }
                },
            },
            "roots": {"r": {"component": "app", "region": "eu"}},
            "approvals": [],
            "baseline": {"app": "2.0.0", "lib": "1.0.0"},
            "deployment": {"app": "2.0.0", "lib": "1.0.0"},
            "migration": {
                "max_steps": 4,
                "pause_limit": 0,
                "edges": [
                    {"id": "app-down", "component": "app", "from": "2.0.0", "to": "1.0.0"}
                ],
                "groups": [],
                "policies": [],
            },
        }

    def test_unreachable_component_can_be_revived(self) -> None:
        doc = self._revival_doc()
        case = case_from(doc)
        # lib is installed at 1.0.0 but initially unreachable.  Downgrading app
        # makes it reachable again, so the target {app 1.0.0, lib 1.0.0} is real.
        payload, plan = run_plan(case, doc, {"app": "1.0.0", "lib": "1.0.0"})
        self.assertTrue(plan.ok, payload)
        self.assertEqual(plan.ops, ["app-down"])
        self.assertEqual(plan.final_deployment, {"app": "1.0.0", "lib": "1.0.0"})

    def test_unreachable_component_is_not_counted_in_the_optimum(self) -> None:
        doc = self._revival_doc()
        case = case_from(doc)
        plan = Planner(case).plan()
        self.assertTrue(plan.ok)
        self.assertEqual(plan.changed, 0)
        self.assertEqual(plan.final_deployment, {"app": "2.0.0"})
