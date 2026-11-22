"""CLI behaviour: exit codes, deterministic UTF-8 JSON, error locations, SQLite."""

from __future__ import annotations

import json
import unittest

from tests.support import ROOT, TempDirTest, load_example, minimal_case, run_cli


def parse_stdout(result) -> dict:
    return json.loads(result.stdout)


class CliAuditTests(TempDirTest):
    def test_audit_example_is_clean_json(self) -> None:
        result = run_cli(["audit", str(ROOT / "examples" / "approval_regions.json")])
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = parse_stdout(result)
        self.assertEqual(payload["command"], "audit")
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["violations"][0]["kind"], "APPROVAL_INVALID")

    def test_stdout_is_byte_identical_across_runs(self) -> None:
        path = str(ROOT / "examples" / "cycle_mutual_ranges.json")
        first = run_cli(["audit", path])
        second = run_cli(["audit", path])
        self.assertEqual(first.stdout, second.stdout)
        self.assertTrue(first.stdout.endswith("\n"))
        # Compact canonical JSON has no indentation.
        self.assertNotIn("\n  ", first.stdout)

    def test_semantically_equal_case_has_same_hash(self) -> None:
        doc, _ = load_example("two_roots_shared.json")
        one = self.write_case(doc, "a.json")
        reordered = json.loads(json.dumps(doc))
        # Reverse key order at the top level.
        shuffled = {key: reordered[key] for key in reversed(list(reordered))}
        two = self.write_case(shuffled, "b.json")
        first = run_cli(["audit", str(one)])
        second = run_cli(["audit", str(two)])
        self.assertEqual(parse_stdout(first)["case_hash"], parse_stdout(second)["case_hash"])

    def test_invalid_json_reports_location(self) -> None:
        path = self.tmp / "broken.json"
        path.write_text('{"schema": "sbmom/v1", }', encoding="utf-8")
        result = run_cli(["audit", str(path)])
        self.assertEqual(result.returncode, 2)
        payload = parse_stdout(result)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"]["code"], "E_JSON")
        self.assertEqual(payload["error"]["path"], "$")
        self.assertIn("line", payload["error"]["message"])

    def test_structural_error_reports_code_and_path(self) -> None:
        doc = minimal_case()
        doc["components"]["lib"]["versions"]["1.0.0"]["mystery"] = 1
        path = self.write_case(doc)
        result = run_cli(["audit", str(path)])
        self.assertEqual(result.returncode, 2)
        payload = parse_stdout(result)
        self.assertEqual(payload["error"]["code"], "E_UNKNOWN_FIELD")
        self.assertEqual(
            payload["error"]["path"], "$/components/lib/versions/1.0.0/mystery"
        )

    def test_missing_file(self) -> None:
        result = run_cli(["audit", str(self.tmp / "absent.json")])
        self.assertEqual(result.returncode, 2)
        self.assertEqual(parse_stdout(result)["error"]["code"], "E_IO")

    def test_unknown_command_is_usage_error(self) -> None:
        result = run_cli(["frobnicate", "x.json"])
        self.assertNotEqual(result.returncode, 0)


class CliSolveTests(TempDirTest):
    def test_solve_reports_changes(self) -> None:
        result = run_cli(["solve", str(ROOT / "examples" / "local_cheap_global_expensive.json")])
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = parse_stdout(result)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["changed"], 1)
        self.assertEqual(payload["deployment"]["lib-core"], "2.0.0")

    def test_solve_infeasible_is_ok_false(self) -> None:
        result = run_cli(["solve", str(ROOT / "examples" / "two_roots_shared.json")])
        self.assertEqual(result.returncode, 0)
        payload = parse_stdout(result)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["deployment"], {})


class CliPlanTests(TempDirTest):
    def test_plan_writes_and_reads_plan(self) -> None:
        db = self.tmp / "state.sqlite"
        case = str(ROOT / "examples" / "migration_pause_capability.json")
        planned = run_cli(["plan", case, "--db", str(db)])
        self.assertEqual(planned.returncode, 0, planned.stderr)
        payload = parse_stdout(planned)
        self.assertTrue(payload["ok"])
        self.assertIn("plan_id", payload)

        replayed = run_cli(["replay", case, "--db", str(db)])
        self.assertEqual(replayed.returncode, 0, replayed.stderr)
        replay = parse_stdout(replayed)
        self.assertTrue(replay["ok"], replay)
        self.assertEqual(replay["plan_id"], payload["plan_id"])

    def test_plan_is_idempotent_in_db(self) -> None:
        db = self.tmp / "state.sqlite"
        case = str(ROOT / "examples" / "migration_cycle_group.json")
        first = run_cli(["plan", case, "--db", str(db)])
        second = run_cli(["plan", case, "--db", str(db)])
        self.assertEqual(first.stdout, second.stdout)
        from solution.store import Store

        store = Store(str(db))
        try:
            self.assertEqual(store.count_cases(), 1)
        finally:
            store.close()

    def test_replay_without_db_fails_cleanly(self) -> None:
        result = run_cli(
            ["replay", str(ROOT / "examples" / "migration_cycle_group.json")]
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(parse_stdout(result)["error"]["code"], "E_USAGE")

    def test_replay_without_plan_fails_cleanly(self) -> None:
        db = self.tmp / "empty.sqlite"
        result = run_cli(
            ["replay", str(ROOT / "examples" / "migration_cycle_group.json"), "--db", str(db)]
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(parse_stdout(result)["error"]["code"], "E_NO_PLAN")

    def test_replay_unknown_plan_id(self) -> None:
        db = self.tmp / "state.sqlite"
        case = str(ROOT / "examples" / "migration_cycle_group.json")
        run_cli(["plan", case, "--db", str(db)])
        result = run_cli(["replay", case, "--db", str(db), "--plan-id", "nope"])
        self.assertEqual(result.returncode, 2)
        self.assertEqual(parse_stdout(result)["error"]["code"], "E_UNKNOWN_PLAN")

    def test_plan_without_migration_is_structural_error(self) -> None:
        result = run_cli(["plan", str(ROOT / "examples" / "cycle_mutual_ranges.json")])
        self.assertEqual(result.returncode, 2)
        self.assertEqual(parse_stdout(result)["error"]["code"], "E_NO_MIGRATION")

    def test_target_file_and_inline_object_agree(self) -> None:
        case = str(ROOT / "examples" / "migration_stage_policy.json")
        target = {"app-eu": "2.0.0", "lib": "3.0.0"}
        inline = json.dumps(target)
        path = self.write_case(target, "target.json")
        first = run_cli(["plan", case, "--target", inline])
        second = run_cli(["plan", case, "--target", str(path)])
        self.assertEqual(parse_stdout(first)["ops"], parse_stdout(second)["ops"])
        self.assertEqual(parse_stdout(first)["ops"], ["lib-1-2", "lib-2-3", "app-eu-1-2"])

    def test_unreachable_target_reported(self) -> None:
        case = str(ROOT / "examples" / "migration_cycle_group.json")
        result = run_cli(
            ["plan", case, "--target", json.dumps({"app": "1.0.0", "hub": "2.0.0", "spine": "2.0.0"})]
        )
        self.assertEqual(result.returncode, 0)
        payload = parse_stdout(result)
        self.assertFalse(payload["ok"])
        self.assertFalse(payload["target_reachable"])


class CliInspectTests(TempDirTest):
    def test_inspect_lists_universe(self) -> None:
        result = run_cli(["inspect", str(ROOT / "examples" / "approval_regions.json")])
        payload = parse_stdout(result)
        self.assertTrue(payload["ok"])
        # The potential universe is what any root could reach; "legacy" is an
        # orphan with no incoming edge, so it is in neither set.
        self.assertEqual(
            payload["potential_universe"], ["eu-app", "shared", "us-app"]
        )
        self.assertNotIn("legacy", payload["baseline_reachable"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()


class CliTargetValidationTests(TempDirTest):
    def _case(self) -> str:
        return str(ROOT / "examples" / "migration_cycle_group.json")

    def test_unknown_component_in_target(self) -> None:
        result = run_cli(["plan", self._case(), "--target", '{"ghost":"1.0.0"}'])
        self.assertEqual(result.returncode, 2)
        payload = parse_stdout(result)
        self.assertEqual(payload["error"]["code"], "E_UNKNOWN_COMPONENT")
        self.assertEqual(payload["error"]["path"], "$/target/ghost")

    def test_unknown_version_in_target(self) -> None:
        result = run_cli(["plan", self._case(), "--target", '{"app":"9.9.9"}'])
        self.assertEqual(result.returncode, 2)
        payload = parse_stdout(result)
        self.assertEqual(payload["error"]["code"], "E_UNKNOWN_VERSION")
        self.assertEqual(payload["error"]["path"], "$/target/app")

    def test_target_must_be_an_object(self) -> None:
        result = run_cli(["plan", self._case(), "--target", "[1,2]"])
        self.assertEqual(result.returncode, 2)
        self.assertEqual(parse_stdout(result)["error"]["code"], "E_USAGE")
