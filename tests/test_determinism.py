"""Deterministic serialisation and SQLite persistence semantics."""

from __future__ import annotations

import json
import unittest

from tests.support import TempDirTest, load_example, minimal_case, run_cli
from solution.jsonio import canonical_text, digest


class CanonicalJsonTests(unittest.TestCase):
    def test_key_order_does_not_affect_text(self) -> None:
        left = {"b": 1, "a": [1, 2, {"z": 0, "y": 1}]}
        right = {"a": [1, 2, {"y": 1, "z": 0}], "b": 1}
        self.assertEqual(canonical_text(left), canonical_text(right))

    def test_digest_is_stable(self) -> None:
        doc = minimal_case()
        self.assertEqual(digest(doc), digest(json.loads(json.dumps(doc))))

    def test_non_ascii_is_kept_verbatim(self) -> None:
        text = canonical_text({"note": "批准区域"})
        self.assertIn("批准区域", text)
        self.assertNotIn("\\u", text)

    def test_no_insignificant_whitespace(self) -> None:
        text = canonical_text({"a": 1, "b": [1, 2]})
        self.assertEqual(text, '{"a":1,"b":[1,2]}')


class StoreTests(TempDirTest):
    def test_same_logical_case_is_stored_once(self) -> None:
        from solution.store import Store

        doc, _ = load_example("two_roots_shared.json")
        store = Store(str(self.tmp / "db.sqlite"))
        try:
            first = store.put_case(doc)
            reordered = {key: doc[key] for key in reversed(list(doc))}
            second = store.put_case(reordered)
            self.assertEqual(first, second)
            self.assertEqual(store.count_cases(), 1)
            self.assertEqual(store.get_case(first), doc)
        finally:
            store.close()

    def test_run_is_idempotent(self) -> None:
        from solution.store import Store

        store = Store(str(self.tmp / "db.sqlite"))
        try:
            store.put_case(minimal_case())
            store.put_run("h", "solve", "o", {"ok": True, "n": 1})
            store.put_run("h", "solve", "o", {"ok": True, "n": 1})
            self.assertEqual(store.list_runs(), [("h", "solve", "o")])
        finally:
            store.close()

    def test_plan_round_trips_through_storage(self) -> None:
        from solution.store import Store

        store = Store(str(self.tmp / "db.sqlite"))
        try:
            store.put_plan(
                "p1",
                "casehash",
                "plan",
                "opts",
                {"ok": True, "ops": ["x"]},
                [{"op": "x", "step": 1}],
            )
            plan, steps = store.get_plan("p1")
            self.assertEqual(plan["ops"], ["x"])
            self.assertEqual(steps, [{"op": "x", "step": 1}])
        finally:
            store.close()

    def test_cli_audit_then_replay_via_database(self) -> None:
        from tests.support import ROOT

        db = self.tmp / "db.sqlite"
        audit = run_cli(
            ["audit", str(ROOT / "examples" / "approval_regions.json"), "--db", str(db)]
        )
        self.assertEqual(audit.returncode, 0)
        from solution.store import Store

        store = Store(str(db))
        try:
            self.assertEqual(store.count_cases(), 1)
            self.assertEqual(len(store.list_runs()), 1)
        finally:
            store.close()


class DeterminismAcrossCommands(unittest.TestCase):
    def test_audit_and_solve_share_case_hash(self) -> None:
        from tests.support import ROOT

        case = str(ROOT / "examples" / "local_cheap_global_expensive.json")
        audit = json.loads(run_cli(["audit", case]).stdout)
        solve = json.loads(run_cli(["solve", case]).stdout)
        self.assertEqual(audit["case_hash"], solve["case_hash"])

    def test_plan_and_replay_share_plan_identity(self) -> None:
        from tests.support import ROOT

        path = ROOT / "examples" / "migration_stage_policy.json"
        first = json.loads(
            run_cli(["plan", str(path), "--target", '{"app-eu":"2.0.0","lib":"3.0.0"}']).stdout
        )
        second = json.loads(
            run_cli(["plan", str(path), "--target", '{"app-eu":"2.0.0","lib":"3.0.0"}']).stdout
        )
        self.assertEqual(first["ops"], second["ops"])
        self.assertEqual(first["target_deployment"], second["target_deployment"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
