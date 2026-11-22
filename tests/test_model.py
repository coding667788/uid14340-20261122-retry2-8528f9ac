"""Model parsing and structural error reporting."""

from __future__ import annotations

import unittest

from tests.support import case_from, clone, minimal_case
from solution.errors import CaseError
from solution.model import parse_case


class ParseTests(unittest.TestCase):
    def test_minimal_case_parses(self) -> None:
        case = case_from(minimal_case())
        self.assertEqual(sorted(case.components), ["app", "lib"])
        self.assertEqual(sorted(case.roots), ["web"])
        self.assertEqual(case.rank["lib"], {"1.0.0": 0, "2.0.0": 1})

    def test_unknown_field_reports_path(self) -> None:
        doc = minimal_case()
        doc["components"]["lib"]["versions"]["1.0.0"]["bogus"] = True
        with self.assertRaises(CaseError) as ctx:
            parse_case(doc)
        self.assertEqual(ctx.exception.code, "E_UNKNOWN_FIELD")
        self.assertEqual(
            ctx.exception.path, "$/components/lib/versions/1.0.0/bogus"
        )

    def test_missing_required_field(self) -> None:
        doc = minimal_case()
        del doc["roots"]["web"]["component"]
        with self.assertRaises(CaseError) as ctx:
            parse_case(doc)
        self.assertEqual(ctx.exception.code, "E_MISSING_FIELD")
        self.assertEqual(ctx.exception.path, "$/roots/web/component")

    def test_wrong_type_reports_path(self) -> None:
        doc = minimal_case()
        doc["components"]["lib"]["versions"]["1.0.0"]["cost"] = "cheap"
        with self.assertRaises(CaseError) as ctx:
            parse_case(doc)
        self.assertEqual(ctx.exception.code, "E_TYPE")
        self.assertEqual(
            ctx.exception.path, "$/components/lib/versions/1.0.0/cost"
        )

    def test_unknown_component_in_dependency(self) -> None:
        doc = minimal_case()
        doc["components"]["app"]["versions"]["1.0.0"]["deps"][0]["component"] = "ghost"
        with self.assertRaises(CaseError) as ctx:
            parse_case(doc)
        self.assertEqual(ctx.exception.code, "E_UNKNOWN_COMPONENT")
        self.assertEqual(
            ctx.exception.path,
            "$/components/app/versions/1.0.0/deps/0/min",
        )

    def test_interval_endpoints_must_be_published(self) -> None:
        doc = minimal_case()
        doc["components"]["app"]["versions"]["1.0.0"]["deps"][0]["max"] = "9.9.9"
        with self.assertRaises(CaseError) as ctx:
            parse_case(doc)
        self.assertEqual(ctx.exception.code, "E_UNKNOWN_VERSION")
        self.assertTrue(ctx.exception.path.endswith("/deps/0/max"))

    def test_empty_interval_is_rejected(self) -> None:
        doc = minimal_case()
        doc["components"]["app"]["versions"]["1.0.0"]["deps"][0].update(
            {"min": "2.0.0", "max": "1.0.0"}
        )
        with self.assertRaises(CaseError) as ctx:
            parse_case(doc)
        self.assertEqual(ctx.exception.code, "E_RANGE_EMPTY")

    def test_ambiguous_natural_order_needs_explicit_order(self) -> None:
        doc = minimal_case()
        doc["components"]["lib"]["versions"] = {
            "A1": {"regions": ["eu"]},
            "a1": {"regions": ["eu"]},
        }
        del doc["components"]["lib"]["version_order"]
        with self.assertRaises(CaseError) as ctx:
            parse_case(doc)
        self.assertEqual(ctx.exception.code, "E_VERSION_AMBIGUOUS")

    def test_incomplete_version_order_is_rejected(self) -> None:
        doc = minimal_case()
        doc["components"]["lib"]["version_order"] = ["1.0.0"]
        with self.assertRaises(CaseError) as ctx:
            parse_case(doc)
        self.assertEqual(ctx.exception.code, "E_VERSION_ORDER_INCOMPLETE")

    def test_duplicate_approval_id(self) -> None:
        doc = minimal_case()
        doc["approvals"] = [
            {"id": "a", "component": "lib", "version": "1.0.0", "region": "eu"},
            {"id": "a", "component": "lib", "version": "2.0.0", "region": "eu"},
        ]
        with self.assertRaises(CaseError) as ctx:
            parse_case(doc)
        self.assertEqual(ctx.exception.code, "E_DUPLICATE_ID")

    def test_bad_date(self) -> None:
        doc = minimal_case()
        doc["as_of"] = "2026-02-30"
        with self.assertRaises(CaseError) as ctx:
            parse_case(doc)
        self.assertEqual(ctx.exception.code, "E_DATE")
        self.assertEqual(ctx.exception.path, "$/as_of")

    def test_migration_reserved_op_prefix(self) -> None:
        doc = minimal_case()
        doc["migration"] = {
            "max_steps": 4,
            "edges": [
                {"id": "pause:web", "component": "lib", "from": "1.0.0", "to": "2.0.0"}
            ],
        }
        with self.assertRaises(CaseError) as ctx:
            parse_case(doc)
        self.assertEqual(ctx.exception.code, "E_RESERVED_ID")

    def test_capability_unknown_root(self) -> None:
        doc = minimal_case()
        doc["capabilities"] = [{"id": "serve", "roots": ["nope"]}]
        with self.assertRaises(CaseError) as ctx:
            parse_case(doc)
        self.assertEqual(ctx.exception.code, "E_UNKNOWN_ROOT")
        self.assertEqual(ctx.exception.path, "$/capabilities/0/roots/0")

    def test_error_is_json_serialisable(self) -> None:
        doc = minimal_case()
        doc["as_of"] = "not-a-date"
        try:
            parse_case(doc)
        except CaseError as exc:
            payload = exc.to_dict()
            self.assertEqual(payload["code"], "E_DATE")
            self.assertEqual(payload["path"], "$/as_of")
        else:  # pragma: no cover
            self.fail("expected CaseError")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
