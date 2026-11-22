"""Shared helpers for the test suite.

Everything here uses only the standard library and local fixtures; no network,
no clock and no random state is involved, so the suite is deterministic.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"
sys.path.insert(0, str(ROOT))

from solution.commands import replay_plan, run_audit, run_plan, run_solve  # noqa: E402
from solution.deps import Resolver  # noqa: E402
from solution.model import parse_case  # noqa: E402
from solution.planner import Planner  # noqa: E402
from solution.solver import Solver, solve_case  # noqa: E402


def load_example(name: str) -> tuple[dict[str, Any], Any]:
    path = EXAMPLES / name
    document = json.loads(path.read_text(encoding="utf-8"))
    return document, parse_case(document)


def case_from(document: dict[str, Any]) -> Any:
    return parse_case(document)


def clone(document: dict[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(document))


def minimal_case(**overrides: Any) -> dict[str, Any]:
    """A tiny valid case document that tests can mutate."""

    base = {
        "schema": "sbmom/v1",
        "as_of": "2026-01-01",
        "components": {
            "app": {
                "versions": {
                    "1.0.0": {
                        "regions": ["eu"],
                        "deps": [{"component": "lib", "min": "1.0.0", "max": "2.0.0"}],
                    }
                }
            },
            "lib": {
                "version_order": ["1.0.0", "2.0.0"],
                "versions": {
                    "1.0.0": {"regions": ["eu"], "cost": 1},
                    "2.0.0": {"regions": ["eu"], "cost": 1},
                },
            },
        },
        "roots": {"web": {"component": "app", "region": "eu"}},
        "approvals": [],
        "baseline": {"app": "1.0.0", "lib": "1.0.0"},
        "deployment": {"app": "1.0.0", "lib": "1.0.0"},
    }
    base.update(overrides)
    return base


def run_cli(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    """Invoke the CLI in a subprocess with an isolated interpreter."""

    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT)
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run(
        [sys.executable, "-m", "solution", *args],
        cwd=str(cwd or ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
        check=False,
    )


class TempDirTest(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._temp.name)

    def tearDown(self) -> None:
        self._temp.cleanup()

    def write_case(self, document: Any, name: str = "case.json") -> Path:
        path = self.tmp / name
        path.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")
        return path
