"""SQLite-backed persistence for cases, results and replayable plans.

The schema is intentionally small and append-only:

``cases``
    one row per distinct canonical case document; the primary key is the
    SHA-256 of the canonical JSON, so the same logical case always maps to the
    same row regardless of key order or whitespace.
``runs``
    one row per command invocation over a case, keyed by (case hash, command,
    options hash).  Re-running the identical request is idempotent and returns
    the previously recorded result.
``plans`` / ``plan_steps``
    a plan and its step list, so a recorded plan can be replayed independently
    of the search that produced it.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any, Iterable

from .jsonio import canonical_text, digest

SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    case_hash TEXT PRIMARY KEY,
    document  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS runs (
    case_hash   TEXT NOT NULL,
    command     TEXT NOT NULL,
    options_key TEXT NOT NULL,
    result      TEXT NOT NULL,
    PRIMARY KEY (case_hash, command, options_key)
);
CREATE TABLE IF NOT EXISTS plans (
    plan_id      TEXT PRIMARY KEY,
    case_hash    TEXT NOT NULL,
    command      TEXT NOT NULL,
    options_key  TEXT NOT NULL,
    plan_json    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS plan_steps (
    plan_id    TEXT NOT NULL,
    step_index INTEGER NOT NULL,
    op         TEXT NOT NULL,
    payload    TEXT NOT NULL,
    PRIMARY KEY (plan_id, step_index)
);
"""


class Store:
    def __init__(self, path: str) -> None:
        self.conn = sqlite3.connect(path)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    # -- cases ------------------------------------------------------------

    def put_case(self, document: Any) -> str:
        case_hash = digest(document)
        self.conn.execute(
            "INSERT OR IGNORE INTO cases (case_hash, document) VALUES (?, ?)",
            (case_hash, canonical_text(document)),
        )
        self.conn.commit()
        return case_hash

    def get_case(self, case_hash: str) -> Any | None:
        row = self.conn.execute(
            "SELECT document FROM cases WHERE case_hash = ?", (case_hash,)
        ).fetchone()
        return None if row is None else json.loads(row[0])

    def count_cases(self) -> int:
        return int(self.conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0])

    # -- runs -------------------------------------------------------------

    def get_run(self, case_hash: str, command: str, options_key: str) -> Any | None:
        row = self.conn.execute(
            "SELECT result FROM runs WHERE case_hash=? AND command=? AND options_key=?",
            (case_hash, command, options_key),
        ).fetchone()
        return None if row is None else json.loads(row[0])

    def put_run(self, case_hash: str, command: str, options_key: str, result: Any) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO runs (case_hash, command, options_key, result) "
            "VALUES (?, ?, ?, ?)",
            (case_hash, command, options_key, canonical_text(result)),
        )
        self.conn.commit()

    def list_runs(self) -> list[tuple[str, str, str]]:
        rows = self.conn.execute(
            "SELECT case_hash, command, options_key FROM runs ORDER BY case_hash, command, options_key"
        ).fetchall()
        return [(str(r[0]), str(r[1]), str(r[2])) for r in rows]

    # -- plans ------------------------------------------------------------

    def put_plan(
        self,
        plan_id: str,
        case_hash: str,
        command: str,
        options_key: str,
        plan: dict[str, Any],
        steps: Iterable[dict[str, Any]],
    ) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO plans (plan_id, case_hash, command, options_key, plan_json) "
            "VALUES (?, ?, ?, ?, ?)",
            (plan_id, case_hash, command, options_key, canonical_text(plan)),
        )
        self.conn.execute("DELETE FROM plan_steps WHERE plan_id = ?", (plan_id,))
        for index, step in enumerate(steps):
            self.conn.execute(
                "INSERT INTO plan_steps (plan_id, step_index, op, payload) VALUES (?, ?, ?, ?)",
                (plan_id, index, str(step["op"]), canonical_text(step)),
            )
        self.conn.commit()

    def get_plan(self, plan_id: str) -> tuple[dict[str, Any], list[dict[str, Any]]] | None:
        row = self.conn.execute(
            "SELECT plan_json FROM plans WHERE plan_id = ?", (plan_id,)
        ).fetchone()
        if row is None:
            return None
        plan = json.loads(row[0])
        steps = [
            json.loads(r[0])
            for r in self.conn.execute(
                "SELECT payload FROM plan_steps WHERE plan_id = ? ORDER BY step_index",
                (plan_id,),
            )
        ]
        return plan, steps

    def list_plans(self) -> list[str]:
        return [
            str(r[0])
            for r in self.conn.execute("SELECT plan_id FROM plans ORDER BY plan_id")
        ]
