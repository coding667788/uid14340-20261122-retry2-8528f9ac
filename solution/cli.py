"""Command line interface: ``python -m solution <command> CASE.json``.

Exit codes
----------
0   command completed (including a negative but well-formed verdict)
2   the case document or invocation was invalid
3   a configured search budget was exhausted
4   an internal invariant was violated (a bug; please report)
"""

from __future__ import annotations

import argparse
import sys
from typing import Any, Mapping, Sequence

from .commands import (
    TOOL_VERSION,
    replay_plan,
    run_audit,
    run_plan,
    run_solve,
)
from .errors import CaseError, SearchLimitError, UsageError
from .jsonio import canonical_text, digest, emit, load_case
from .model import parse_case
from .store import Store

COMMANDS = ("audit", "solve", "plan", "replay", "inspect")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m solution",
        description="SBOM component admission auditing and replacement planning.",
    )
    parser.add_argument("command", choices=COMMANDS, help="command to run")
    parser.add_argument("case", help="path to a case JSON document")
    parser.add_argument(
        "--db",
        default=None,
        help="SQLite database for persistent state (required by replay)",
    )
    parser.add_argument(
        "--target",
        default=None,
        help="JSON assignment file (or inline JSON object) used as the plan target",
    )
    parser.add_argument(
        "--plan-id",
        default=None,
        help="plan id to replay (defaults to the plan recorded for this case)",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="indent the JSON output (default is compact canonical JSON)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"sbmom {TOOL_VERSION}",
    )
    return parser


def _load_target(raw: str | None) -> dict[str, str] | None:
    if raw is None:
        return None
    text = raw
    if not raw.lstrip().startswith("{"):
        try:
            with open(raw, "rb") as handle:
                text = handle.read().decode("utf-8-sig")
        except OSError as exc:
            raise UsageError(f"cannot read --target file: {exc}") from exc
    try:
        value = __import__("json").loads(text)
    except Exception as exc:  # noqa: BLE001 - reported as a usage problem
        raise UsageError(f"--target is not valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise UsageError("--target must be a JSON object mapping component -> version")
    out: dict[str, str] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not isinstance(item, str):
            raise UsageError("--target keys and values must be strings")
        out[key] = item
    return out


def _options_key(args: argparse.Namespace) -> str:
    target = _load_target(args.target)
    payload: dict[str, Any] = {"target": target, "plan_id": args.plan_id}
    return digest(payload)


def _emit(payload: Mapping[str, Any], pretty: bool) -> None:
    if pretty:
        sys.stdout.write(canonical_text(payload))
        sys.stdout.write("\n")
    else:
        sys.stdout.write(emit(payload))


def _fail(code: str, path: str, message: str, pretty: bool = False) -> int:
    payload = {"ok": False, "error": {"code": code, "path": path, "message": message}}
    _emit(payload, pretty)
    return 2


def _run(argv: Sequence[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        document = load_case(args.case)
        case = parse_case(document)
    except CaseError as exc:
        return _fail(exc.code, exc.path, exc.message, args.pretty)
    except UsageError as exc:
        return _fail(exc.code, exc.path, exc.message, args.pretty)

    try:
        options_key = _options_key(args)
    except UsageError as exc:
        return _fail(exc.code, exc.path, exc.message, args.pretty)

    store: Store | None = None
    if args.db:
        try:
            store = Store(args.db)
        except Exception as exc:  # noqa: BLE001
            return _fail("E_DB", "$", f"cannot open database: {exc}", args.pretty)

    try:
        if args.command == "audit":
            payload = run_audit(case, document)
        elif args.command == "solve":
            payload = run_solve(case, document)
        elif args.command == "inspect":
            payload = _inspect(case, document)
        elif args.command == "plan":
            payload, plan = run_plan(case, document, _load_target(args.target))
            if store is not None and plan is not None and plan.ok:
                case_hash = store.put_case(document)
                plan_id = digest(
                    {
                        "case": case_hash,
                        "ops": plan.ops,
                        "final": plan.final_deployment,
                    }
                )[:16]
                document_plan = dict(payload)
                document_plan["plan_id"] = plan_id
                store.put_plan(
                    plan_id,
                    case_hash,
                    "plan",
                    options_key,
                    document_plan,
                    [step.to_dict() for step in plan.steps],
                )
                payload = document_plan
                store.put_run(case_hash, "plan", options_key, payload)
            elif store is not None:
                case_hash = store.put_case(document)
                store.put_run(case_hash, "plan", options_key, payload)
        elif args.command == "replay":
            if store is None:
                raise UsageError("replay requires --db")
            payload = _run_replay(case, document, store, args.plan_id)
        else:  # pragma: no cover - argparse rejects other values
            raise UsageError(f"unknown command {args.command!r}")
    except CaseError as exc:
        if store is not None:
            store.close()
        return _fail(exc.code, exc.path, exc.message, args.pretty)
    except UsageError as exc:
        if store is not None:
            store.close()
        return _fail(exc.code, exc.path, exc.message, args.pretty)
    except SearchLimitError as exc:
        if store is not None:
            store.close()
        _emit(
            {"ok": False, "error": {"code": exc.code, "path": exc.path, "message": exc.message}},
            args.pretty,
        )
        return 3

    if store is not None:
        if args.command in ("audit", "solve", "inspect") and not payload.get("error"):
            case_hash = store.put_case(document)
            store.put_run(case_hash, args.command, options_key, payload)
        store.close()
    _emit(payload, args.pretty)
    return 0


def _run_replay(
    case, document: Any, store: Store, plan_id: str | None
) -> dict[str, Any]:
    if plan_id is None:
        # Find the most recent plan for this logical case, if any.
        case_hash = digest(document)
        rows = [
            pid
            for pid in store.list_plans()
            if (entry := store.get_plan(pid)) is not None
            and entry[0].get("case_hash") == case_hash
            and entry[0].get("ok")
        ]
        if not rows:
            raise CaseError(
                "E_NO_PLAN",
                "$/plan",
                "no recorded plan for this case; run 'plan --db ...' first",
            )
        plan_id = rows[-1]
    entry = store.get_plan(plan_id)
    if entry is None:
        raise CaseError("E_UNKNOWN_PLAN", "$/plan", f"no recorded plan {plan_id!r}")
    plan_document, steps = entry
    payload = replay_plan(case, plan_document, steps)
    payload["plan_id"] = plan_id
    payload["case_hash"] = digest(document)
    return payload


def _inspect(case, document: Any) -> dict[str, Any]:
    from .deps import Resolver
    from .solver import Solver

    universe = Solver(case).compute_universe()
    reached = (
        sorted(Resolver(case).reachable(case.baseline))
        if case.baseline is not None
        else []
    )
    return {
        "command": "inspect",
        "case_hash": digest(document),
        "ok": True,
        "components": sorted(case.components),
        "roots": {
            rid: {"component": root.component, "region": root.region}
            for rid, root in sorted(case.roots.items())
        },
        "potential_universe": sorted(universe),
        "baseline_reachable": reached,
        "approval_count": len(case.approvals),
        "capabilities": {cap.cid: list(cap.roots) for cap in case.capabilities},
    }


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        return _run(args)
    except SystemExit as exc:  # argparse
        return int(exc.code or 0)
    except BrokenPipeError:  # pragma: no cover
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
