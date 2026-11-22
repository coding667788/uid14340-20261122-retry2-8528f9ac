"""Command implementations and result documents.

Every command reads one case document, does its work and returns a plain
``dict`` that is serialised deterministically by ``jsonio.emit``.  Errors are
raised as ``CaseError`` (located structural problems) or ``UsageError``.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from .deps import Resolver, Violation
from .errors import CaseError, UsageError
from .jsonio import digest
from .model import Case
from .planner import Plan, Planner
from .solver import solve_case


TOOL_VERSION = "1.0.0"


# ---------------------------------------------------------------------------
# helpers


def _assignment_for(case: Case, which: str) -> dict[str, str]:
    if which == "deployment":
        if case.deployment is None:
            raise CaseError(
                "E_NO_DEPLOYMENT",
                "$/deployment",
                "audit needs a deployment; supply a 'deployment' object",
            )
        return dict(case.deployment)
    raise UsageError(f"unknown assignment {which!r}")


def _violation_list(violations: Sequence[Violation]) -> list[dict[str, Any]]:
    return [violation.to_dict() for violation in violations]


def _solution_document(case: Case, solution) -> dict[str, Any]:
    if solution is None:
        return {
            "ok": False,
            "reason": "no legal deployment exists",
            "deployment": {},
            "changed": 0,
            "version_cost": 0,
            "removal_cost": 0,
            "total_cost": 0,
            "changes": [],
        }
    return {
        "ok": True,
        "deployment": solution.deployment,
        "changed": solution.changed,
        "version_cost": solution.version_cost,
        "removal_cost": solution.removal_cost,
        "total_cost": solution.total_cost,
        "changes": list(solution.changes),
    }


# ---------------------------------------------------------------------------
# audit


def run_audit(case: Case, document: Any) -> dict[str, Any]:
    assignment = _assignment_for(case, "deployment")
    resolver = Resolver(case)
    violations = resolver.audit(assignment)
    reached = resolver.reachable(assignment)
    baseline_reach = (
        set(resolver.reachable(case.baseline)) if case.baseline is not None else set()
    )
    changed, cost, changes = resolver.deployment_changes(assignment, case.baseline)
    return {
        "command": "audit",
        "ok": not violations,
        "deployment": {cid: assignment[cid] for cid in sorted(reached)},
        "reachable": {cid: list(rids) for cid, rids in sorted(reached.items())},
        "violations": _violation_list(violations),
        "changed": changed,
        "change_cost": cost,
        "changes": changes,
        "baseline_reachable": sorted(baseline_reach),
        "case_hash": digest(document),
    }


# ---------------------------------------------------------------------------
# solve


def run_solve(case: Case, document: Any) -> dict[str, Any]:
    solution = solve_case(case)
    payload = {
        "command": "solve",
        "case_hash": digest(document),
    }
    payload.update(_solution_document(case, solution))
    return payload


# ---------------------------------------------------------------------------
# plan


def _plan_document(case: Case, plan: Plan, document: Any) -> dict[str, Any]:
    return {
        "command": "plan",
        "case_hash": digest(document),
        "ok": plan.ok,
        "pinned_target": plan.pinned_target,
        "reason": plan.reason,
        "initial_deployment": plan.initial_deployment,
        "final_deployment": plan.final_deployment,
        "changed": plan.changed,
        "changes": plan.changes,
        "total_cost": plan.total_cost,
        "migration_cost": plan.migration_cost,
        "outage_cost": plan.outage_cost,
        "steps": [step.to_dict() for step in plan.steps],
        "ops": plan.ops,
        "step_count": len(plan.steps),
        "explored_states": plan.explored_states,
    }


def _validate_target(case: Case, target: Mapping[str, str]) -> None:
    """Reject a pinned target that names unknown components or versions."""

    for cid in sorted(target):
        if cid not in case.components:
            raise CaseError(
                "E_UNKNOWN_COMPONENT",
                f"$/target/{cid}",
                f"target names unknown component {cid!r}",
            )
        label = target[cid]
        if label not in case.components[cid].versions:
            raise CaseError(
                "E_UNKNOWN_VERSION",
                f"$/target/{cid}",
                f"target names version {label!r}, which {cid!r} does not publish",
            )


def run_plan(
    case: Case,
    document: Any,
    target: Mapping[str, str] | None = None,
) -> tuple[dict[str, Any], Plan | None]:
    """Plan a safe replacement path and jointly choose the final deployment.

    The objective is the plan objective from the specification: minimise
    (components changed relative to the baseline, total migration + outage
    cost, step count, operation-id sequence).  The endpoint is therefore chosen
    by the planner itself; ``--target`` pins it, which is what replay and the
    ``unreachable_target`` scenario use.
    """

    if target is not None:
        _validate_target(case, target)
    planner = Planner(case, target)
    plan = planner.plan()
    payload = _plan_document(case, plan, document)
    payload["target_deployment"] = (
        dict(target) if target is not None else dict(plan.final_deployment)
    )
    payload["target_source"] = "explicit" if target is not None else "planner"
    if target is not None and not plan.ok:
        payload["target_reachable"] = False
        fallback = Planner(case).plan()
        payload["reachable_legal_endpoint"] = (
            dict(fallback.final_deployment) if fallback.ok else None
        )
    return payload, plan


# ---------------------------------------------------------------------------
# replay


def replay_plan(
    case: Case, plan_document: Mapping[str, Any], steps: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    """Re-execute a recorded plan from the baseline, step by step.

    Replay is deliberately independent of the planner: it re-derives every
    intermediate state from the operation ids and re-checks legality, so a
    recorded plan can be verified without trusting the search that found it.
    """

    migration = case.migration
    if migration is None:
        raise CaseError("E_NO_MIGRATION", "$/migration", "case has no migration block")
    if case.baseline is None:
        raise CaseError("E_NO_BASELINE", "$/baseline", "replay requires a baseline deployment")
    resolver = Resolver(case)
    edges = {edge.eid: edge for edge in migration.edges}
    groups = {group.gid: group for group in migration.groups}

    assignment = dict(case.baseline)
    paused: list[str] = []
    failures: list[dict[str, Any]] = []
    reached_states: list[dict[str, Any]] = [
        {
            "step": 0,
            "deployment": {cid: assignment[cid] for cid in sorted(resolver.reachable(assignment))},
            "paused": [],
            "legal": True,
        }
    ]

    for index, record in enumerate(steps, start=1):
        op = str(record.get("op"))
        step_failures: list[str] = []
        if op.startswith("pause:") or op.startswith("resume:"):
            kind, _, rid = op.partition(":")
            if rid not in case.roots:
                step_failures.append(f"unknown root {rid!r}")
            elif kind == "pause" and rid in paused:
                step_failures.append(f"root {rid!r} is already paused")
            elif kind == "resume" and rid not in paused:
                step_failures.append(f"root {rid!r} is not paused")
            else:
                if kind == "pause":
                    paused.append(rid)
                else:
                    paused.remove(rid)
        elif op in edges:
            edge = edges[op]
            current = assignment.get(edge.component)
            if current != edge.from_version:
                step_failures.append(
                    f"edge {op!r} expects {edge.component}@{edge.from_version}, found {current!r}"
                )
                assignment = dict(assignment)
            else:
                assignment = dict(assignment)
                if edge.to_version is None:
                    assignment.pop(edge.component, None)
                else:
                    assignment[edge.component] = edge.to_version
        elif op in groups:
            group = groups[op]
            new_assignment = dict(assignment)
            for move in group.moves:
                current = assignment.get(move.component)
                if current != move.from_version:
                    step_failures.append(
                        f"group {op!r} expects {move.component}@{move.from_version}, found {current!r}"
                    )
            if not step_failures:
                for move in group.moves:
                    if move.to_version is None:
                        new_assignment.pop(move.component, None)
                    else:
                        new_assignment[move.component] = move.to_version
                assignment = new_assignment
        else:
            step_failures.append(f"unknown operation {op!r}")

        violation = None
        if not step_failures:
            violation = resolver.step_violation(assignment, sorted(paused), index)
            if violation is not None:
                step_failures.append(
                    f"{violation.kind}: {violation.detail} (witness {' -> '.join(violation.path)})"
                )
            for capability in case.capabilities:
                if not any(rid not in paused for rid in capability.roots):
                    step_failures.append(
                        f"capability {capability.cid!r} has no running root"
                    )
            if len(paused) > migration.pause_limit:
                step_failures.append(
                    f"{len(paused)} artifacts paused exceeds limit {migration.pause_limit}"
                )

        reached_states.append(
            {
                "step": index,
                "op": op,
                "deployment": {
                    cid: assignment[cid] for cid in sorted(resolver.reachable(assignment))
                },
                "paused": sorted(paused),
                "legal": not step_failures,
                "violations": step_failures,
            }
        )
        if step_failures:
            failures.append({"step": index, "op": op, "violations": step_failures})
            break

    expected = plan_document.get("ops")
    replay_ops = [str(record.get("op")) for record in steps]
    matches = expected is None or list(expected) == replay_ops
    final = {cid: assignment[cid] for cid in sorted(resolver.reachable(assignment))}
    final_audit = [v.to_dict() for v in resolver.audit(assignment)] if not paused else []
    ok = not failures and matches and not paused and not final_audit
    return {
        "command": "replay",
        "ok": ok,
        "steps": len(steps),
        "matches_recorded_ops": matches,
        "failures": failures,
        "final_deployment": final,
        "final_audit": final_audit,
        "reached": reached_states,
    }
