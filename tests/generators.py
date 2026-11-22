"""Synthetic case generators used by the scale tests.

Deterministic functions of their parameters: no randomness and no clock.  They
exercise the documented limits — 35 components with 4 published versions for
``solve`` and 16 components with 3 versions for ``plan`` — without committing
large JSON blobs.
"""

from __future__ import annotations

from typing import Any


def solve_scale_case(components: int = 35, versions: int = 4) -> dict[str, Any]:
    """35 components x 4 versions with root pinning, cycles and review gates.

    Structure:

    * two roots, each pinning three middle components to a fixed version, so the
      baseline is illegal and the solver must choose;
    * the 27 leaves are dealt round-robin across the six middles, so every leaf
      is reachable from some root;
    * each middle's leaves form a mutual-equality cycle, so every member of a
      group must share one version — the "whole cycle satisfies at once" rule at
      scale;
    * one middle version per group requires independent review, with approvals
      present in every region.

    Each leaf group has four legal versions, so the naive cross product over the
    six groups is 4**6 = 4096; propagation explores roughly a hundredth of that.
    """

    labels = [f"{major}.0.0" for major in range(1, versions + 1)]
    regions = ["eu", "us", "apac"]
    ids = [f"c{index:02d}" for index in range(components)]
    roots = ids[0:2]
    middles = ids[2:8]
    leaves = ids[8:]

    # Distribute leaves evenly across the middles so every leaf is reachable.
    groups: list[list[str]] = [[] for _ in middles]
    for position, leaf in enumerate(leaves):
        groups[position % len(middles)].append(leaf)

    def leaf_group(index: int) -> list[str]:
        position = leaves.index(index)
        return groups[position % len(middles)]

    doc_components: dict[str, Any] = {}

    for index, cid in enumerate(ids):
        variants: dict[str, Any] = {}
        for label in labels:
            if cid in middles:
                group = middles.index(cid)
                targets = groups[group]
                deps = [
                    {"component": target, "min": labels[0], "max": labels[-1]}
                    for target in targets
                ]
            elif cid in leaves:
                group = leaf_group(cid)
                position = group.index(cid)
                successor = group[(position + 1) % len(group)]
                # Mutual equality inside the group: every member must match.
                deps = [{"component": successor, "min": label, "max": label}]
            else:
                deps = []
            variants[label] = {
                "regions": list(regions),
                "deps": deps,
                "cost": (index * 3 + int(label.split(".")[0])) % 5 + 1,
            }
        if cid in middles and middles.index(cid) % 2 == 0:
            variants[labels[-1]]["requires_review"] = True
        doc_components[cid] = {
            "version_order": list(labels),
            "versions": variants,
            "removal_cost": 2,
        }

    # Roots pin their middles so the baseline is illegal and choices matter.
    for root_index, cid in enumerate(roots):
        targets = middles[root_index * 3 : root_index * 3 + 3]
        pinned = labels[2] if root_index == 0 else labels[1]
        doc_components[cid]["versions"] = {
            label: {
                "regions": list(regions),
                "deps": [
                    {
                        "component": target,
                        "min": pinned,
                        "max": pinned,
                    }
                    for target in targets
                ],
                "cost": 1,
            }
            for label in labels
        }

    approvals = []
    for index, cid in enumerate(middles):
        if index % 2 == 0:
            for region in regions:
                approvals.append(
                    {
                        "id": f"ap-{cid}-{region}",
                        "component": cid,
                        "version": labels[-1],
                        "region": region,
                        "expires": "2030-01-01",
                    }
                )

    baseline = {cid: labels[0] for cid in ids}
    return {
        "schema": "sbmom/v1",
        "description": (
            f"synthetic {components} component solve case: pinned middle layer, "
            "leaf cycles, review-gated versions"
        ),
        "as_of": "2026-04-01",
        "components": doc_components,
        "roots": {
            "svc-a": {"component": roots[0], "region": "eu"},
            "svc-b": {"component": roots[1], "region": "us"},
        },
        "approvals": approvals,
        "baseline": baseline,
        "deployment": dict(baseline),
    }


def plan_scale_case(components: int = 16, versions: int = 3) -> dict[str, Any]:
    """16 components x 3 versions with a pause-gated, fully ordered upgrade.

    Shape:

    * ``p00..p13`` form seven mutually pinned pairs (each pair's members depend
      on each other at exactly the same version, so no single member may move
      alone); each pair is moved by a registered atomic group.
    * ``gate`` is the ``us`` root's component.  Its 1.0.0 is not approved in
      ``us``, so the baseline is illegal; its 2.0.0 requires every other
      component at exactly 2.0.0.
    * ``aux`` is an ordinary component that ``gate`` 2.0.0 also requires.

    Because ``gate`` 1.0.0 is illegal while ``us`` runs, every intermediate
    state is illegal until ``us`` is paused.  Pausing is admissible only
    because the critical capability "svc" is also carried by the ``eu`` root,
    and ``pause_limit`` is 1.  The only feasible plan is therefore: pause
    ``us``, move seven pairs plus ``aux``, move ``gate``, resume ``us``.
    """

    if components != 16:
        raise ValueError("plan_scale_case is defined for exactly 16 components")
    labels = [f"{major}.0.0" for major in range(1, versions + 1)]
    pair_count = 7
    pair_ids = [f"p{index:02d}" for index in range(pair_count * 2)]
    gate = "gate"
    aux = "aux"
    ids = pair_ids + [gate, aux]

    doc_components: dict[str, Any] = {}

    for index, cid in enumerate(pair_ids):
        partner = pair_ids[index ^ 1]
        # Chain pairs together so every component is root-reachable through the
        # previous pair's second member.
        successor = (
            pair_ids[index + 2]
            if index % 2 == 1 and index + 2 < len(pair_ids)
            else None
        )
        variants: dict[str, Any] = {}
        for label in labels:
            deps = [{"component": partner, "min": label, "max": label}]
            if successor is not None:
                deps.append(
                    {
                        "component": successor,
                        "min": labels[0],
                        "max": labels[-1],
                    }
                )
            variants[label] = {
                "regions": ["eu", "us"],
                "deps": deps,
                "cost": 1,
            }
        doc_components[cid] = {
            "version_order": list(labels),
            "versions": variants,
            "removal_cost": 1,
        }

    aux_variants = {}
    for label in labels:
        aux_variants[label] = {"regions": ["eu", "us"], "cost": 1}
    doc_components[aux] = {
        "version_order": list(labels),
        "versions": aux_variants,
        "removal_cost": 1,
    }

    gate_variants = {}
    for label in labels:
        if label == labels[0]:
            gate_variants[label] = {"regions": ["eu"], "cost": 1}
        else:
            gate_variants[label] = {
                "regions": ["eu", "us"],
                "deps": [
                    {"component": cid, "min": labels[1], "max": labels[1]}
                    for cid in pair_ids[::2]
                ],
                "cost": 1,
            }
    doc_components[gate] = {
        "version_order": list(labels),
        "versions": gate_variants,
        "removal_cost": 1,
    }

    edges = []
    for cid in ids:
        for source, target in zip(labels, labels[1:]):
            edges.append(
                {
                    "id": f"{cid}-{source}-{target}",
                    "component": cid,
                    "from": source,
                    "to": target,
                    "cost": 1,
                }
            )
            edges.append(
                {
                    "id": f"{cid}-{target}-{source}",
                    "component": cid,
                    "from": target,
                    "to": source,
                    "cost": 1,
                }
            )

    groups = []
    for pair in range(pair_count):
        moves = [
            {"component": pair_ids[pair * 2], "from": labels[0], "to": labels[1]},
            {"component": pair_ids[pair * 2 + 1], "from": labels[0], "to": labels[1]},
        ]
        groups.append({"id": f"batch-{pair:02d}", "moves": moves, "cost": 2})

    baseline = {cid: labels[0] for cid in ids}
    return {
        "schema": "sbmom/v1",
        "description": (
            f"synthetic {components}x{versions} plan case: pause-gated ordered "
            "upgrade with mutually pinned pairs"
        ),
        "as_of": "2026-04-01",
        "components": doc_components,
        "roots": {
            "eu": {"component": pair_ids[0], "region": "eu", "halt_cost": 4},
            "us": {"component": gate, "region": "us", "halt_cost": 6},
        },
        "capabilities": [{"id": "svc", "roots": ["eu", "us"]}],
        "baseline": baseline,
        "deployment": dict(baseline),
        "migration": {
            "max_steps": 2 * components,
            "pause_limit": 1,
            "edges": edges,
            "groups": groups,
            "policies": [],
        },
    }
