"""Parsed, validated case model for the SBOM admission and migration tooling.

The model is deliberately strict: unknown fields, dangling references and
malformed scalars are rejected with a stable error code and a JSON-Pointer
style location so that a structure mistake can be found mechanically.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import Any, Iterable

from .errors import CaseError, join_path
from .versions import build_ranks


# ---------------------------------------------------------------------------
# value helpers


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _as_obj(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CaseError("E_TYPE", path, "expected a JSON object")
    for key in value:
        if not isinstance(key, str):
            raise CaseError("E_TYPE", path, "object keys must be strings")
    return value


def _as_list(value: Any, path: str) -> list[Any]:
    if not isinstance(value, list):
        raise CaseError("E_TYPE", path, "expected a JSON array")
    return value


def _as_str(value: Any, path: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise CaseError("E_TYPE", path, "expected a JSON string")
    if not allow_empty and value == "":
        raise CaseError("E_VALUE", path, "must not be empty")
    return value


def _as_bool(value: Any, path: str) -> bool:
    if not isinstance(value, bool):
        raise CaseError("E_TYPE", path, "expected true or false")
    return value


def _as_cost(value: Any, path: str) -> int:
    if not _is_int(value):
        raise CaseError("E_TYPE", path, "expected an integer cost")
    if value < 0:
        raise CaseError("E_VALUE", path, "cost must be non-negative")
    return value


_DATE_RE_CACHE: set[str] = set()


def _as_date(value: Any, path: str) -> str:
    text = _as_str(value, path)
    if len(text) != 10 or text[4] != "-" or text[7] != "-":
        raise CaseError("E_DATE", path, "expected an ISO date YYYY-MM-DD")
    try:
        datetime.date.fromisoformat(text)
    except ValueError as exc:
        raise CaseError("E_DATE", path, f"invalid calendar date: {exc}") from exc
    return text


def _check_keys(obj: dict[str, Any], allowed: Iterable[str], path: str) -> None:
    allowed_set = set(allowed)
    for key in obj:
        if key not in allowed_set:
            raise CaseError("E_UNKNOWN_FIELD", join_path(path, key), "unknown field")


def _require(obj: dict[str, Any], key: str, path: str) -> Any:
    if key not in obj:
        raise CaseError("E_MISSING_FIELD", join_path(path, key), "required field is missing")
    return obj[key]


# ---------------------------------------------------------------------------
# model records


@dataclass(frozen=True)
class DepEdge:
    component: str
    min_version: str
    max_version: str
    min_exclusive: bool
    max_exclusive: bool

    def accepts(self, candidate_rank: int, ranks: dict[str, int]) -> bool:
        low = ranks[self.min_version]
        high = ranks[self.max_version]
        if self.min_exclusive:
            if candidate_rank <= low:
                return False
        elif candidate_rank < low:
            return False
        if self.max_exclusive:
            if candidate_rank >= high:
                return False
        elif candidate_rank > high:
            return False
        return True


@dataclass(frozen=True)
class Version:
    label: str
    deps: tuple[DepEdge, ...]
    regions: frozenset[str]
    requires_review: bool
    cost: int
    rank: int


@dataclass(frozen=True)
class Component:
    cid: str
    versions: dict[str, Version]
    removal_cost: int

    def get(self, label: str) -> Version:
        return self.versions[label]


@dataclass(frozen=True)
class Root:
    rid: str
    component: str
    region: str
    halt_cost: int


@dataclass(frozen=True)
class Approval:
    aid: str
    component: str
    version: str
    region: str
    expires: str | None

    def active(self, as_of: str) -> bool:
        return self.expires is None or self.expires >= as_of


@dataclass(frozen=True)
class Edge:
    eid: str
    component: str
    from_version: str | None
    to_version: str | None
    cost: int


@dataclass(frozen=True)
class GroupMove:
    component: str
    from_version: str | None
    to_version: str | None


@dataclass(frozen=True)
class Group:
    gid: str
    moves: tuple[GroupMove, ...]
    cost: int


@dataclass(frozen=True)
class Policy:
    pid: str
    step_from: int
    step_to: int | None
    regions: frozenset[str] | None
    allowed: dict[str, frozenset[str]]

    def applies_to_step(self, step: int) -> bool:
        if step < self.step_from:
            return False
        return self.step_to is None or step <= self.step_to

    def covers_region(self, region: str) -> bool:
        return self.regions is None or region in self.regions


@dataclass(frozen=True)
class Migration:
    edges: tuple[Edge, ...]
    groups: tuple[Group, ...]
    max_steps: int
    pause_limit: int
    policies: tuple[Policy, ...]


@dataclass(frozen=True)
class Capability:
    cid: str
    roots: tuple[str, ...]


@dataclass(frozen=True)
class Limits:
    max_nodes: int = 3_000_000
    max_changes: int | None = None
    max_states: int = 300_000


@dataclass
class Case:
    schema: str | None
    as_of: str
    components: dict[str, Component]
    roots: dict[str, Root]
    approvals: tuple[Approval, ...]
    baseline: dict[str, str] | None
    deployment: dict[str, str] | None
    migration: Migration | None
    capabilities: tuple[Capability, ...]
    limits: Limits
    description: str | None
    rank: dict[str, dict[str, int]] = field(default_factory=dict)

    # -- lookups -----------------------------------------------------------

    def version(self, component: str, label: str) -> Version:
        return self.components[component].versions[label]

    def ranks_for(self, component: str) -> dict[str, int]:
        return self.rank[component]

    def labels(self, component: str) -> list[str]:
        return list(self.components[component].versions)

    def baseline_version(self, component: str) -> str | None:
        if self.baseline is None:
            return None
        return self.baseline.get(component)

    def roots_in_order(self) -> list[Root]:
        return [self.roots[rid] for rid in sorted(self.roots)]


# ---------------------------------------------------------------------------
# parsing


def _parse_dep(raw: Any, path: str) -> DepEdge:
    obj = _as_obj(raw, path)
    _check_keys(
        obj,
        ("component", "min", "max", "min_exclusive", "max_exclusive"),
        path,
    )
    component = _as_str(_require(obj, "component", path), join_path(path, "component"))
    low = _as_str(_require(obj, "min", path), join_path(path, "min"))
    high = _as_str(_require(obj, "max", path), join_path(path, "max"))
    min_ex = _as_bool(obj.get("min_exclusive", False), join_path(path, "min_exclusive"))
    max_ex = _as_bool(obj.get("max_exclusive", False), join_path(path, "max_exclusive"))
    return DepEdge(component, low, high, min_ex, max_ex)


def _parse_version(raw: Any, path: str, label: str) -> Version:
    obj = _as_obj(raw, path)
    _check_keys(obj, ("deps", "regions", "requires_review", "cost", "description"), path)
    deps_raw = _as_list(obj.get("deps", []), join_path(path, "deps"))
    deps = []
    for index, item in enumerate(deps_raw):
        deps.append(_parse_dep(item, join_path(path, "deps", index)))
    regions_raw = _as_list(obj.get("regions", []), join_path(path, "regions"))
    regions = set()
    for index, item in enumerate(regions_raw):
        region = _as_str(item, join_path(path, "regions", index))
        if region in regions:
            raise CaseError(
                "E_DUPLICATE_REGION",
                join_path(path, "regions", index),
                f"region {region!r} is listed twice",
            )
        regions.add(region)
    requires_review = _as_bool(
        obj.get("requires_review", False), join_path(path, "requires_review")
    )
    cost = _as_cost(obj.get("cost", 0), join_path(path, "cost"))
    return Version(
        label=label,
        deps=tuple(deps),
        regions=frozenset(regions),
        requires_review=requires_review,
        cost=cost,
        rank=-1,
    )


def _parse_components(raw: Any) -> dict[str, Component]:
    path = "$/components"
    obj = _as_obj(raw, path)
    components: dict[str, Component] = {}
    for cid in sorted(obj):
        cpath = join_path(path, cid)
        if cid == "":
            raise CaseError("E_VALUE", cpath, "component id must not be empty")
        comp_obj = _as_obj(obj[cid], cpath)
        _check_keys(
            comp_obj, ("versions", "version_order", "removal_cost", "description"), cpath
        )
        removal_cost = _as_cost(
            comp_obj.get("removal_cost", 0), join_path(cpath, "removal_cost")
        )
        versions_raw = _as_obj(_require(comp_obj, "versions", cpath), join_path(cpath, "versions"))
        versions: dict[str, Version] = {}
        for label in sorted(versions_raw):
            if label == "":
                raise CaseError(
                    "E_VALUE", join_path(cpath, "versions", label), "version label must not be empty"
                )
            versions[label] = _parse_version(
                versions_raw[label], join_path(cpath, "versions", label), label
            )
        if not versions:
            raise CaseError(
                "E_EMPTY_VERSIONS", join_path(cpath, "versions"), "component has no published versions"
            )
        explicit = None
        if "version_order" in comp_obj:
            order_raw = _as_list(
                comp_obj["version_order"], join_path(cpath, "version_order")
            )
            explicit = [
                _as_str(item, join_path(cpath, "version_order", index))
                for index, item in enumerate(order_raw)
            ]
        ranks = build_ranks(cid, versions.keys(), explicit, join_path(cpath, "version_order"))
        ranked = {
            label: Version(
                label=v.label,
                deps=v.deps,
                regions=v.regions,
                requires_review=v.requires_review,
                cost=v.cost,
                rank=ranks[label],
            )
            for label, v in versions.items()
        }
        components[cid] = Component(cid=cid, versions=ranked, removal_cost=removal_cost)
    if not components:
        raise CaseError("E_EMPTY_COMPONENTS", path, "case has no components")
    return components


def _parse_roots(raw: Any) -> dict[str, Root]:
    path = "$/roots"
    obj = _as_obj(raw, path)
    roots: dict[str, Root] = {}
    for rid in sorted(obj):
        rpath = join_path(path, rid)
        if rid == "":
            raise CaseError("E_VALUE", rpath, "root id must not be empty")
        robj = _as_obj(obj[rid], rpath)
        _check_keys(robj, ("component", "region", "halt_cost", "description"), rpath)
        component = _as_str(_require(robj, "component", rpath), join_path(rpath, "component"))
        region = _as_str(_require(robj, "region", rpath), join_path(rpath, "region"))
        halt = _as_cost(robj.get("halt_cost", 0), join_path(rpath, "halt_cost"))
        roots[rid] = Root(rid=rid, component=component, region=region, halt_cost=halt)
    if not roots:
        raise CaseError("E_EMPTY_ROOTS", path, "case has no artifact roots")
    return roots


def _parse_approvals(raw: Any) -> tuple[Approval, ...]:
    path = "$/approvals"
    items = _as_list(raw, path)
    approvals = []
    seen: set[str] = set()
    for index, item in enumerate(items):
        apath = join_path(path, index)
        obj = _as_obj(item, apath)
        _check_keys(obj, ("id", "component", "version", "region", "expires", "note"), apath)
        aid = _as_str(_require(obj, "id", apath), join_path(apath, "id"))
        if aid in seen:
            raise CaseError("E_DUPLICATE_ID", join_path(apath, "id"), f"duplicate approval id {aid!r}")
        seen.add(aid)
        component = _as_str(_require(obj, "component", apath), join_path(apath, "component"))
        version = _as_str(_require(obj, "version", apath), join_path(apath, "version"))
        region = _as_str(_require(obj, "region", apath), join_path(apath, "region"))
        expires = None
        if "expires" in obj and obj["expires"] is not None:
            expires = _as_date(obj["expires"], join_path(apath, "expires"))
        approvals.append(Approval(aid, component, version, region, expires))
    return tuple(approvals)


def _parse_assignment(raw: Any, path: str) -> dict[str, str]:
    obj = _as_obj(raw, path)
    assignment: dict[str, str] = {}
    for cid in sorted(obj):
        assignment[cid] = _as_str(obj[cid], join_path(path, cid))
    return assignment


def _parse_migration(raw: Any) -> Migration:
    path = "$/migration"
    obj = _as_obj(raw, path)
    _check_keys(
        obj,
        ("edges", "groups", "max_steps", "pause_limit", "policies", "description"),
        path,
    )
    edges = []
    edge_ids: set[str] = set()
    for index, item in enumerate(_as_list(obj.get("edges", []), join_path(path, "edges"))):
        epath = join_path(path, "edges", index)
        eobj = _as_obj(item, epath)
        _check_keys(eobj, ("id", "component", "from", "to", "cost", "description"), epath)
        eid = _as_str(_require(eobj, "id", epath), join_path(epath, "id"))
        if eid in edge_ids:
            raise CaseError("E_DUPLICATE_ID", join_path(epath, "id"), f"duplicate edge id {eid!r}")
        if eid.startswith("pause:") or eid.startswith("resume:"):
            raise CaseError("E_RESERVED_ID", join_path(epath, "id"), "id uses a reserved prefix")
        edge_ids.add(eid)
        component = _as_str(_require(eobj, "component", epath), join_path(epath, "component"))
        frm = eobj.get("from")
        from_version = None if frm is None else _as_str(frm, join_path(epath, "from"))
        to_raw = eobj.get("to")
        if to_raw is None and "to" in eobj:
            to_version = None
        else:
            to_version = _as_str(_require(eobj, "to", epath), join_path(epath, "to"))
        if from_version is None and to_version is None:
            raise CaseError(
                "E_VALUE",
                epath,
                "a migration edge needs at least one of 'from' or 'to'",
            )
        cost = _as_cost(eobj.get("cost", 0), join_path(epath, "cost"))
        edges.append(Edge(eid, component, from_version, to_version, cost))
    groups = []
    group_ids: set[str] = set()
    for index, item in enumerate(_as_list(obj.get("groups", []), join_path(path, "groups"))):
        gpath = join_path(path, "groups", index)
        gobj = _as_obj(item, gpath)
        _check_keys(gobj, ("id", "moves", "cost", "description"), gpath)
        gid = _as_str(_require(gobj, "id", gpath), join_path(gpath, "id"))
        if gid in group_ids:
            raise CaseError("E_DUPLICATE_ID", join_path(gpath, "id"), f"duplicate group id {gid!r}")
        if gid.startswith("pause:") or gid.startswith("resume:"):
            raise CaseError("E_RESERVED_ID", join_path(gpath, "id"), "id uses a reserved prefix")
        group_ids.add(gid)
        moves = []
        seen_comp: set[str] = set()
        for mindex, mitem in enumerate(_as_list(_require(gobj, "moves", gpath), join_path(gpath, "moves"))):
            mpath = join_path(gpath, "moves", mindex)
            mobj = _as_obj(mitem, mpath)
            _check_keys(mobj, ("component", "from", "to"), mpath)
            component = _as_str(_require(mobj, "component", mpath), join_path(mpath, "component"))
            if component in seen_comp:
                raise CaseError(
                    "E_GROUP_DUPLICATE_COMPONENT",
                    join_path(mpath, "component"),
                    f"component {component!r} appears twice in the same group",
                )
            seen_comp.add(component)
            frm = mobj.get("from")
            from_version = None if frm is None else _as_str(frm, join_path(mpath, "from"))
            to_raw = mobj.get("to")
            if to_raw is None and "to" in mobj:
                to_version = None
            else:
                to_version = _as_str(_require(mobj, "to", mpath), join_path(mpath, "to"))
            if from_version is None and to_version is None:
                raise CaseError(
                    "E_VALUE",
                    mpath,
                    "a group move needs at least one of 'from' or 'to'",
                )
            moves.append(GroupMove(component, from_version, to_version))
        if not moves:
            raise CaseError("E_GROUP_EMPTY", join_path(gpath, "moves"), "group has no moves")
        cost = _as_cost(gobj.get("cost", 0), join_path(gpath, "cost"))
        groups.append(Group(gid, tuple(moves), cost))
    overlap = edge_ids & group_ids
    if overlap:
        raise CaseError(
            "E_DUPLICATE_ID", path, f"ids used by both edges and groups: {sorted(overlap)!r}"
        )
    if "max_steps" not in obj:
        raise CaseError("E_MISSING_FIELD", join_path(path, "max_steps"), "required field is missing")
    max_steps = _as_cost(obj["max_steps"], join_path(path, "max_steps"))
    if max_steps == 0:
        raise CaseError("E_VALUE", join_path(path, "max_steps"), "max_steps must be positive")
    pause_limit = _as_cost(obj.get("pause_limit", 0), join_path(path, "pause_limit"))
    policies = []
    policy_ids: set[str] = set()
    for index, item in enumerate(_as_list(obj.get("policies", []), join_path(path, "policies"))):
        ppath = join_path(path, "policies", index)
        pobj = _as_obj(item, ppath)
        _check_keys(pobj, ("id", "steps", "regions", "allowed", "description"), ppath)
        pid = _as_str(_require(pobj, "id", ppath), join_path(ppath, "id"))
        if pid in policy_ids:
            raise CaseError("E_DUPLICATE_ID", join_path(ppath, "id"), f"duplicate policy id {pid!r}")
        policy_ids.add(pid)
        steps_raw = _as_list(_require(pobj, "steps", ppath), join_path(ppath, "steps"))
        if len(steps_raw) != 2:
            raise CaseError("E_POLICY_STEPS", join_path(ppath, "steps"), "steps must be [first, last]")
        first = _as_cost(steps_raw[0], join_path(ppath, "steps", 0))
        if first < 1:
            raise CaseError("E_VALUE", join_path(ppath, "steps", 0), "step numbers start at 1")
        last = steps_raw[1]
        if last is None:
            step_to = None
        else:
            step_to = _as_cost(last, join_path(ppath, "steps", 1))
            if step_to < first:
                raise CaseError(
                    "E_POLICY_STEPS",
                    join_path(ppath, "steps"),
                    "last step must not be smaller than first step",
                )
        regions = None
        if "regions" in pobj:
            regions = set()
            for rindex, ritem in enumerate(
                _as_list(pobj["regions"], join_path(ppath, "regions"))
            ):
                rpath = join_path(ppath, "regions", rindex)
                regions.add(_as_str(ritem, rpath))
        allowed_raw = _as_obj(pobj.get("allowed", {}), join_path(ppath, "allowed"))
        allowed: dict[str, frozenset[str]] = {}
        for cid in sorted(allowed_raw):
            cpath = join_path(ppath, "allowed", cid)
            labels = set()
            for lindex, litem in enumerate(_as_list(allowed_raw[cid], cpath)):
                labels.add(_as_str(litem, join_path(cpath, lindex)))
            allowed[cid] = frozenset(labels)
        policies.append(Policy(pid, first, step_to, None if regions is None else frozenset(regions), allowed))
    return Migration(tuple(edges), tuple(groups), max_steps, pause_limit, tuple(policies))


def _parse_capabilities(raw: Any) -> tuple[Capability, ...]:
    path = "$/capabilities"
    items = _as_list(raw, path)
    caps = []
    seen: set[str] = set()
    for index, item in enumerate(items):
        cpath = join_path(path, index)
        obj = _as_obj(item, cpath)
        _check_keys(obj, ("id", "roots", "description"), cpath)
        cid = _as_str(_require(obj, "id", cpath), join_path(cpath, "id"))
        if cid in seen:
            raise CaseError("E_DUPLICATE_ID", join_path(cpath, "id"), f"duplicate capability id {cid!r}")
        seen.add(cid)
        root_list = []
        for rindex, ritem in enumerate(_as_list(_require(obj, "roots", cpath), join_path(cpath, "roots"))):
            rpath = join_path(cpath, "roots", rindex)
            rid = _as_str(ritem, rpath)
            if rid in root_list:
                raise CaseError("E_DUPLICATE_REF", rpath, f"root {rid!r} is listed twice")
            root_list.append(rid)
        if not root_list:
            raise CaseError("E_CAPABILITY_EMPTY", join_path(cpath, "roots"), "capability needs at least one root")
        caps.append(Capability(cid, tuple(root_list)))
    return tuple(caps)


def _parse_limits(raw: Any) -> Limits:
    path = "$/limits"
    obj = _as_obj(raw, path)
    _check_keys(obj, ("max_nodes", "max_changes", "max_states"), path)
    max_nodes = obj.get("max_nodes", 3_000_000)
    max_states = obj.get("max_states", 300_000)
    max_changes = obj.get("max_changes", None)
    for name, value in (("max_nodes", max_nodes), ("max_states", max_states)):
        if not _is_int(value) or value <= 0:
            raise CaseError("E_VALUE", join_path(path, name), "must be a positive integer")
    if max_changes is not None:
        if not _is_int(max_changes) or max_changes < 0:
            raise CaseError("E_VALUE", join_path(path, "max_changes"), "must be a non-negative integer")
    return Limits(int(max_nodes), max_changes, int(max_states))


def parse_case(data: Any) -> Case:
    path = "$"
    obj = _as_obj(data, path)
    _check_keys(
        obj,
        (
            "schema",
            "as_of",
            "components",
            "roots",
            "approvals",
            "baseline",
            "deployment",
            "migration",
            "capabilities",
            "limits",
            "description",
            "name",
            "notes",
        ),
        path,
    )
    schema = None
    if "schema" in obj:
        schema = _as_str(obj["schema"], join_path(path, "schema"))
        if schema != "sbmom/v1":
            raise CaseError("E_SCHEMA", join_path(path, "schema"), "expected schema 'sbmom/v1'")
    as_of = _as_date(_require(obj, "as_of", path), join_path(path, "as_of"))
    components = _parse_components(_require(obj, "components", path))
    roots = _parse_roots(_require(obj, "roots", path))
    approvals = _parse_approvals(obj.get("approvals", []))
    baseline = None
    if "baseline" in obj:
        baseline = _parse_assignment(obj["baseline"], join_path(path, "baseline"))
    deployment = None
    if "deployment" in obj:
        deployment = _parse_assignment(obj["deployment"], join_path(path, "deployment"))
    migration = None
    if "migration" in obj:
        migration = _parse_migration(obj["migration"])
    capabilities = _parse_capabilities(obj.get("capabilities", []))
    limits = _parse_limits(obj.get("limits", {}))
    description = None
    if "description" in obj:
        description = _as_str(obj["description"], join_path(path, "description"), allow_empty=True)

    case = Case(
        schema=schema,
        as_of=as_of,
        components=components,
        roots=roots,
        approvals=approvals,
        baseline=baseline,
        deployment=deployment,
        migration=migration,
        capabilities=capabilities,
        limits=limits,
        description=description,
    )
    _validate_references(case)
    case.rank = {
        cid: {label: version.rank for label, version in comp.versions.items()}
        for cid, comp in components.items()
    }
    return case


# ---------------------------------------------------------------------------
# cross-reference validation


def _require_component(case: Case, cid: str, path: str) -> None:
    if cid not in case.components:
        raise CaseError("E_UNKNOWN_COMPONENT", path, f"unknown component {cid!r}")


def _require_version(case: Case, cid: str, label: str, path: str) -> None:
    _require_component(case, cid, path)
    if label not in case.components[cid].versions:
        raise CaseError(
            "E_UNKNOWN_VERSION",
            path,
            f"component {cid!r} has no published version {label!r}",
        )


def _validate_references(case: Case) -> None:
    for cid, comp in case.components.items():
        cpath = f"$/components/{cid}"
        for label, version in comp.versions.items():
            vpath = f"{cpath}/versions/{label}"
            for index, dep in enumerate(version.deps):
                dpath = f"{vpath}/deps/{index}"
                _require_version(case, dep.component, dep.min_version, f"{dpath}/min")
                _require_version(case, dep.component, dep.max_version, f"{dpath}/max")
                target = case.components[dep.component]
                if target.versions[dep.min_version].rank > target.versions[dep.max_version].rank:
                    raise CaseError(
                        "E_RANGE_EMPTY",
                        dpath,
                        "dependency interval is empty (min is newer than max)",
                    )
    for rid, root in case.roots.items():
        _require_component(case, root.component, f"$/roots/{rid}/component")
    for index, approval in enumerate(case.approvals):
        apath = f"$/approvals/{index}"
        _require_version(case, approval.component, approval.version, f"{apath}/version")
    for name, assignment, base in (
        ("baseline", case.baseline, "$/baseline"),
        ("deployment", case.deployment, "$/deployment"),
    ):
        if assignment is None:
            continue
        for cid, label in assignment.items():
            _require_version(case, cid, label, f"{base}/{cid}")
    if case.migration is not None:
        mpath = "$/migration"
        for index, edge in enumerate(case.migration.edges):
            epath = f"{mpath}/edges/{index}"
            _require_component(case, edge.component, f"{epath}/component")
            if edge.from_version is not None:
                _require_version(case, edge.component, edge.from_version, f"{epath}/from")
            if edge.to_version is not None:
                _require_version(case, edge.component, edge.to_version, f"{epath}/to")
        for index, group in enumerate(case.migration.groups):
            gpath = f"{mpath}/groups/{index}"
            for mindex, move in enumerate(group.moves):
                mpath2 = f"{gpath}/moves/{mindex}"
                _require_component(case, move.component, f"{mpath2}/component")
                if move.from_version is not None:
                    _require_version(case, move.component, move.from_version, f"{mpath2}/from")
                if move.to_version is not None:
                    _require_version(case, move.component, move.to_version, f"{mpath2}/to")
        for index, policy in enumerate(case.migration.policies):
            ppath = f"{mpath}/policies/{index}"
            for cid, labels in policy.allowed.items():
                if cid not in case.components:
                    raise CaseError(
                        "E_UNKNOWN_COMPONENT", f"{ppath}/allowed/{cid}", f"unknown component {cid!r}"
                    )
                for lindex, label in enumerate(sorted(labels)):
                    if label not in case.components[cid].versions:
                        raise CaseError(
                            "E_UNKNOWN_VERSION",
                            f"{ppath}/allowed/{cid}",
                            f"component {cid!r} has no published version {label!r}",
                        )
    for index, cap in enumerate(case.capabilities):
        for rindex, rid in enumerate(cap.roots):
            if rid not in case.roots:
                raise CaseError(
                    "E_UNKNOWN_ROOT",
                    f"$/capabilities/{index}/roots/{rindex}",
                    f"unknown root {rid!r}",
                )
