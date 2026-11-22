"""Property-based cross-checks with a fixed, self-contained pseudo-random stream.

The generator below is a tiny linear congruential generator with a hard-coded
seed, so every run explores exactly the same cases: there is no dependence on
the clock, the OS or ``random``'s global state.  Each generated instance is small
enough for the brute-force oracle, and the solver's answer is compared against
it field by field.
"""

from __future__ import annotations

import unittest

from tests.support import case_from
from tests.test_solve import brute_force
from solution.deps import Resolver
from solution.solver import solve_case


class Lcg:
    def __init__(self, seed: int) -> None:
        self.state = seed & 0xFFFFFFFF

    def next(self) -> int:
        self.state = (self.state * 1103515245 + 12345) & 0x7FFFFFFF
        return self.state

    def below(self, bound: int) -> int:
        if bound <= 0:
            raise ValueError("bound must be positive")
        return self.next() % bound

    def choice(self, items):
        return items[self.below(len(items))]

    def chance(self, numerator: int, denominator: int) -> bool:
        return self.below(denominator) < numerator


REGION_POOL = ["eu", "us"]
VERSION_POOL = ["1.0.0", "1.5.0", "2.0.0"]


def random_case(rng: Lcg, component_count: int) -> dict:
    ids = [f"n{index}" for index in range(component_count)]
    # A random DAG by construction: edges only point from lower to higher index.
    edges: dict[str, list[str]] = {cid: [] for cid in ids}
    for index, cid in enumerate(ids):
        for other in ids[index + 1 :]:
            if rng.chance(2, 5):
                edges[cid].append(other)

    components: dict[str, dict] = {}
    for cid in ids:
        versions: dict[str, dict] = {}
        source_versions = VERSION_POOL[: rng.below(len(VERSION_POOL)) + 1]
        for label in source_versions:
            regions = [r for r in REGION_POOL if rng.chance(1, 2)] or ["eu"]
            deps = []
            for target in edges[cid]:
                allowed = VERSION_POOL[: rng.below(3) + 1]
                deps.append(
                    {
                        "component": target,
                        "min": allowed[0],
                        "max": allowed[-1],
                    }
                )
            requires_review = rng.chance(1, 5)
            versions[label] = {
                "regions": regions,
                "deps": deps,
                "requires_review": requires_review,
                "cost": rng.below(5),
            }
        components[cid] = {
            "version_order": list(source_versions),
            "versions": versions,
            "removal_cost": rng.below(4),
        }

    # Reference version pool per component must include interval endpoints; the
    # generator above keeps min/max inside VERSION_POOL, so ensure every
    # component publishes the full pool used by any inbound edge.
    for cid in ids:
        published = set(components[cid]["versions"])
        for other in ids:
            for label, payload in components[other]["versions"].items():
                for dep in payload.get("deps", []):
                    if dep["component"] != cid:
                        continue
                    for endpoint in (dep["min"], dep["max"]):
                        if endpoint not in published:
                            components[cid]["versions"][endpoint] = {
                                "regions": ["eu"],
                                "deps": [],
                                "requires_review": False,
                                "cost": rng.below(5),
                            }
                            published.add(endpoint)
        components[cid]["version_order"] = sorted(
            components[cid]["versions"], key=lambda label: tuple(int(p) for p in label.split("."))
        )
        # Drop fields that carry no information to keep the oracle fast.
        for payload in components[cid]["versions"].values():
            if not payload["deps"]:
                payload.pop("deps", None)

    root_count = 1 + rng.below(min(2, component_count))
    roots = {}
    for index in range(root_count):
        rid = f"r{index}"
        roots[rid] = {
            "component": ids[rng.below(component_count)],
            "region": rng.choice(REGION_POOL),
        }

    approvals = []
    for cid in ids:
        for label, payload in components[cid]["versions"].items():
            if not payload.get("requires_review"):
                continue
            for region in REGION_POOL:
                if rng.chance(3, 4):
                    approvals.append(
                        {
                            "id": f"ap-{cid}-{label}-{region}",
                            "component": cid,
                            "version": label,
                            "region": region,
                            "expires": rng.choice(["2026-06-01", "2030-01-01"]),
                        }
                    )

    baseline = {}
    for cid in ids:
        if rng.chance(3, 4):
            baseline[cid] = rng.choice(list(components[cid]["versions"]))

    return {
        "schema": "sbmom/v1",
        "as_of": "2026-01-01",
        "components": components,
        "roots": roots,
        "approvals": approvals,
        "baseline": baseline,
        "deployment": dict(baseline),
        "limits": {"max_nodes": 2_000_000},
    }


class RandomizedSolverOracle(unittest.TestCase):
    def test_two_hundred_random_cases_match_brute_force(self) -> None:
        rng = Lcg(20261122)
        compared = 0
        infeasible = 0
        for trial in range(200):
            component_count = 2 + rng.below(3)  # 2..4 components
            doc = random_case(rng, component_count)
            try:
                case = case_from(doc)
            except Exception as exc:  # noqa: BLE001
                self.fail(f"trial {trial}: generated case failed validation: {exc}")
            expected = brute_force(case)
            actual = solve_case(case)
            if expected is None:
                infeasible += 1
                self.assertIsNone(
                    actual, f"trial {trial}: solver found a solution the oracle did not"
                )
                continue
            self.assertIsNotNone(actual, f"trial {trial}: solver missed a legal deployment")
            self.assertEqual(
                actual.changed, expected["changed"], f"trial {trial}: change count"
            )
            self.assertEqual(
                actual.total_cost, expected["cost"], f"trial {trial}: total cost"
            )
            self.assertEqual(
                actual.deployment, expected["deployment"], f"trial {trial}: deployment"
            )
            self.assertEqual(
                Resolver(case).audit(actual.deployment),
                [],
                f"trial {trial}: returned deployment is not legal",
            )
            compared += 1
        self.assertGreater(compared, 20, "too few feasible random cases to be meaningful")
        self.assertGreater(infeasible, 0, "generator never produced an infeasible case")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
