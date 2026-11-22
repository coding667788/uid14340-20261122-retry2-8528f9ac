"""Version ordering.

The toolchain never assumes a particular versioning scheme inside the case
data.  If a case supplies ``version_order`` for a component, that list is
authoritative.  Otherwise versions are ordered by a natural key that splits a
label into digit and word runs, comparing numeric runs numerically and word
runs case-insensitively.  Two distinct labels that collapse to the same
natural key are rejected as ambiguous instead of being silently ordered.
"""

from __future__ import annotations

import re
from typing import Iterable

from .errors import CaseError

_TOKEN = re.compile(r"\d+|[A-Za-z]+")


def natural_key(text: str) -> tuple[tuple[int, object], ...]:
    parts = []
    for token in _TOKEN.findall(text):
        if token.isdigit():
            parts.append((0, int(token)))
        else:
            parts.append((1, token.lower()))
    return tuple(parts)


def build_ranks(
    component: str,
    versions: Iterable[str],
    explicit: list[str] | None,
    path: str,
) -> dict[str, int]:
    """Return a total rank for every version label mentioned for a component."""

    labels = sorted(set(versions))
    if explicit is not None:
        seen = set()
        for index, label in enumerate(explicit):
            if not isinstance(label, str) or not label:
                raise CaseError(
                    "E_VERSION_ORDER", path, "version_order entries must be non-empty strings"
                )
            if label in seen:
                raise CaseError(
                    "E_VERSION_ORDER_DUPLICATE",
                    path,
                    f"version {label!r} appears twice in version_order",
                )
            seen.add(label)
        missing = [label for label in labels if label not in seen]
        if missing:
            raise CaseError(
                "E_VERSION_ORDER_INCOMPLETE",
                path,
                f"version_order for component {component!r} is missing {missing!r}",
            )
        return {label: index for index, label in enumerate(explicit)}

    keyed = sorted(labels, key=lambda label: (natural_key(label), label))
    for left, right in zip(keyed, keyed[1:]):
        if natural_key(left) == natural_key(right):
            raise CaseError(
                "E_VERSION_AMBIGUOUS",
                path,
                f"versions {left!r} and {right!r} of component {component!r} "
                "have the same natural order; supply version_order",
            )
    return {label: index for index, label in enumerate(keyed)}
