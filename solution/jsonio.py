"""Deterministic JSON input/output helpers.

All result documents are serialised with sorted object keys, no ASCII
escaping and no insignificant whitespace, so that the same logical case
always produces byte-identical stdout.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .errors import CaseError


def canonical_text(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_text(value).encode("utf-8")).hexdigest()


def _reject_constant(name: str) -> Any:
    raise CaseError("E_JSON", "$", f"non-finite number literal {name!r} is not allowed")


def load_case(path: str) -> Any:
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError as exc:
        raise CaseError("E_IO", "$", f"cannot read case file: {exc}") from exc
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise CaseError("E_JSON", "$", f"case file is not valid UTF-8: {exc}") from exc
    try:
        return json.loads(text, parse_constant=_reject_constant)
    except json.JSONDecodeError as exc:
        raise CaseError(
            "E_JSON",
            "$",
            f"invalid JSON at line {exc.lineno} column {exc.colno}: {exc.msg}",
        ) from exc


def emit(value: Any) -> str:
    """Render a result document for stdout (one trailing newline)."""

    return canonical_text(value) + "\n"
