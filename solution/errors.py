"""Structured error types used across the admission and migration tooling.

Every failure that can be blamed on the input document carries a stable error
code and a JSON-Pointer-like location so that callers can find the offending
field mechanically.
"""

from __future__ import annotations

from typing import Any


def join_path(base: str, *segments: Any) -> str:
    """Append raw segments to a ``$``-rooted JSON Pointer path."""

    out = base
    for seg in segments:
        text = str(seg)
        text = text.replace("~", "~0").replace("/", "~1")
        out += "/" + text
    return out


class CaseError(Exception):
    """An input document is structurally or semantically invalid."""

    def __init__(self, code: str, path: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.path = path
        self.message = message

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "path": self.path,
            "message": self.message,
        }


class UsageError(Exception):
    """Bad command line invocation."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.code = "E_USAGE"
        self.path = "$"
        self.message = message

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "path": self.path, "message": self.message}


class SearchLimitError(Exception):
    """The configured search budget was exhausted without a conclusive answer."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.code = "E_SEARCH_LIMIT"
        self.path = "$"
        self.message = message

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "path": self.path, "message": self.message}
