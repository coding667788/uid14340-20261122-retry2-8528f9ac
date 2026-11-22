"""SBOM component admission auditing, deployment solving and migration planning.

Run as ``python -m solution <command> CASE.json``.
"""

from __future__ import annotations

__all__ = ["main", "__version__"]

__version__ = "1.0.0"


def main(argv=None) -> int:
    from .cli import main as _main

    return _main(argv)
