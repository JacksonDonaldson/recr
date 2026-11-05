"""Verification entry point referenced by plan.txt.

The implementation lives in the top-level :mod:`verify` module so the same
checks can be invoked from the CLI and from tests.
"""

from verify import (  # noqa: F401
    check_end_to_end,
    check_per_function,
    check_round_trip,
    check_static,
    run,
)

__all__ = [
    "check_end_to_end",
    "check_per_function",
    "check_round_trip",
    "check_static",
    "run",
]
