"""Charter-bound executive project orchestration.

The package surface is lazy so importing the small Founder capability contract
inside KeeperAuthority does not also import the desktop persistence stack.
"""

from typing import Any


__all__ = ["AuthorityEvaluator", "ExecutiveRepository"]


def __getattr__(name: str) -> Any:
    value: Any
    if name == "AuthorityEvaluator":
        from keeper.executive.authority import AuthorityEvaluator

        value = AuthorityEvaluator
    elif name == "ExecutiveRepository":
        from keeper.executive.repository import ExecutiveRepository

        value = ExecutiveRepository
    else:
        raise AttributeError(name)
    globals()[name] = value
    return value
