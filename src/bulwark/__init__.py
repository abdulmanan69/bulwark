"""Bulwark: agent security posture management.

Inventories what AI agents can reach -- MCP servers, tool descriptions, hooks,
permission rules, instruction files -- and reports what is exploitable about it.
"""

from .version import __version__

__all__ = ["Engine", "Policy", "Severity", "__version__", "scan"]


def __getattr__(name):
    # Lazy re-exports: importing the package should not pull in the whole rule
    # engine, so `python -c "import bulwark"` stays fast for tooling that only
    # wants the version.
    if name in {"scan", "Engine"}:
        from . import engine

        return getattr(engine, name)
    if name == "Policy":
        from .policy import Policy

        return Policy
    if name == "Severity":
        from .core.models import Severity

        return Severity
    raise AttributeError("module 'bulwark' has no attribute %r" % name)
