"""The scan pipeline.

Six stages, in order, each replaceable in isolation:

1. **discover**  -- turn files on disk into artifacts
2. **enrich**    -- optionally connect to live servers and add their real tools
3. **pin**       -- load the lockfile and compute what moved
4. **detect**    -- run the selected rules over the artifact graph
5. **police**    -- apply policy: waivers, severity overrides, baselines
6. **finish**    -- dedupe, sort, score

Keeping these separate is what makes the tool testable: every stage takes
data and returns data, and no stage reaches back into the one before it.
"""

from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional, Sequence

from .core.models import Artifact, ScanError, ScanResult
from .core.rulebase import ScanContext
from .discovery import discover
from .lockfile import Lockfile, default_path
from .policy import Policy

# Importing the rules package is what populates the registry: every rule
# module registers itself on import, so this import is load-bearing, not
# cosmetic.
from .rules import REGISTRY, load_plugins, run_rules
from .version import __version__


class Engine:
    """Runs a scan end to end."""

    def __init__(self, policy: Optional[Policy] = None) -> None:
        self.policy = policy or Policy()
        if self.policy.plugin_paths:
            load_plugins(self.policy.plugin_paths)

    # ---- public API ------------------------------------------------------

    def scan(
        self,
        roots: Sequence[str],
        *,
        home: Optional[str] = None,
        include_user_scope: bool = True,
        online: bool = False,
        lock_path: Optional[str] = None,
        rule_ids: Optional[Sequence[str]] = None,
        categories: Optional[Sequence[str]] = None,
        online_timeout: float = 20.0,
    ) -> ScanResult:
        started = time.time()
        normalised = [os.path.abspath(r) for r in roots if r] or [os.path.abspath(".")]

        result = ScanResult(
            started_at=started, targets=normalised, tool_version=__version__
        )

        # --- 1. discover --------------------------------------------------
        collected = discover(
            normalised, home=home, include_user_scope=include_user_scope
        )
        result.artifacts = list(collected.artifacts)
        result.errors.extend(collected.errors)
        result.metadata["files_scanned"] = len(collected.files_seen)
        result.metadata["files"] = collected.files_seen

        # --- 2. enrich ----------------------------------------------------
        if online:
            result.artifacts.extend(self._introspect(result, timeout=online_timeout))

        # --- 3. pin -------------------------------------------------------
        lock = self._load_lock(normalised, lock_path)
        changes = lock.diff(result.artifacts) if lock else []

        # --- 4. detect ----------------------------------------------------
        ctx = ScanContext(
            artifacts=result.artifacts,
            root=normalised[0],
            settings=self.policy.rule_settings(),
            lock=lock.entries if lock else {},
            online=online,
        )
        ctx.shared["lock_changes"] = changes
        ctx.shared["lockfile"] = lock

        rules = REGISTRY.select(
            enabled=list(rule_ids or self.policy.enabled_rules) or None,
            disabled=list(self.policy.disabled_rules) or None,
            categories=categories,
            online=online,
        )
        result.metadata["rules_run"] = len(rules)
        result.metadata["rules_available"] = len(REGISTRY)

        result.findings = run_rules(rules, ctx)
        result.errors.extend(ctx.errors)

        # --- 5. police ----------------------------------------------------
        result.findings = self.policy.apply(result.findings)

        # --- 6. finish ----------------------------------------------------
        result.dedupe()
        result.sort()
        result.metadata["lockfile"] = {
            "present": lock is not None,
            "path": lock_path or default_path(normalised[0]),
            "entries": len(lock.entries) if lock else 0,
            "changes": [c.to_dict() for c in changes],
        }
        result.finished_at = time.time()
        return result

    # ---- stages ----------------------------------------------------------

    def _load_lock(
        self, roots: Sequence[str], lock_path: Optional[str]
    ) -> Optional[Lockfile]:
        candidates: List[str] = (
            [lock_path] if lock_path else [default_path(root) for root in roots]
        )
        for candidate in candidates:
            if candidate and os.path.isfile(candidate):
                lock = Lockfile.load(candidate)
                if lock is not None:
                    return lock
        return None

    def _introspect(self, result: ScanResult, *, timeout: float) -> List[Artifact]:
        """Connect to each stdio server and record the tools it really offers.

        Static configuration rarely lists tools; the live handshake is the only
        way to see the descriptions that actually reach the model.  This is
        opt-in because it starts third-party processes -- which, given what
        these rules are looking for, is not something to do by default.
        """
        from .mcp.client import introspect_servers

        try:
            extra, errors = introspect_servers(result.artifacts, timeout=timeout)
        except Exception as exc:
            result.errors.append(
                ScanError(
                    where="introspection",
                    message="%s: %s" % (type(exc).__name__, exc),
                    kind="introspection_error",
                )
            )
            return []
        result.errors.extend(errors)
        return extra


def scan(
    roots: Sequence[str], *, policy: Optional[Policy] = None, **kwargs: Any
) -> ScanResult:
    """Convenience wrapper: one call, one result."""
    return Engine(policy).scan(roots, **kwargs)


def pin(
    roots: Sequence[str],
    *,
    lock_path: Optional[str] = None,
    note: str = "",
    policy: Optional[Policy] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Record the current model-visible state as approved.

    Returns a summary rather than the lockfile so the caller can report what
    was pinned without re-reading the file.
    """
    result = Engine(policy).scan(roots, **kwargs)
    target = lock_path or default_path(os.path.abspath(roots[0] if roots else "."))
    previous = Lockfile.load(target) if os.path.isfile(target) else None

    lock = Lockfile.from_artifacts(
        result.artifacts, tool_version=__version__, note=note, previous=previous
    )
    changes = previous.diff(result.artifacts) if previous else []
    lock.save(target)

    return {
        "path": target,
        "entries": len(lock.entries),
        "previous_entries": len(previous.entries) if previous else 0,
        "changes": [c.to_dict() for c in changes],
        "result": result,
    }
