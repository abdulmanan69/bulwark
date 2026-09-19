"""Discovery entry point.

One call, :func:`discover`, runs every collector and returns a deduplicated
artifact set.  Collectors are isolated from one another: a collector that
throws records an error and the rest still run, because a partial inventory is
useful and an empty one is not.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..core.models import Artifact, ScanError
from .agent_config import AgentConfigCollector
from .base import CollectionResult, Collector, home_dir
from .mcp_config import McpConfigCollector

__all__ = [
    "COLLECTORS",
    "AgentConfigCollector",
    "CollectionResult",
    "Collector",
    "McpConfigCollector",
    "discover",
]

#: Every collector, in the order their artifacts should appear.
COLLECTORS: List[Collector] = [
    McpConfigCollector(),
    AgentConfigCollector(),
]


def discover(
    roots: Sequence[str],
    *,
    home: Optional[str] = None,
    include_user_scope: bool = True,
    collectors: Optional[Sequence[Collector]] = None,
    exclude: Optional[Sequence[str]] = None,
) -> CollectionResult:
    """Collect every agent artifact reachable from ``roots``.

    ``include_user_scope`` exists because the two audiences want different
    things: a developer scanning their laptop wants the user-level configs
    included, while a CI job scanning a repository must not report on whatever
    the build agent happens to have in its home directory.
    """
    # Pointing at a config file rather than a directory is a reasonable thing
    # to do -- `bulwark scan .mcp.json` -- and silently reporting nothing for
    # it is the same false-clean failure as never walking the tree.
    normalised_roots = []
    for root in roots:
        if not root:
            continue
        absolute = os.path.abspath(root)
        normalised_roots.append(
            os.path.dirname(absolute) if os.path.isfile(absolute) else absolute
        )

    if include_user_scope:
        resolved_home = home if home is not None else home_dir()
    else:
        # Point the home at a directory that cannot contain configs rather
        # than threading a conditional through every collector.
        anchor = normalised_roots[0] if normalised_roots else os.path.abspath(".")
        resolved_home = os.path.join(anchor, "__bulwark_no_user_scope__")

    combined = CollectionResult()

    for collector in collectors if collectors is not None else COLLECTORS:
        try:
            combined.extend(
                collector.collect(normalised_roots, resolved_home, tuple(exclude or ()))
            )
        except Exception as exc:
            combined.errors.append(
                ScanError(
                    where="collector:" + (collector.name or type(collector).__name__),
                    message="%s: %s" % (type(exc).__name__, exc),
                    kind="collector_error",
                )
            )

    combined.artifacts = _dedupe(combined.artifacts)
    if not combined.coverage.complete:
        # A clean report must say what it did not look at, or the clean part
        # is not something anyone can safely rely on.
        combined.errors.append(
            ScanError(
                where="coverage",
                message=_describe_coverage(combined.coverage),
                kind="coverage",
            )
        )
    combined.files_seen = sorted(set(combined.files_seen))
    return combined


def _dedupe(artifacts: Sequence[Artifact]) -> List[Artifact]:
    """Collapse artifacts that different collectors found twice.

    The same server can legitimately appear in a user config and a project
    config.  Keep the first occurrence but record the duplicate's path, so a
    finding can say "also declared in ..." instead of firing twice.
    """
    out: List[Artifact] = []
    index: Dict[Tuple[str, str, str], Artifact] = {}
    for artifact in artifacts:
        key = (artifact.kind.value, artifact.identity, artifact.fingerprint)
        if key in index:
            first = index[key]
            others: Any = first.data.setdefault("also_declared_in", [])
            path = artifact.source.path
            if (
                isinstance(others, list)
                and path
                and path != first.source.path
                and path not in others
            ):
                others.append(path)
            continue
        index[key] = artifact
        out.append(artifact)
    return out


def _describe_coverage(stats) -> str:
    """A one-line, honest statement of what the walk left out."""
    parts = ["%d directories walked" % stats.directories]
    if stats.skipped:
        top = sorted(stats.skipped.items(), key=lambda kv: -kv[1])[:4]
        parts.append(
            "%d skipped (%s)"
            % (
                sum(stats.skipped.values()),
                ", ".join("%s x%d" % (name, count) for name, count in top),
            )
        )
    if stats.truncated:
        parts.append("%d truncated at the depth limit" % len(stats.truncated))
    return "; ".join(parts)
