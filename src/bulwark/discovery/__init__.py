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
) -> CollectionResult:
    """Collect every agent artifact reachable from ``roots``.

    ``include_user_scope`` exists because the two audiences want different
    things: a developer scanning their laptop wants the user-level configs
    included, while a CI job scanning a repository must not report on whatever
    the build agent happens to have in its home directory.
    """
    normalised_roots = [os.path.abspath(root) for root in roots if root]

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
            combined.extend(collector.collect(normalised_roots, resolved_home))
        except Exception as exc:
            combined.errors.append(
                ScanError(
                    where="collector:" + (collector.name or type(collector).__name__),
                    message="%s: %s" % (type(exc).__name__, exc),
                    kind="collector_error",
                )
            )

    combined.artifacts = _dedupe(combined.artifacts)
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
