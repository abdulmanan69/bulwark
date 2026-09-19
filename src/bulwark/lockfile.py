"""Pin what the model is allowed to be told.

Package managers solved "the code changed underneath me" with a lockfile.
Agent tooling has no equivalent, and it needs one *more* than a package manager
does, because an MCP server's tool descriptions are re-fetched on every
connection and never compared against anything.

That gap is the rug pull: a server behaves correctly while it is being
reviewed, then changes a tool description afterwards.  The configuration is
byte-identical, the package version may be identical, and the instruction the
model receives is completely different.

``bulwark.lock`` closes it by recording a content hash of every model-visible
string.  ``bulwark diff`` compares a fresh scan against that record, and
``bulwark proxy`` enforces it live.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .core.models import Artifact, ArtifactKind

LOCK_SCHEMA = "bulwark.lock/1"
DEFAULT_LOCK_NAME = "bulwark.lock"

#: Kinds whose content the model reads, and which therefore must be pinned.
PINNED_KINDS = (
    ArtifactKind.MCP_SERVER,
    ArtifactKind.MCP_TOOL,
    ArtifactKind.MCP_PROMPT,
    ArtifactKind.MCP_RESOURCE,
    ArtifactKind.SKILL,
    ArtifactKind.SUBAGENT,
    ArtifactKind.SLASH_COMMAND,
    ArtifactKind.HOOK,
)


# --------------------------------------------------------------------------
# Change records
# --------------------------------------------------------------------------

#: Ordered by how much a change of that kind should alarm someone.
CHANGE_SEVERITY = {
    "text_changed": 4,        # the instruction the model receives is different
    "capability_added": 4,    # the tool can now do something it could not
    "added": 3,               # something new is being offered to the model
    "schema_changed": 3,      # new arguments can carry new data
    "trust_lowered": 3,
    "capability_removed": 1,
    "removed": 1,             # losing a tool breaks things but is not an attack
    "metadata_changed": 1,
}

#: Ordered from most to least verifiable, for detecting a downgrade.
TRUST_ORDER = {"local": 3, "registry": 2, "remote": 1, "unknown": 0}


@dataclass
class Change:
    kind: str
    identity: str
    artifact_kind: str = ""
    before: str = ""
    after: str = ""
    detail: str = ""

    @property
    def weight(self) -> int:
        return CHANGE_SEVERITY.get(self.kind, 2)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "identity": self.identity,
            "artifact_kind": self.artifact_kind,
            "before": self.before,
            "after": self.after,
            "detail": self.detail,
            "weight": self.weight,
        }


@dataclass
class Lockfile:
    entries: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    created_at: float = 0.0
    updated_at: float = 0.0
    tool_version: str = ""
    note: str = ""

    # ---- construction ---------------------------------------------------

    @classmethod
    def from_artifacts(
        cls,
        artifacts: Sequence[Artifact],
        *,
        tool_version: str = "",
        note: str = "",
        previous: Optional["Lockfile"] = None,
    ) -> "Lockfile":
        now = time.time()
        lock = cls(
            created_at=previous.created_at if previous else now,
            updated_at=now,
            tool_version=tool_version,
            note=note,
        )
        for artifact in artifacts:
            if artifact.kind in PINNED_KINDS:
                lock.entries[_key(artifact)] = _entry(artifact)
        return lock

    # ---- persistence ----------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": LOCK_SCHEMA,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "tool": {"name": "bulwark", "version": self.tool_version},
            "note": self.note,
            "entry_count": len(self.entries),
            # Sorted so the file is diff-friendly in version control: a rug
            # pull should show up as a one-line change in a pull request.
            "entries": dict(sorted(self.entries.items())),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Lockfile":
        entries = data.get("entries")
        tool = data.get("tool") or {}
        return cls(
            entries=dict(entries) if isinstance(entries, dict) else {},
            created_at=float(data.get("created_at") or 0.0),
            updated_at=float(data.get("updated_at") or 0.0),
            tool_version=str(tool.get("version") or ""),
            note=str(data.get("note") or ""),
        )

    def save(self, path: str) -> None:
        directory = os.path.dirname(os.path.abspath(path))
        if directory:
            os.makedirs(directory, exist_ok=True)
        payload = json.dumps(self.to_dict(), indent=2, ensure_ascii=False)
        # Write-then-rename so an interrupted save cannot leave a truncated
        # lockfile, which would silently disable drift detection.
        temporary = path + ".tmp"
        with open(temporary, "w", encoding="utf-8") as handle:
            handle.write(payload + "\n")
        os.replace(temporary, path)

    @classmethod
    def load(cls, path: str) -> Optional["Lockfile"]:
        try:
            with open(path, encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError):
            return None
        if not isinstance(data, dict):
            return None
        return cls.from_dict(data)

    # ---- comparison ------------------------------------------------------

    def diff(self, artifacts: Sequence[Artifact]) -> List[Change]:
        """Compare a fresh scan against the pinned state."""
        current: Dict[str, Dict[str, Any]] = {
            _key(a): _entry(a) for a in artifacts if a.kind in PINNED_KINDS
        }
        changes: List[Change] = []

        for key in sorted(set(self.entries) | set(current)):
            before = self.entries.get(key)
            after = current.get(key)
            identity, artifact_kind = _split_key(key)

            if before is None:
                changes.append(
                    Change(
                        kind="added",
                        identity=identity,
                        artifact_kind=artifact_kind,
                        after=str((after or {}).get("fingerprint", "")),
                        detail="not present when the lockfile was written",
                    )
                )
                continue
            if after is None:
                changes.append(
                    Change(
                        kind="removed",
                        identity=identity,
                        artifact_kind=artifact_kind,
                        before=str(before.get("fingerprint", "")),
                        detail="pinned but no longer present",
                    )
                )
                continue
            if before.get("fingerprint") == after.get("fingerprint"):
                continue

            changes.extend(_explain(identity, artifact_kind, before, after))

        changes.sort(key=lambda c: (-c.weight, c.identity, c.kind))
        return changes

    def verify(self, artifacts: Sequence[Artifact]) -> Tuple[bool, List[Change]]:
        """``(clean, changes)`` -- clean means nothing model-visible moved."""
        changes = self.diff(artifacts)
        material = [c for c in changes if c.weight >= 3]
        return (not material), changes

    def fingerprint_of(self, identity: str, kind: ArtifactKind) -> str:
        entry = self.entries.get("%s|%s" % (kind.value, identity))
        return str((entry or {}).get("fingerprint", ""))


# --------------------------------------------------------------------------
# Entry shape
# --------------------------------------------------------------------------


def _key(artifact: Artifact) -> str:
    return "%s|%s" % (artifact.kind.value, artifact.identity)


def _split_key(key: str) -> Tuple[str, str]:
    kind, _, identity = key.partition("|")
    return identity, kind


def _entry(artifact: Artifact) -> Dict[str, Any]:
    """What gets pinned.

    The text is stored as a hash plus a short preview rather than in full: a
    lockfile is committed to version control, and tool descriptions can be
    long, occasionally proprietary, and -- when poisoned -- something nobody
    wants replicated into another file.  The preview is enough for a human to
    recognise which description changed.
    """
    return {
        "fingerprint": artifact.fingerprint,
        "name": artifact.name,
        "parent": artifact.parent,
        "platform": artifact.platform,
        "trust": artifact.trust,
        "capabilities": sorted(artifact.capabilities),
        "text_preview": _preview(artifact.text),
        "text_length": len(artifact.text or ""),
        "schema_fingerprint": _schema_fingerprint(artifact),
    }


def _preview(text: str, limit: int = 120) -> str:
    collapsed = " ".join((text or "").split())
    return collapsed if len(collapsed) <= limit else collapsed[: limit - 3] + "..."


def _schema_fingerprint(artifact: Artifact) -> str:
    schema = artifact.data.get("schema")
    if not schema:
        return ""
    material = json.dumps(schema, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def _explain(
    identity: str, artifact_kind: str, before: Dict[str, Any], after: Dict[str, Any]
) -> List[Change]:
    """Say what actually moved, not just that the hash differs."""
    changes: List[Change] = []

    text_moved = before.get("text_preview") != after.get(
        "text_preview"
    ) or before.get("text_length") != after.get("text_length")
    if text_moved:
        changes.append(
            Change(
                kind="text_changed",
                identity=identity,
                artifact_kind=artifact_kind,
                before=str(before.get("text_preview", "")),
                after=str(after.get("text_preview", "")),
                detail=(
                    "the text the model reads has changed since it was pinned "
                    "(%s -> %s characters)"
                    % (before.get("text_length", 0), after.get("text_length", 0))
                ),
            )
        )

    old_caps = set(before.get("capabilities") or [])
    new_caps = set(after.get("capabilities") or [])
    if new_caps - old_caps:
        changes.append(
            Change(
                kind="capability_added",
                identity=identity,
                artifact_kind=artifact_kind,
                before=", ".join(sorted(old_caps)),
                after=", ".join(sorted(new_caps)),
                detail="gained: " + ", ".join(sorted(new_caps - old_caps)),
            )
        )
    if old_caps - new_caps:
        changes.append(
            Change(
                kind="capability_removed",
                identity=identity,
                artifact_kind=artifact_kind,
                before=", ".join(sorted(old_caps)),
                after=", ".join(sorted(new_caps)),
                detail="lost: " + ", ".join(sorted(old_caps - new_caps)),
            )
        )

    if before.get("schema_fingerprint") != after.get("schema_fingerprint"):
        changes.append(
            Change(
                kind="schema_changed",
                identity=identity,
                artifact_kind=artifact_kind,
                before=str(before.get("schema_fingerprint", "")),
                after=str(after.get("schema_fingerprint", "")),
                detail="the tool's arguments changed; new fields can carry new data",
            )
        )

    old_trust = str(before.get("trust", "unknown"))
    new_trust = str(after.get("trust", "unknown"))
    if TRUST_ORDER.get(new_trust, 0) < TRUST_ORDER.get(old_trust, 0):
        changes.append(
            Change(
                kind="trust_lowered",
                identity=identity,
                artifact_kind=artifact_kind,
                before=old_trust,
                after=new_trust,
                detail="the code now comes from a less verifiable source",
            )
        )

    if not changes:
        changes.append(
            Change(
                kind="metadata_changed",
                identity=identity,
                artifact_kind=artifact_kind,
                before=str(before.get("fingerprint", ""))[:23],
                after=str(after.get("fingerprint", ""))[:23],
                detail="fingerprint differs but no tracked field explains it",
            )
        )
    return changes


def default_path(root: str) -> str:
    return os.path.join(root, DEFAULT_LOCK_NAME)
