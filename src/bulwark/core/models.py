"""Core data model for Bulwark.

Everything the scanner produces is built from these types.  They are plain
dataclasses with explicit to_dict/from_dict so the whole tool stays
dependency-free and every artefact round-trips through JSON without surprises.
"""

from __future__ import annotations

import enum
import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# --------------------------------------------------------------------------
# Severity
# --------------------------------------------------------------------------


class Severity(enum.IntEnum):
    """Ordered severity.  Higher is worse, so findings sort naturally."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: Any) -> "Severity":
        if isinstance(value, Severity):
            return value
        if isinstance(value, bool):
            raise ValueError("bool is not a severity")
        if isinstance(value, int):
            return cls(max(0, min(4, value)))
        text = str(value).strip().upper()
        aliases = {
            "INFORMATIONAL": "INFO",
            "NOTE": "INFO",
            "NONE": "INFO",
            "WARNING": "MEDIUM",
            "WARN": "MEDIUM",
            "ERROR": "HIGH",
            "CRIT": "CRITICAL",
        }
        text = aliases.get(text, text)
        try:
            return cls[text]
        except KeyError as exc:
            raise ValueError("unknown severity: %r" % (value,)) from exc

    @property
    def label(self) -> str:
        return self.name

    @property
    def sarif_level(self) -> str:
        """SARIF only defines four levels; map on without losing ordering."""
        return {
            Severity.INFO: "note",
            Severity.LOW: "note",
            Severity.MEDIUM: "warning",
            Severity.HIGH: "error",
            Severity.CRITICAL: "error",
        }[self]

    @property
    def score(self) -> float:
        """0-10 scale for the posture score and SARIF security-severity."""
        return {
            Severity.INFO: 0.0,
            Severity.LOW: 3.0,
            Severity.MEDIUM: 5.5,
            Severity.HIGH: 8.0,
            Severity.CRITICAL: 9.5,
        }[self]


class Confidence(enum.IntEnum):
    LOW = 0
    MEDIUM = 1
    HIGH = 2

    @classmethod
    def parse(cls, value: Any) -> "Confidence":
        if isinstance(value, Confidence):
            return value
        if isinstance(value, bool):
            raise ValueError("bool is not a confidence")
        if isinstance(value, int):
            return cls(max(0, min(2, value)))
        return cls[str(value).strip().upper()]


# --------------------------------------------------------------------------
# Artifacts: the things we discovered and can reason about
# --------------------------------------------------------------------------


class ArtifactKind(str, enum.Enum):
    """What sort of agent surface an artifact represents."""

    MCP_SERVER = "mcp_server"
    MCP_TOOL = "mcp_tool"
    MCP_PROMPT = "mcp_prompt"
    MCP_RESOURCE = "mcp_resource"
    HOOK = "hook"
    SKILL = "skill"
    SUBAGENT = "subagent"
    PERMISSION_RULE = "permission_rule"
    SETTINGS = "settings"
    ENV_FILE = "env_file"
    SLASH_COMMAND = "slash_command"
    AGENT_SOURCE = "agent_source"
    UNKNOWN = "unknown"


@dataclass
class SourceRef:
    """Where an artifact or finding physically lives."""

    path: str = ""
    line: Optional[int] = None
    column: Optional[int] = None
    snippet: str = ""
    json_pointer: str = ""

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"path": self.path}
        if self.line is not None:
            out["line"] = self.line
        if self.column is not None:
            out["column"] = self.column
        if self.snippet:
            out["snippet"] = self.snippet
        if self.json_pointer:
            out["json_pointer"] = self.json_pointer
        return out

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SourceRef":
        return cls(
            path=data.get("path", ""),
            line=data.get("line"),
            column=data.get("column"),
            snippet=data.get("snippet", ""),
            json_pointer=data.get("json_pointer", ""),
        )


@dataclass
class Artifact:
    """A discovered piece of the agent attack surface.

    identity is the stable, human-meaningful address of the artifact (for
    example "github:create_issue"); fingerprint is the content hash used for
    drift and rug-pull detection.
    """

    kind: ArtifactKind
    identity: str
    name: str = ""
    platform: str = ""  # claude-code, claude-desktop, cursor, vscode, ...
    parent: str = ""  # owning server / file, for tools and prompts
    source: SourceRef = field(default_factory=SourceRef)
    text: str = ""  # the model-visible text (tool description etc.)
    data: Dict[str, Any] = field(default_factory=dict)
    capabilities: List[str] = field(default_factory=list)
    trust: str = "unknown"  # local | registry | remote | unknown
    tags: List[str] = field(default_factory=list)

    # ---- fingerprinting -------------------------------------------------

    def fingerprint_material(self) -> str:
        """Canonical serialisation of everything the model can see.

        Deliberately excludes file paths and line numbers: moving a config
        should not look like a rug pull, but changing a tool description must.
        """
        payload = {
            "kind": self.kind.value,
            "identity": self.identity,
            "name": self.name,
            "text": self.text,
            "capabilities": sorted(self.capabilities),
            "data": canonical(self.data),
        }
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )

    @property
    def fingerprint(self) -> str:
        digest = hashlib.sha256(self.fingerprint_material().encode("utf-8"))
        return "sha256:" + digest.hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind.value,
            "identity": self.identity,
            "name": self.name,
            "platform": self.platform,
            "parent": self.parent,
            "source": self.source.to_dict(),
            "text": self.text,
            "data": self.data,
            "capabilities": sorted(self.capabilities),
            "trust": self.trust,
            "tags": sorted(self.tags),
            "fingerprint": self.fingerprint,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Artifact":
        return cls(
            kind=ArtifactKind(data.get("kind", "unknown")),
            identity=data.get("identity", ""),
            name=data.get("name", ""),
            platform=data.get("platform", ""),
            parent=data.get("parent", ""),
            source=SourceRef.from_dict(data.get("source") or {}),
            text=data.get("text", ""),
            data=data.get("data") or {},
            capabilities=list(data.get("capabilities") or []),
            trust=data.get("trust", "unknown"),
            tags=list(data.get("tags") or []),
        )


def canonical(value: Any) -> Any:
    """Recursively normalise a value for stable hashing."""
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: str(kv[0]))
        return {str(k): canonical(v) for k, v in items}
    if isinstance(value, (list, tuple)):
        return [canonical(v) for v in value]
    if isinstance(value, (str, bool, int, float)) or value is None:
        return value
    return str(value)


# --------------------------------------------------------------------------
# Findings
# --------------------------------------------------------------------------


@dataclass
class Evidence:
    """A concrete, quotable reason the finding fired."""

    label: str
    value: str = ""
    source: Optional[SourceRef] = None

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"label": self.label, "value": self.value}
        if self.source:
            out["source"] = self.source.to_dict()
        return out


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    artifact: Optional[Artifact] = None
    description: str = ""
    remediation: str = ""
    confidence: Confidence = Confidence.MEDIUM
    evidence: List[Evidence] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    frameworks: Dict[str, List[str]] = field(default_factory=dict)
    source: Optional[SourceRef] = None
    tags: List[str] = field(default_factory=list)
    related: List[str] = field(default_factory=list)  # other artifact identities
    # populated by the policy engine
    waived: bool = False
    waiver_reason: str = ""
    original_severity: Optional[Severity] = None

    @property
    def location(self) -> SourceRef:
        if self.source is not None:
            return self.source
        if self.artifact is not None:
            return self.artifact.source
        return SourceRef()

    @property
    def artifact_identity(self) -> str:
        return self.artifact.identity if self.artifact else ""

    @property
    def fingerprint(self) -> str:
        """Stable id for dedup, waivers and baseline suppression.

        Intentionally ignores line numbers so reformatting a config does not
        resurrect a waived finding.
        """
        material = "|".join(
            [
                self.rule_id,
                self.artifact_identity,
                self.location.path.replace("\\", "/").lower(),
                "|".join(sorted(e.value for e in self.evidence))[:512],
            ]
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.fingerprint,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.label,
            "severity_score": self.severity.score,
            "confidence": self.confidence.name,
            "description": self.description,
            "remediation": self.remediation,
            "artifact": self.artifact.to_dict() if self.artifact else None,
            "location": self.location.to_dict(),
            "evidence": [e.to_dict() for e in self.evidence],
            "references": list(self.references),
            "frameworks": {k: list(v) for k, v in self.frameworks.items()},
            "tags": sorted(self.tags),
            "related": list(self.related),
            "waived": self.waived,
            "waiver_reason": self.waiver_reason,
            "original_severity": (
                self.original_severity.label if self.original_severity else None
            ),
        }


# --------------------------------------------------------------------------
# Scan result
# --------------------------------------------------------------------------


@dataclass
class ScanError:
    where: str
    message: str
    kind: str = "error"

    def to_dict(self) -> Dict[str, Any]:
        return {"where": self.where, "message": self.message, "kind": self.kind}


@dataclass
class ScanResult:
    findings: List[Finding] = field(default_factory=list)
    artifacts: List[Artifact] = field(default_factory=list)
    errors: List[ScanError] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    finished_at: float = 0.0
    targets: List[str] = field(default_factory=list)
    tool_version: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def active_findings(self) -> List[Finding]:
        return [f for f in self.findings if not f.waived]

    def by_severity(self, minimum: Severity = Severity.INFO) -> List[Finding]:
        return [f for f in self.active_findings if f.severity >= minimum]

    def counts(self) -> Dict[str, int]:
        out = {s.label: 0 for s in Severity}
        for f in self.active_findings:
            out[f.severity.label] += 1
        return out

    def waived_count(self) -> int:
        return sum(1 for f in self.findings if f.waived)

    def highest(self) -> Severity:
        if not self.active_findings:
            return Severity.INFO
        return max(f.severity for f in self.active_findings)

    def posture_score(self) -> int:
        """0-100, higher is safer.

        Weighted by severity and saturating: one CRITICAL should dominate a
        pile of INFO notes, and forty mediums should not read the same as four.
        """
        if not self.artifacts:
            return 100
        weights = {
            Severity.CRITICAL: 40.0,
            Severity.HIGH: 16.0,
            Severity.MEDIUM: 5.0,
            Severity.LOW: 1.5,
            Severity.INFO: 0.0,
        }
        confidence_factor = {
            Confidence.LOW: 0.5,
            Confidence.MEDIUM: 0.85,
            Confidence.HIGH: 1.0,
        }
        penalty = 0.0
        for f in self.active_findings:
            penalty += weights[f.severity] * confidence_factor[f.confidence]
        if penalty <= 0:
            return 100
        score = 100.0 * (40.0 / (40.0 + penalty))
        return round(max(0.0, min(100.0, score)))

    def grade(self) -> str:
        score = self.posture_score()
        for threshold, letter in ((90, "A"), (80, "B"), (65, "C"), (50, "D")):
            if score >= threshold:
                return letter
        return "F"

    def sort(self) -> None:
        self.findings.sort(
            key=lambda f: (
                -int(f.severity),
                -int(f.confidence),
                f.rule_id,
                f.artifact_identity,
                f.location.path,
            )
        )

    def dedupe(self) -> None:
        seen: Dict[str, Finding] = {}
        for f in self.findings:
            seen.setdefault(f.fingerprint, f)
        self.findings = list(seen.values())

    def to_dict(self) -> Dict[str, Any]:
        finished = self.finished_at or time.time()
        return {
            "schema": "bulwark.scan/1",
            "tool": {"name": "bulwark", "version": self.tool_version},
            "started_at": self.started_at,
            "finished_at": finished,
            "duration_seconds": round(finished - self.started_at, 3),
            "targets": list(self.targets),
            "summary": {
                "artifacts": len(self.artifacts),
                "findings": len(self.active_findings),
                "waived": self.waived_count(),
                "counts": self.counts(),
                "posture_score": self.posture_score(),
                "grade": self.grade(),
                "highest_severity": self.highest().label,
            },
            "findings": [f.to_dict() for f in self.findings],
            "artifacts": [a.to_dict() for a in self.artifacts],
            "errors": [e.to_dict() for e in self.errors],
            "metadata": self.metadata,
        }
