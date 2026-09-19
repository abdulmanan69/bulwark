"""AI Bill of Materials.

An SBOM answers "what code is in this build".  It cannot answer the question a
regulator, an auditor or an incoming security team now asks about an AI system:
*what can the agent reach, on whose authority, and where does the data go?*
Those capabilities come from MCP servers resolved at runtime, so they never
appear in a dependency manifest.

This emits CycloneDX 1.5 -- the format existing SBOM tooling already ingests --
with each MCP server as a component, each tool as a nested subcomponent, and
the inferred capabilities and trust boundaries attached as properties.  The
result drops into an existing SBOM pipeline rather than needing a new one.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import uuid
from typing import Any, Dict, List

from .analyzers import capability as cap
from .core.models import Artifact, ArtifactKind, Finding, ScanResult
from .version import __version__

SPEC_VERSION = "1.5"
PROJECT_URL = "https://github.com/abdulmanan69/bulwark"


def build(result: ScanResult) -> Dict[str, Any]:
    """Build a CycloneDX document describing the agent's reachable surface."""
    servers = [
        a
        for a in result.artifacts
        if a.kind is ArtifactKind.MCP_SERVER and not a.data.get("disabled")
    ]
    tools = [a for a in result.artifacts if a.kind is ArtifactKind.MCP_TOOL]
    by_parent: Dict[str, List[Artifact]] = {}
    for tool in tools:
        by_parent.setdefault(tool.parent, []).append(tool)

    components = [_server_component(s, by_parent.get(s.identity, [])) for s in servers]
    components.extend(
        _surface_component(a)
        for a in result.artifacts
        if a.kind in (ArtifactKind.SKILL, ArtifactKind.SUBAGENT, ArtifactKind.HOOK)
    )

    reports = [
        cap.CapabilityReport(
            capabilities=list(t.capabilities),
            roles=list(t.data.get("roles") or []),
        )
        for t in tools
    ]
    roles = cap.aggregate_roles(reports)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": "urn:uuid:" + str(uuid.uuid4()),
        "version": 1,
        "metadata": {
            # CycloneDX requires an ISO-8601 instant here.
            "timestamp": _iso(result.started_at),
            "tools": {
                "components": [
                    {"type": "application", "name": "bulwark", "version": __version__}
                ]
            },
            "component": {
                "type": "application",
                "bom-ref": "agent-surface",
                "name": "ai-agent-surface",
                "description": (
                    "The tool surface reachable by AI agents configured in "
                    + ", ".join(result.targets)
                ),
            },
            "properties": _properties(
                {
                    "bulwark:postureScore": result.posture_score(),
                    "bulwark:grade": result.grade(),
                    "bulwark:findings": len(result.active_findings),
                    "bulwark:criticalFindings": result.counts()["CRITICAL"],
                    "bulwark:servers": len(servers),
                    "bulwark:tools": len(tools),
                    "bulwark:trifectaComplete": cap.trifecta_complete(reports),
                    "bulwark:privateDataCapabilities": ", ".join(
                        roles.get(cap.PRIVATE_DATA, [])
                    ),
                    "bulwark:untrustedInputCapabilities": ", ".join(
                        roles.get(cap.UNTRUSTED_INPUT, [])
                    ),
                    "bulwark:egressCapabilities": ", ".join(roles.get(cap.EGRESS, [])),
                }
            ),
        },
        "components": components,
        "vulnerabilities": [_vulnerability(f) for f in result.active_findings],
    }


def _iso(epoch: float) -> str:
    moment = datetime.datetime.fromtimestamp(epoch, tz=datetime.timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _server_component(server: Artifact, tools: List[Artifact]) -> Dict[str, Any]:
    raw = server.data.get("provenance")
    prov = raw if isinstance(raw, dict) else {}
    package = str(prov.get("package") or server.identity)
    version = str(prov.get("version") or "")

    component: Dict[str, Any] = {
        "type": "application",
        "bom-ref": "mcp-server/" + server.identity,
        "name": package,
        "description": server.text or ("MCP server '%s'" % server.identity),
        "scope": "required",
        "properties": _properties(
            {
                "bulwark:serverName": server.identity,
                "bulwark:platform": server.platform,
                "bulwark:transport": prov.get("transport", ""),
                "bulwark:trust": server.trust,
                "bulwark:pinned": prov.get("pinned", False),
                "bulwark:ephemeral": prov.get("ephemeral", False),
                "bulwark:autoConfirm": prov.get("auto_confirm", False),
                "bulwark:provenanceIssues": ", ".join(prov.get("issues") or []),
                "bulwark:configPath": server.data.get("config_path", ""),
                "bulwark:toolCount": len(tools),
                "bulwark:fingerprint": server.fingerprint,
            }
        ),
    }
    if version:
        component["version"] = version
    purl = _purl(str(prov.get("ecosystem") or ""), package, version)
    if purl:
        component["purl"] = purl
    if tools:
        component["components"] = [
            _tool_component(t) for t in sorted(tools, key=lambda a: a.name)
        ]
    return component


def _tool_component(tool: Artifact) -> Dict[str, Any]:
    return {
        "type": "library",
        "bom-ref": "mcp-tool/" + tool.identity,
        "name": tool.name,
        "description": (tool.text or "")[:1000],
        "scope": "required",
        "properties": _properties(
            {
                "bulwark:server": tool.parent,
                "bulwark:capabilities": ", ".join(tool.capabilities),
                "bulwark:capabilityDetail": "; ".join(
                    "%s: %s" % (c, cap.describe_capability(c))
                    for c in tool.capabilities
                ),
                "bulwark:trustRoles": ", ".join(tool.data.get("roles") or []),
                "bulwark:agencyScore": tool.data.get("agency_score", 0),
                "bulwark:autoApproved": bool(tool.data.get("auto_approved")),
                "bulwark:origin": tool.data.get("origin", ""),
                "bulwark:fingerprint": tool.fingerprint,
            }
        ),
    }


def _surface_component(artifact: Artifact) -> Dict[str, Any]:
    return {
        "type": "data",
        "bom-ref": "%s/%s" % (artifact.kind.value, artifact.identity),
        "name": artifact.name or artifact.identity,
        "description": (artifact.text or "")[:500],
        "properties": _properties(
            {
                "bulwark:kind": artifact.kind.value,
                "bulwark:platform": artifact.platform,
                "bulwark:path": artifact.source.path,
                "bulwark:fingerprint": artifact.fingerprint,
            }
        ),
    }


def _vulnerability(finding: Finding) -> Dict[str, Any]:
    """Represent a finding as a CycloneDX vulnerability.

    Findings are not CVEs, and the ``source`` names Bulwark so nobody mistakes
    one for a published advisory.  Expressing them here is what lets an
    existing SBOM dashboard show agent risk next to dependency risk instead of
    in a separate tool nobody opens.
    """
    ref = finding.artifact_identity or finding.location.path or "agent-surface"
    return {
        "bom-ref": "bulwark/" + finding.fingerprint,
        "id": finding.rule_id,
        "source": {"name": "bulwark", "url": PROJECT_URL},
        "ratings": [
            {
                "source": {"name": "bulwark"},
                "score": finding.severity.score,
                "severity": finding.severity.label.lower(),
                "method": "other",
            }
        ],
        "cwes": [
            int(identifier.split("-")[1])
            for identifier in finding.frameworks.get("CWE", [])
            if identifier.startswith("CWE-") and identifier.split("-")[1].isdigit()
        ],
        "description": finding.title,
        "detail": finding.description,
        "recommendation": finding.remediation,
        "affects": [{"ref": _bom_ref_for(ref)}],
        "properties": _properties(
            {
                "bulwark:confidence": finding.confidence.name,
                "bulwark:evidence": "; ".join(
                    "%s=%s" % (e.label, e.value[:160]) for e in finding.evidence[:4]
                ),
            }
        ),
    }


def _bom_ref_for(identity: str) -> str:
    if ":" in identity and not identity.startswith(("config:", "settings:")):
        return "mcp-tool/" + identity
    return "agent-surface"


def _purl(ecosystem: str, package: str, version: str) -> str:
    """Build a package URL when the ecosystem is one purl understands."""
    kind = {"npm": "npm", "pypi": "pypi", "oci": "oci"}.get(ecosystem)
    if not kind or not package:
        return ""
    if kind == "npm" and package.startswith("@"):
        # purl encodes an npm scope as a namespace segment: the leading "@"
        # is percent-encoded and the slash stays a real path separator.
        scope, _, rest = package[1:].partition("/")
        name = "%%40%s/%s" % (scope, rest) if rest else "%%40%s" % scope
    elif kind == "oci":
        # The tag belongs in the version, not the name, or it appears twice.
        head, separator, tail = package.rpartition(":")
        name = head if separator and "/" not in tail else package
    else:
        name = package
    suffix = "@" + version if version else ""
    return "pkg:%s/%s%s" % (kind, name, suffix)


def _properties(values: Dict[str, Any]) -> List[Dict[str, str]]:
    """CycloneDX properties are name/value strings; empty ones add noise."""
    out: List[Dict[str, str]] = []
    for name, value in values.items():
        if value in (None, "", [], {}):
            continue
        out.append({"name": name, "value": str(value)})
    return out


def digest(document: Dict[str, Any]) -> str:
    """Stable hash of the surface, ignoring the serial number and timestamp.

    Lets a pipeline answer "did the agent's reachable surface change since the
    last release" without diffing two large documents.
    """
    stripped = dict(document)
    stripped.pop("serialNumber", None)
    metadata = dict(stripped.get("metadata") or {})
    metadata.pop("timestamp", None)
    stripped["metadata"] = metadata
    material = json.dumps(stripped, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()
