"""Rules that need the whole picture, not one artifact.

Every rule so far judges a single thing.  These judge combinations, because
the interesting agent failures are not "this tool is bad" -- each component is
individually reasonable -- but "these three tools, together, form a channel".
"""

from __future__ import annotations

import re
from typing import Dict, Iterable, List, Set

from ..analyzers import capability as cap
from ..analyzers.text import normalise_homoglyphs
from ..core.frameworks import CWE, EU_AI_ACT, MITRE_ATLAS, NIST_AI_RMF, OWASP_LLM
from ..core.models import Artifact, ArtifactKind, Confidence, Evidence, Finding, Severity
from ..core.rulebase import Rule, ScanContext, register


def _live_tools(ctx: ScanContext) -> List[Artifact]:
    """Tools belonging to servers that are actually enabled."""
    disabled = {
        server.identity
        for server in ctx.of_kind(ArtifactKind.MCP_SERVER)
        if server.data.get("disabled")
    }
    return [t for t in ctx.tools() if t.parent not in disabled]


def _roles(tool: Artifact) -> List[str]:
    roles = tool.data.get("roles")
    return list(roles) if isinstance(roles, list) else []


@register
class LethalTrifecta(Rule):
    id = "BW-CMP-001"
    title = "Agent combines private data, untrusted input and an outbound channel"
    severity = Severity.CRITICAL
    confidence = Confidence.MEDIUM
    category = "composite"
    description = (
        "This agent can simultaneously (1) reach data that would not be "
        "published, (2) ingest content that someone outside the organisation "
        "wrote, and (3) send bytes to a destination outside the trust "
        "boundary. Each is a reasonable capability. Together they are a "
        "complete exfiltration path that needs no vulnerability to exploit: "
        "attacker-authored text arrives through the ingestion tool as data, "
        "the model reads it as instructions, and the outbound tool carries the "
        "private data away. A model following instructions found in content is "
        "the intended behaviour, which is why no patch closes this -- only "
        "removing one of the three legs does."
    )
    remediation = (
        "Break one leg for any session that needs the other two. In practice: "
        "split the work across two agents with different tool sets; restrict "
        "the outbound tool to an allow-listed destination; or route the "
        "ingestion tool through `bulwark proxy` so fetched content is scanned "
        "and quarantined before it reaches the context window."
    )
    frameworks = {
        OWASP_LLM: ["LLM01", "LLM02", "LLM06"],
        MITRE_ATLAS: ["AML.T0051", "AML.T0024", "AML.T0025"],
        NIST_AI_RMF: ["NIST.GAI.DATA", "NIST.GAI.INFO"],
        EU_AI_ACT: ["EUAIACT.ART15"],
        CWE: ["CWE-200", "CWE-829"],
    }
    references = ["https://atlas.mitre.org/techniques/AML.T0024"]
    tags = ["trifecta", "exfiltration", "composite"]

    def check(self, ctx: ScanContext) -> Iterable[Finding]:
        tools = _live_tools(ctx)
        if not tools:
            return

        by_role: Dict[str, List[Artifact]] = {role: [] for role in cap.TRIFECTA}
        for tool in tools:
            for role in _roles(tool):
                if role in by_role:
                    by_role[role].append(tool)

        if not all(by_role[role] for role in cap.TRIFECTA):
            return

        def summarise(role: str, limit: int = 4) -> str:
            names = sorted(t.identity for t in by_role[role])
            shown = ", ".join(names[:limit])
            if len(names) > limit:
                shown += " (+%d more)" % (len(names) - limit)
            return shown

        # Severity depends on whether a human still gates the outbound leg.
        auto_egress = [t for t in by_role[cap.EGRESS] if t.data.get("auto_approved")]

        evidence = [
            Evidence(label="private data", value=summarise(cap.PRIVATE_DATA)),
            Evidence(label="untrusted input", value=summarise(cap.UNTRUSTED_INPUT)),
            Evidence(label="outbound channel", value=summarise(cap.EGRESS)),
        ]
        if auto_egress:
            evidence.append(
                Evidence(
                    label="outbound tools that are pre-approved",
                    value=", ".join(sorted(t.identity for t in auto_egress)[:6]),
                )
            )

        yield self.finding(
            None,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH if auto_egress else Confidence.MEDIUM,
            evidence=evidence,
            related=sorted(
                {t.identity for role in cap.TRIFECTA for t in by_role[role][:6]}
            ),
        )


def _normalise_tool_name(name: str) -> str:
    """Fold the differences a model will not notice but a registry will."""
    return re.sub(r"[^a-z0-9]", "", normalise_homoglyphs(name).lower())


@register
class CrossServerToolShadowing(Rule):
    id = "BW-CMP-002"
    title = "Two servers expose tools with colliding names"
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    category = "composite"
    description = (
        "Two connected servers publish tools with the same or near-identical "
        "names. The model chooses between them from the description alone, so "
        "a newly added server can quietly capture calls the user believes are "
        "going to the established one. A name that differs only by a "
        "look-alike character or an underscore is not a coincidence."
    )
    remediation = (
        "Rename or disconnect one of the servers. Where the host supports "
        "namespacing, enable it so the model sees a qualified name. Confirm "
        "which server a colliding name belongs to before using either."
    )
    frameworks = {
        OWASP_LLM: ["LLM01", "LLM03"],
        MITRE_ATLAS: ["AML.T0053"],
        CWE: ["CWE-345", "CWE-829"],
    }
    tags = ["shadowing", "composite"]

    def check(self, ctx: ScanContext) -> Iterable[Finding]:
        buckets: Dict[str, List[Artifact]] = {}
        for tool in _live_tools(ctx):
            buckets.setdefault(_normalise_tool_name(tool.name), []).append(tool)

        for normalised, group in sorted(buckets.items()):
            servers = {t.parent for t in group}
            if len(servers) < 2:
                continue

            exact = len({t.name for t in group}) == 1
            trusts = {t.trust for t in group}
            # A collision between a local server and a registry one is worse
            # than two servers from the same origin sharing a generic verb.
            mixed_trust = len(trusts) > 1

            yield self.finding(
                group[0],
                title="Tool name '%s' is exposed by %d different servers"
                % (normalised, len(servers)),
                severity=Severity.HIGH if (exact and mixed_trust) else Severity.MEDIUM,
                confidence=Confidence.HIGH if exact else Confidence.MEDIUM,
                evidence=[
                    Evidence(
                        label="colliding tools",
                        value=", ".join(sorted(t.identity for t in group)),
                    ),
                    Evidence(
                        label="match type",
                        value=(
                            "identical names"
                            if exact
                            else "names differ only after normalisation"
                        ),
                    ),
                    Evidence(
                        label="server trust levels", value=", ".join(sorted(trusts))
                    ),
                ],
                related=sorted(t.identity for t in group),
            )


@register
class CrossOriginToolReference(Rule):
    id = "BW-CMP-003"
    title = "Tool description gives instructions about another server's tools"
    severity = Severity.CRITICAL
    confidence = Confidence.HIGH
    category = "composite"
    description = (
        "A tool description names a tool belonging to a different server and "
        "tells the model how to treat it. A server has no legitimate knowledge "
        "of what else is connected: describing a peer's tools means the "
        "description was written to manipulate the model's routing, not to "
        "document this tool. This is how one compromised server redirects, "
        "disables or wraps the tools around it."
    )
    remediation = (
        "Disconnect the server that references its peers. Nothing about a "
        "correct integration requires it."
    )
    frameworks = {
        OWASP_LLM: ["LLM01", "LLM03"],
        MITRE_ATLAS: ["AML.T0053", "AML.T0051"],
        CWE: ["CWE-345"],
    }
    tags = ["shadowing", "cross-origin", "composite"]

    #: Verbs that turn a mention into a directive.
    DIRECTIVE = re.compile(
        r"\b(?:instead\s+of|rather\s+than|do\s+not\s+use|never\s+use|always\s+use|"
        r"before\s+(?:calling|using)|after\s+(?:calling|using)|disable|replace|"
        r"override|prefer|bypass|in\s+place\s+of)\b",
        re.IGNORECASE,
    )

    def check(self, ctx: ScanContext) -> Iterable[Finding]:
        tools = _live_tools(ctx)
        # Index tool names to their owning server, ignoring names too short to
        # be evidence of anything.
        owners: Dict[str, Set[str]] = {}
        for tool in tools:
            if len(tool.name) < 5:
                continue
            owners.setdefault(tool.name.lower(), set()).add(tool.parent)

        server_names = {
            s.identity.lower(): s.identity
            for s in ctx.of_kind(ArtifactKind.MCP_SERVER)
            if len(s.identity) >= 4
        }

        for tool in tools:
            text = (tool.text or "").lower()
            if not text or not self.DIRECTIVE.search(text):
                continue

            foreign: List[str] = []
            for name, parents in owners.items():
                if tool.parent in parents:
                    continue
                if re.search(r"\b%s\b" % re.escape(name), text):
                    foreign.append(
                        "tool '%s' (owned by %s)" % (name, ", ".join(sorted(parents)))
                    )

            for lowered, original in server_names.items():
                if original == tool.parent:
                    continue
                if re.search(r"\b%s\b" % re.escape(lowered), text):
                    foreign.append("server '%s'" % original)

            if not foreign:
                continue

            yield self.finding(
                tool,
                title="Tool %s issues directives about another server's tools"
                % tool.identity,
                evidence=[
                    Evidence(
                        label="references", value="; ".join(sorted(set(foreign))[:6])
                    ),
                    Evidence(label="description", value=(tool.text or "")[:300]),
                ],
                related=sorted(set(foreign)),
            )


@register
class ExcessiveAgency(Rule):
    id = "BW-CMP-004"
    title = "Single tool concentrates disproportionate capability"
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    category = "composite"
    description = (
        "One tool combines several high-power capabilities -- executing "
        "commands, deleting files, reaching credentials, changing "
        "infrastructure or moving money. A tool that can do all of these is "
        "indistinguishable, from the model's point of view, from a shell: "
        "there is no meaningful approval decision left to make, because "
        "approving it once approves everything."
    )
    remediation = (
        "Split the tool into narrower operations so each call can be judged. "
        "Where the tool is third-party, restrict it at the boundary instead: "
        "`bulwark proxy --deny-tool` removes individual operations from the "
        "surface the model sees."
    )
    frameworks = {
        OWASP_LLM: ["LLM06"],
        MITRE_ATLAS: ["AML.T0011"],
        EU_AI_ACT: ["EUAIACT.ART14"],
        CWE: ["CWE-250", "CWE-269"],
    }
    tags = ["excessive-agency", "composite"]

    #: Above this, one approval decision covers too much ground.
    AGENCY_THRESHOLD = 20

    def check(self, ctx: ScanContext) -> Iterable[Finding]:
        for tool in _live_tools(ctx):
            score = tool.data.get("agency_score")
            if not isinstance(score, int) or score < self.AGENCY_THRESHOLD:
                continue
            auto = bool(tool.data.get("auto_approved"))
            yield self.finding(
                tool,
                title="Tool %s concentrates %d points of capability"
                % (tool.identity, score),
                severity=Severity.CRITICAL if auto else Severity.HIGH,
                confidence=Confidence.HIGH if auto else Confidence.MEDIUM,
                evidence=[
                    Evidence(
                        label="capabilities",
                        value=", ".join(
                            "%s (%s)" % (c, cap.describe_capability(c))
                            for c in tool.capabilities
                        ),
                    ),
                    Evidence(label="agency score", value=str(score)),
                    Evidence(
                        label="approval",
                        value="pre-approved - no prompt" if auto else "prompts on use",
                    ),
                ],
            )


@register
class AutoApprovedDangerousTool(Rule):
    id = "BW-CMP-005"
    title = "Dangerous tool is pre-approved in configuration"
    severity = Severity.CRITICAL
    confidence = Confidence.HIGH
    category = "composite"
    description = (
        "The configuration lists this tool as auto-approved, so the host will "
        "call it without prompting. The tool can execute commands, delete "
        "data, reach credentials or move money. Pre-approval is reasonable for "
        "a read-only lookup; for these operations it removes the only control "
        "that stands between injected text and an irreversible action."
    )
    remediation = (
        "Remove the tool from the auto-approve list. If the friction is the "
        "problem, pre-approve a narrower tool instead of a broader one."
    )
    frameworks = {
        OWASP_LLM: ["LLM06"],
        MITRE_ATLAS: ["AML.T0011"],
        EU_AI_ACT: ["EUAIACT.ART14"],
        NIST_AI_RMF: ["NIST.GAI.HUMAN"],
        CWE: ["CWE-250", "CWE-284"],
    }
    tags = ["auto-approve", "excessive-agency", "composite"]

    DANGEROUS = {
        "exec", "code_eval", "fs_delete", "fs_write", "db_write", "secrets",
        "cloud_admin", "identity", "payment", "net_send", "messaging",
    }

    def check(self, ctx: ScanContext) -> Iterable[Finding]:
        for tool in _live_tools(ctx):
            if not tool.data.get("auto_approved"):
                continue
            risky = sorted(set(tool.capabilities) & self.DANGEROUS)
            server = ctx.by_identity(tool.parent)
            approvals = server.data.get("auto_approve", []) if server else []
            wildcard = "*" in approvals
            if not risky and not wildcard:
                continue
            yield self.finding(
                tool,
                title="Tool %s is pre-approved and %s"
                % (
                    tool.identity,
                    cap.describe_capability(risky[0]) if risky else "acts without review",
                ),
                severity=Severity.CRITICAL if risky else Severity.HIGH,
                evidence=[
                    Evidence(
                        label="dangerous capabilities",
                        value=", ".join(risky) or "(unknown - blanket approval)",
                    ),
                    Evidence(
                        label="approval scope",
                        value=(
                            "every tool on this server"
                            if wildcard
                            else "this tool specifically"
                        ),
                    ),
                    Evidence(label="server", value=tool.parent),
                ],
            )


@register
class UntrustedServerHighPrivilege(Rule):
    id = "BW-CMP-006"
    title = "Server with weak provenance holds high-privilege tools"
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    category = "composite"
    description = (
        "This server's code is not pinned, not reviewed, or fetched at launch, "
        "and the tools it exposes can execute commands, reach credentials or "
        "change infrastructure. Weak provenance is tolerable for a calculator. "
        "Combined with this much authority, the next upstream publish is a "
        "remote code execution on every machine that runs the agent."
    )
    remediation = (
        "Pin the server to a reviewed version before granting it these tools, "
        "or move the high-privilege operations to a server you control."
    )
    frameworks = {
        OWASP_LLM: ["LLM03", "LLM06"],
        MITRE_ATLAS: ["AML.T0010", "AML.T0011"],
        NIST_AI_RMF: ["NIST.GAI.SUPPLY"],
        CWE: ["CWE-494", "CWE-250"],
    }
    tags = ["supply-chain", "excessive-agency", "composite"]

    PRIVILEGED = {
        "exec", "code_eval", "secrets", "cloud_admin", "identity", "payment",
        "fs_delete",
    }

    def check(self, ctx: ScanContext) -> Iterable[Finding]:
        for server in ctx.of_kind(ArtifactKind.MCP_SERVER):
            if server.data.get("disabled"):
                continue
            raw = server.data.get("provenance")
            prov = raw if isinstance(raw, dict) else {}
            weak = (not prov.get("pinned")) or prov.get("trust") in {"remote", "unknown"}
            if not weak:
                continue

            privileged: Dict[str, Set[str]] = {}
            for tool in ctx.children_of(server.identity):
                hits = set(tool.capabilities) & self.PRIVILEGED
                if hits:
                    privileged[tool.identity] = hits
            if not privileged:
                continue

            yield self.finding(
                server,
                title="Unpinned server '%s' exposes %d high-privilege tool(s)"
                % (server.identity, len(privileged)),
                evidence=[
                    Evidence(
                        label="provenance",
                        value="trust=%s pinned=%s issues=%s"
                        % (
                            prov.get("trust"),
                            prov.get("pinned"),
                            ", ".join(prov.get("issues") or []) or "none",
                        ),
                    )
                ]
                + [
                    Evidence(label=identity, value=", ".join(sorted(hits)))
                    for identity, hits in sorted(privileged.items())[:6]
                ],
                related=sorted(privileged),
            )
