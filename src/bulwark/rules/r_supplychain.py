"""Rules about where an MCP server's code comes from.

The threat here is not exotic.  An MCP server entry is a command that runs with
the developer's privileges every time the agent starts; if that command
re-resolves a package from the internet, then whoever controls the package
controls the developer's machine from the next launch onward, with no build, no
review and no deploy.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, Iterator

from ..core.frameworks import (
    CWE,
    EU_AI_ACT,
    ISO_42001,
    MITRE_ATLAS,
    NIST_AI_RMF,
    OWASP_LLM,
)
from ..core.models import Artifact, ArtifactKind, Confidence, Evidence, Finding, Severity
from ..core.rulebase import Rule, ScanContext, register


def _provenance(artifact: Artifact) -> Dict[str, Any]:
    data = artifact.data.get("provenance")
    return data if isinstance(data, dict) else {}


def _command_line(artifact: Artifact) -> str:
    parts = [str(artifact.data.get("command", ""))]
    parts.extend(str(a) for a in artifact.data.get("args", []) or [])
    return " ".join(p for p in parts if p).strip()


def _active_servers(ctx: ScanContext) -> Iterator[Artifact]:
    """Servers that will actually start.

    A disabled server is still inventory, but it is not exposure, and reporting
    it at the same severity trains people to ignore the report.
    """
    for artifact in ctx.of_kind(ArtifactKind.MCP_SERVER):
        if not artifact.data.get("disabled"):
            yield artifact


@register
class UnreviewedAutoInstall(Rule):
    id = "BW-SUP-001"
    title = "Server auto-installs an unpinned package on every launch"
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    category = "supply-chain"
    description = (
        "The launch command re-resolves a package from a public registry, "
        "auto-confirms the install, and pins no version. The code that runs "
        "tomorrow is therefore whatever the maintainer -- or whoever "
        "compromises the maintainer's account -- publishes tonight. No commit "
        "lands in your repository, no build runs, and nothing in the "
        "configuration changes, so the change is invisible to every control "
        "you already have."
    )
    remediation = (
        "Pin an exact version in the args (`package@1.4.2`), install the "
        "server as a project dependency so a lockfile governs it, or vendor it "
        "and launch from a path. Re-pin deliberately after reviewing a diff."
    )
    frameworks = {
        OWASP_LLM: ["LLM03"],
        MITRE_ATLAS: ["AML.T0010", "AML.T0011"],
        NIST_AI_RMF: ["NIST.GAI.SUPPLY"],
        ISO_42001: ["ISO42001.A.10.2"],
        CWE: ["CWE-494", "CWE-829"],
    }
    tags = ["supply-chain", "pinning"]

    def check(self, ctx: ScanContext) -> Iterable[Finding]:
        for server in _active_servers(ctx):
            prov = _provenance(server)
            issues = prov.get("issues") or []
            auto = "unreviewed_auto_install" in issues
            if not auto and "floating_version" not in issues:
                continue

            yield self.finding(
                server,
                title="Server '%s' resolves %s fresh on every launch"
                % (server.identity, prov.get("package") or "its package"),
                severity=Severity.HIGH if auto else Severity.MEDIUM,
                evidence=[
                    Evidence(label="command", value=_command_line(server)[:300]),
                    Evidence(label="package", value=str(prov.get("package") or "?")),
                    Evidence(
                        label="version",
                        value=str(prov.get("version") or "(none - floating)"),
                    ),
                    Evidence(
                        label="auto-confirm flag present",
                        value="yes" if prov.get("auto_confirm") else "no",
                    ),
                ],
            )


@register
class RemoteCodeAtLaunch(Rule):
    id = "BW-SUP-002"
    title = "Server downloads and executes code at launch"
    severity = Severity.CRITICAL
    confidence = Confidence.HIGH
    category = "supply-chain"
    description = (
        "The launch command pipes downloaded bytes into a shell, runs an "
        "inline program, or installs straight from a URL or moving VCS "
        "reference. There is no artifact to review, no hash to compare and no "
        "version to roll back to: what executes is whatever the remote server "
        "returns at that instant."
    )
    remediation = (
        "Replace with a pinned package or a vendored script committed to the "
        "repository. If the vendor only ships an installer, run it once "
        "manually, review the result, and launch the installed binary by path."
    )
    frameworks = {
        OWASP_LLM: ["LLM03"],
        MITRE_ATLAS: ["AML.T0010", "AML.T0011"],
        NIST_AI_RMF: ["NIST.GAI.SUPPLY"],
        CWE: ["CWE-494", "CWE-829", "CWE-78"],
    }
    tags = ["supply-chain", "rce"]

    WATCHED = {
        "pipe_to_shell": Severity.CRITICAL,
        "url_package": Severity.HIGH,
        "vcs_unpinned": Severity.HIGH,
        "inline_code": Severity.MEDIUM,
    }

    def check(self, ctx: ScanContext) -> Iterable[Finding]:
        for server in _active_servers(ctx):
            prov = _provenance(server)
            notes = prov.get("notes") or {}
            hits = [i for i in (prov.get("issues") or []) if i in self.WATCHED]
            if not hits:
                continue
            yield self.finding(
                server,
                title="Server '%s' fetches executable code at launch" % server.identity,
                severity=max(self.WATCHED[i] for i in hits),
                evidence=[Evidence(label="command", value=_command_line(server)[:300])]
                + [Evidence(label=i, value=str(notes.get(i, i))) for i in hits],
            )


@register
class TyposquatCandidate(Rule):
    id = "BW-SUP-003"
    title = "Package name closely resembles a well-known MCP package"
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    category = "supply-chain"
    description = (
        "The configured package name is within one or two edits of a widely "
        "used package, or borrows a protected publisher scope without being "
        "published under it. Both are the standard shapes of a registry "
        "impersonation attack, and both survive review precisely because the "
        "name looks right."
    )
    remediation = (
        "Confirm the exact package name against the vendor's own "
        "documentation. If the name is genuinely correct, record a waiver so "
        "the finding does not recur."
    )
    frameworks = {
        OWASP_LLM: ["LLM03"],
        MITRE_ATLAS: ["AML.T0010"],
        NIST_AI_RMF: ["NIST.GAI.SUPPLY"],
        CWE: ["CWE-829"],
    }
    tags = ["supply-chain", "typosquat"]

    WATCHED = {"typosquat_candidate", "scope_impersonation"}

    def check(self, ctx: ScanContext) -> Iterable[Finding]:
        for server in _active_servers(ctx):
            prov = _provenance(server)
            notes = prov.get("notes") or {}
            hits = [i for i in (prov.get("issues") or []) if i in self.WATCHED]
            if not hits:
                continue
            yield self.finding(
                server,
                title="Server '%s' uses a look-alike package name" % server.identity,
                evidence=[
                    Evidence(label="package", value=str(prov.get("package") or "?"))
                ]
                + [Evidence(label=i, value=str(notes.get(i, i))) for i in hits],
            )


@register
class InsecureRemoteTransport(Rule):
    id = "BW-SUP-004"
    title = "Remote MCP endpoint is cleartext, unverifiable or ephemeral"
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    category = "supply-chain"
    description = (
        "The server is reached over the network with a transport that cannot "
        "be trusted: plain HTTP, a credential in the query string, a bare IP "
        "with no certificate identity to verify, or a temporary tunnel domain. "
        "An MCP session carries tool definitions inbound and tool arguments "
        "outbound, so whoever can intercept or claim the endpoint can both "
        "read the agent's data and rewrite its instructions."
    )
    remediation = (
        "Use HTTPS with a verifiable hostname. Move credentials into an "
        "Authorization header. Replace tunnel domains with a stable hostname "
        "before this leaves a development machine."
    )
    frameworks = {
        OWASP_LLM: ["LLM02", "LLM03"],
        MITRE_ATLAS: ["AML.T0025"],
        EU_AI_ACT: ["EUAIACT.ART15"],
        CWE: ["CWE-319", "CWE-295", "CWE-598"],
    }
    tags = ["transport", "supply-chain"]

    WATCHED = {
        "cleartext_transport": Severity.HIGH,
        "cleartext_websocket": Severity.HIGH,
        "credential_in_url": Severity.HIGH,
        "ephemeral_tunnel": Severity.MEDIUM,
        "bare_ip_endpoint": Severity.MEDIUM,
        "unknown_scheme": Severity.MEDIUM,
    }

    def check(self, ctx: ScanContext) -> Iterable[Finding]:
        for server in _active_servers(ctx):
            prov = _provenance(server)
            notes = prov.get("notes") or {}
            hits = [i for i in (prov.get("issues") or []) if i in self.WATCHED]
            if not hits:
                continue
            yield self.finding(
                server,
                title="Server '%s' uses an untrustworthy remote transport"
                % server.identity,
                severity=max(self.WATCHED[i] for i in hits),
                evidence=[
                    Evidence(label="endpoint", value=str(server.data.get("url", "")))
                ]
                + [Evidence(label=i, value=str(notes.get(i, i))) for i in hits],
            )


@register
class ContainerIsolationWeakened(Rule):
    id = "BW-SUP-005"
    title = "Containerised server runs with isolation removed or a mutable tag"
    severity = Severity.MEDIUM
    confidence = Confidence.HIGH
    category = "supply-chain"
    description = (
        "Running an MCP server in a container is a good decision that these "
        "flags undo. `--privileged` and `--network=host` return the container "
        "to host-level authority, and a mutable tag such as `:latest` means "
        "the image contents can change without the configuration changing."
    )
    remediation = (
        "Drop `--privileged` and host networking; grant specific capabilities "
        "and publish specific ports instead. Reference the image by digest "
        "(`image@sha256:...`) so the bytes are fixed."
    )
    frameworks = {
        OWASP_LLM: ["LLM03", "LLM06"],
        NIST_AI_RMF: ["NIST.GAI.SUPPLY"],
        CWE: ["CWE-250", "CWE-829"],
    }
    tags = ["container", "supply-chain"]

    WATCHED = {
        "privileged_container": Severity.HIGH,
        "host_network": Severity.MEDIUM,
        "mutable_image_tag": Severity.MEDIUM,
        "implicit_latest_tag": Severity.MEDIUM,
    }

    def check(self, ctx: ScanContext) -> Iterable[Finding]:
        for server in _active_servers(ctx):
            prov = _provenance(server)
            notes = prov.get("notes") or {}
            hits = [i for i in (prov.get("issues") or []) if i in self.WATCHED]
            if not hits:
                continue
            yield self.finding(
                server,
                title="Container for server '%s' is weakly isolated" % server.identity,
                severity=max(self.WATCHED[i] for i in hits),
                evidence=[
                    Evidence(label="image", value=str(prov.get("package") or "?"))
                ]
                + [Evidence(label=i, value=str(notes.get(i, i))) for i in hits],
            )


@register
class UnresolvedBinary(Rule):
    id = "BW-SUP-006"
    title = "Server launches a bare binary resolved from the environment"
    severity = Severity.MEDIUM
    confidence = Confidence.MEDIUM
    category = "supply-chain"
    description = (
        "The command is neither a path nor a recognised package runner, so "
        "what executes depends on the PATH in effect when the agent starts. "
        "Anything that can write to an earlier PATH entry -- an installer, a "
        "shell profile, another tool's shim directory -- can substitute itself "
        "for this server."
    )
    remediation = (
        "Use an absolute path, or launch through a runner that names the "
        "package explicitly."
    )
    frameworks = {OWASP_LLM: ["LLM03"], CWE: ["CWE-829"]}
    tags = ["supply-chain", "path"]

    WATCHED = ("unresolved_binary", "module_from_environment")

    def check(self, ctx: ScanContext) -> Iterable[Finding]:
        for server in _active_servers(ctx):
            prov = _provenance(server)
            issues = prov.get("issues") or []
            notes = prov.get("notes") or {}
            hits = [i for i in self.WATCHED if i in issues]
            if not hits:
                continue
            yield self.finding(
                server,
                title="Server '%s' resolves its executable from the environment"
                % server.identity,
                evidence=[
                    Evidence(
                        label="command", value=str(server.data.get("command", ""))
                    )
                ]
                + [Evidence(label=i, value=str(notes.get(i, i))) for i in hits],
            )
