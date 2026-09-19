"""Rules that compare the present against a pinned past.

A rug pull leaves no trace in a configuration file, so no amount of config
review detects it.  The only evidence is that a string changed after it was
approved, which means detection requires having recorded the approved state.

These rules read the change list the engine computes from ``bulwark.lock``.
The absence of a lockfile is itself worth reporting, which is what
:class:`NoLockfile` does.
"""

from __future__ import annotations

from typing import Iterable, List

from ..core.frameworks import CWE, ISO_42001, MITRE_ATLAS, NIST_AI_RMF, OWASP_LLM
from ..core.models import ArtifactKind, Confidence, Evidence, Finding, Severity
from ..core.rulebase import Rule, ScanContext, register


@register
class ToolDefinitionDrift(Rule):
    id = "BW-DRF-001"
    title = "Tool definition changed after it was pinned"
    severity = Severity.CRITICAL
    confidence = Confidence.HIGH
    category = "drift"
    description = (
        "A model-visible string differs from the version recorded in "
        "bulwark.lock. The configuration did not change, so nothing in code "
        "review or version control would show this: the server simply returned "
        "different text on the next connection. That is the rug pull -- behave "
        "correctly while being evaluated, change afterwards -- and it is the "
        "single failure mode that static configuration review cannot detect by "
        "construction."
    )
    remediation = (
        "Do not re-pin until the change is explained. Compare the before and "
        "after text, check the upstream release notes for a version that "
        "matches, and if there is no published change that accounts for it, "
        "disconnect the server. Once satisfied, `bulwark pin` records the new "
        "state deliberately."
    )
    frameworks = {
        OWASP_LLM: ["LLM01", "LLM03", "LLM04"],
        MITRE_ATLAS: ["AML.T0053", "AML.T0031"],
        NIST_AI_RMF: ["NIST.GAI.SUPPLY"],
        ISO_42001: ["ISO42001.A.6.2.4"],
        CWE: ["CWE-345", "CWE-494"],
    }
    tags = ["drift", "rug-pull", "supply-chain"]

    SEVERITY_BY_CHANGE = {
        "text_changed": Severity.CRITICAL,
        "capability_added": Severity.CRITICAL,
        "schema_changed": Severity.HIGH,
        "trust_lowered": Severity.HIGH,
        "added": Severity.HIGH,
        "metadata_changed": Severity.MEDIUM,
        "capability_removed": Severity.LOW,
        "removed": Severity.LOW,
    }

    def check(self, ctx: ScanContext) -> Iterable[Finding]:
        changes = ctx.shared.get("lock_changes")
        if not changes:
            return

        for change in changes:
            severity = self.SEVERITY_BY_CHANGE.get(change.kind, Severity.MEDIUM)
            artifact = ctx.by_identity(change.identity)

            evidence: List[Evidence] = [
                Evidence(
                    label="change", value="%s -- %s" % (change.kind, change.detail)
                )
            ]
            if change.before:
                evidence.append(Evidence(label="pinned", value=change.before[:300]))
            if change.after:
                evidence.append(Evidence(label="now", value=change.after[:300]))

            yield self.finding(
                artifact,
                title="%s %s changed since it was pinned"
                % (change.artifact_kind.replace("_", " "), change.identity),
                severity=severity,
                confidence=Confidence.HIGH if change.weight >= 3 else Confidence.MEDIUM,
                evidence=evidence,
                extra_tags=["change:" + change.kind],
            )


@register
class NoLockfile(Rule):
    id = "BW-DRF-002"
    title = "No lockfile, so tool definitions are unverifiable"
    severity = Severity.MEDIUM
    confidence = Confidence.HIGH
    category = "drift"
    description = (
        "There is no bulwark.lock recording what the connected servers were "
        "approved to say. Without it, a server can change its tool "
        "descriptions at any point after review and nothing will notice: there "
        "is no prior state to compare against. This is the agent-stack "
        "equivalent of installing dependencies with no lockfile, except that "
        "the thing that changes is an instruction to a model rather than a "
        "function body."
    )
    remediation = (
        "Run `bulwark pin` once the current configuration has been reviewed, "
        "commit bulwark.lock, and add `bulwark verify` to CI so any later "
        "change has to be approved in a pull request."
    )
    frameworks = {
        OWASP_LLM: ["LLM03"],
        NIST_AI_RMF: ["NIST.GAI.SUPPLY"],
        ISO_42001: ["ISO42001.A.6.2.4"],
        CWE: ["CWE-345"],
    }
    tags = ["drift", "hygiene"]

    def check(self, ctx: ScanContext) -> Iterable[Finding]:
        if ctx.lock:
            return
        pinnable = ctx.of_kind(
            ArtifactKind.MCP_SERVER, ArtifactKind.MCP_TOOL, ArtifactKind.SKILL
        )
        if not pinnable:
            return
        yield self.finding(
            None,
            evidence=[
                Evidence(
                    label="unpinned artifacts",
                    value="%d server/tool/skill definitions have no recorded baseline"
                    % len(pinnable),
                ),
                Evidence(label="fix", value="bulwark pin"),
            ],
        )
