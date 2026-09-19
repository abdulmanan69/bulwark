"""Rules for text that reaches the model.

Every artifact in :meth:`ScanContext.model_visible` contributes text to a
context window.  These rules ask one question of that text: is it describing a
capability, or is it issuing an instruction?
"""

from __future__ import annotations

from typing import Iterable, List

from ..analyzers import injection
from ..analyzers import text as textlib
from ..core.frameworks import CWE, MITRE_ATLAS, NIST_AI_RMF, OWASP_LLM
from ..core.models import Artifact, Confidence, Evidence, Finding, Severity
from ..core.rulebase import Rule, ScanContext, register


def _describe_artifact(artifact: Artifact) -> str:
    return "%s %s" % (artifact.kind.value.replace("_", " "), artifact.identity)


@register
class ToolPoisoning(Rule):
    id = "BW-INJ-001"
    title = "Tool description contains instructions aimed at the model"
    severity = Severity.CRITICAL
    confidence = Confidence.HIGH
    category = "injection"
    description = (
        "A tool description is documentation: it tells the model what a tool "
        "does so the model can decide whether to call it. This description "
        "instead issues directives -- overriding prior instructions, "
        "concealing behaviour from the user, naming credentials, or specifying "
        "where to send data. Because descriptions are loaded into context "
        "before any tool is called, the instruction executes as soon as the "
        "server is connected, whether or not the tool is ever used."
    )
    remediation = (
        "Do not connect this server until the description is explained. "
        "Pin the server to a reviewed version, diff the tool definitions "
        "against that pin with `bulwark diff`, and run the server behind "
        "`bulwark proxy` so description changes are caught at runtime."
    )
    frameworks = {
        OWASP_LLM: ["LLM01", "LLM06"],
        MITRE_ATLAS: ["AML.T0051", "AML.T0053"],
        NIST_AI_RMF: ["NIST.GAI.INFO"],
        CWE: ["CWE-77", "CWE-829"],
    }
    references = [
        "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        "https://atlas.mitre.org/techniques/AML.T0051",
    ]
    tags = ["tool-poisoning", "prompt-injection"]

    def check(self, ctx: ScanContext) -> Iterable[Finding]:
        custom = injection.compile_custom(ctx.settings.get("injection_patterns", []))
        for artifact in ctx.model_visible():
            if not artifact.text:
                continue
            report = injection.scan(artifact.text, custom)
            if not report.triggered:
                continue

            verdict = report.verdict()
            severity = {
                "smuggled": Severity.CRITICAL,
                "malicious": Severity.CRITICAL,
                "suspicious": Severity.HIGH,
            }.get(verdict, Severity.MEDIUM)

            evidence: List[Evidence] = [
                Evidence(
                    label="verdict",
                    value="%s (score %.1f across %d signal families)"
                    % (verdict, report.score, len(report.families)),
                )
            ]
            for signal in report.signals[:8]:
                suffix = " [HIDDEN CHANNEL]" if signal.channel == "hidden" else ""
                evidence.append(
                    Evidence(
                        label="%s/%s%s" % (signal.family, signal.pattern_id, suffix),
                        value="%s -- %s" % (signal.matched, signal.note),
                    )
                )

            yield self.finding(
                artifact,
                title="%s carries model-directed instructions"
                % _describe_artifact(artifact),
                severity=severity,
                confidence=(
                    Confidence.HIGH
                    if verdict in {"smuggled", "malicious"}
                    else Confidence.MEDIUM
                ),
                evidence=evidence,
                extra_tags=["verdict:" + verdict],
            )


@register
class HiddenUnicodePayload(Rule):
    id = "BW-INJ-002"
    title = "Model-visible text hides characters a reviewer cannot see"
    severity = Severity.CRITICAL
    confidence = Confidence.HIGH
    category = "injection"
    description = (
        "The text contains codepoints that render as nothing -- Unicode Tag "
        "characters, zero-width spaces, bidirectional overrides, variation "
        "selectors or private-use characters. The model receives every one of "
        "them; a human reviewing the same string in an editor or a marketplace "
        "listing does not. There is no legitimate reason for a tool "
        "description to contain them, and the Unicode Tag block in particular "
        "maps one-to-one onto ASCII, so it can carry an entire hidden "
        "instruction inside a string that looks empty."
    )
    remediation = (
        "Treat the artifact as compromised. Strip the invisible codepoints and "
        "compare what remains against what the publisher claims the tool does. "
        "Reject any component whose description needs invisible characters."
    )
    frameworks = {
        OWASP_LLM: ["LLM01"],
        MITRE_ATLAS: ["AML.T0051"],
        CWE: ["CWE-94", "CWE-345"],
    }
    tags = ["unicode", "steganography", "prompt-injection"]

    #: Kinds that carry a payload rather than merely being unusual.
    PAYLOAD_KINDS = {
        "tag_block": Severity.CRITICAL,
        "tag_block_payload": Severity.CRITICAL,
        "bidi_control": Severity.HIGH,
        "private_use": Severity.HIGH,
        "variation_selector": Severity.MEDIUM,
        "zero_width": Severity.MEDIUM,
        "control_char": Severity.MEDIUM,
    }

    def check(self, ctx: ScanContext) -> Iterable[Finding]:
        for artifact in ctx.model_visible():
            if not artifact.text:
                continue
            observations = [
                obs
                for obs in textlib.find_invisible(artifact.text)
                if obs.kind in self.PAYLOAD_KINDS
            ]
            if not observations:
                continue

            severity = max(self.PAYLOAD_KINDS[obs.kind] for obs in observations)
            evidence = [
                Evidence(
                    label=obs.kind,
                    value="%d occurrence(s): %s" % (obs.count, obs.detail),
                )
                for obs in observations
            ]

            decoded = textlib.decode_tag_block(artifact.text)
            if decoded:
                evidence.insert(
                    0, Evidence(label="recovered hidden text", value=decoded[:300])
                )
            evidence.append(
                Evidence(
                    label="what a reviewer sees",
                    value=textlib.visible_text(artifact.text)[:200],
                )
            )

            yield self.finding(
                artifact,
                title="%s contains invisible characters" % _describe_artifact(artifact),
                severity=severity,
                evidence=evidence,
            )


@register
class HiddenMarkupPayload(Rule):
    id = "BW-INJ-003"
    title = "Instructions concealed in markup or layout padding"
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    category = "injection"
    description = (
        "The text hides content using HTML comments, CSS that renders an "
        "element invisible, or whitespace padding that pushes the payload "
        "outside a reviewer's viewport. The model reads the raw string, so "
        "none of these mechanisms hide anything from it -- they hide it only "
        "from the person approving the component."
    )
    remediation = (
        "Remove the concealed content, or reject the component. A description "
        "that needs an HTML comment is describing something it does not want "
        "reviewed."
    )
    frameworks = {
        OWASP_LLM: ["LLM01"],
        MITRE_ATLAS: ["AML.T0051"],
        CWE: ["CWE-94"],
    }
    tags = ["prompt-injection", "concealment"]

    CONCEALING = {"html_comment", "hidden_markup", "blank_padding", "space_padding"}

    def check(self, ctx: ScanContext) -> Iterable[Finding]:
        for artifact in ctx.model_visible():
            if not artifact.text:
                continue
            observations = textlib.find_hidden_markup(artifact.text)
            observations.extend(textlib.find_layout_evasion(artifact.text))

            # A long line in a rules file is prose, not an attack.  Require a
            # concealment mechanism, not merely an unusual shape.
            concealing = [obs for obs in observations if obs.kind in self.CONCEALING]
            if not concealing:
                continue

            evidence = [
                Evidence(label=obs.kind, value=(obs.sample or obs.detail)[:300])
                for obs in concealing
            ]

            # Concealed text that is *also* an instruction is a different
            # severity to a stray comment, so re-score the hidden part alone.
            hidden_text = " ".join(obs.sample for obs in concealing if obs.sample)
            report = injection.scan(hidden_text)
            if report.signals:
                evidence.append(
                    Evidence(
                        label="concealed text scores as injection",
                        value="%s (families: %s)"
                        % (report.verdict(), ", ".join(report.families)),
                    )
                )

            yield self.finding(
                artifact,
                title="%s conceals content from reviewers"
                % _describe_artifact(artifact),
                severity=Severity.CRITICAL if report.triggered else Severity.MEDIUM,
                confidence=Confidence.HIGH if report.triggered else Confidence.MEDIUM,
                evidence=evidence,
            )


@register
class EncodedPayload(Rule):
    id = "BW-INJ-004"
    title = "Encoded payload embedded in model-visible text"
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    category = "injection"
    description = (
        "A base64 or hex blob in the text decodes to readable prose. Encoding "
        "prose serves no functional purpose in a description -- it defeats "
        "keyword review while remaining perfectly legible to a model that is "
        "asked to decode it."
    )
    remediation = (
        "Decode the blob and judge the plaintext. If it reads as an "
        "instruction, treat the component as hostile."
    )
    frameworks = {
        OWASP_LLM: ["LLM01"],
        MITRE_ATLAS: ["AML.T0051"],
        CWE: ["CWE-94"],
    }
    tags = ["prompt-injection", "obfuscation"]

    def check(self, ctx: ScanContext) -> Iterable[Finding]:
        for artifact in ctx.model_visible():
            if not artifact.text:
                continue
            observations = textlib.find_encoded_payloads(artifact.text)
            if not observations:
                continue

            evidence: List[Evidence] = []
            escalate = False
            for obs in observations[:4]:
                evidence.append(Evidence(label=obs.kind, value=obs.sample[:300]))
                if injection.scan(obs.sample).triggered:
                    escalate = True

            if escalate:
                evidence.append(
                    Evidence(
                        label="decoded content scores as injection",
                        value="the plaintext matches instruction-override patterns",
                    )
                )

            yield self.finding(
                artifact,
                title="%s embeds an encoded payload" % _describe_artifact(artifact),
                severity=Severity.CRITICAL if escalate else Severity.MEDIUM,
                confidence=Confidence.HIGH if escalate else Confidence.LOW,
                evidence=evidence,
            )


@register
class ExfiltrationChannelInText(Rule):
    id = "BW-INJ-005"
    title = "Model-visible text names an out-of-band collection endpoint"
    severity = Severity.CRITICAL
    confidence = Confidence.HIGH
    category = "injection"
    description = (
        "The text references a request-capture service (webhook.site, "
        "interact.sh, a tunnelling domain) or a markdown image whose URL "
        "carries a query string. A markdown image is fetched when the response "
        "renders, so a URL of the form https://host/?q=DATA exfiltrates "
        "whatever the model substitutes for DATA with no tool call, no "
        "approval prompt, and nothing visible in the transcript but a broken "
        "image."
    )
    remediation = (
        "Remove the endpoint. If the component genuinely needs to call out, "
        "the destination belongs in configuration where it can be allow-listed "
        "and logged, not in text the model reads as an instruction."
    )
    frameworks = {
        OWASP_LLM: ["LLM01", "LLM02"],
        MITRE_ATLAS: ["AML.T0024", "AML.T0025"],
        NIST_AI_RMF: ["NIST.GAI.DATA"],
        CWE: ["CWE-200", "CWE-598"],
    }
    tags = ["exfiltration", "prompt-injection"]

    WATCHED = {"INJ.EXFIL.WEBHOOK", "INJ.EXFIL.MDIMAGE", "INJ.EXFIL.MDLINK"}

    def check(self, ctx: ScanContext) -> Iterable[Finding]:
        for artifact in ctx.model_visible():
            if not artifact.text:
                continue
            report = injection.scan(artifact.text)
            hits = [s for s in report.signals if s.pattern_id in self.WATCHED]
            if not hits:
                continue
            yield self.finding(
                artifact,
                title="%s names an exfiltration endpoint" % _describe_artifact(artifact),
                evidence=[
                    Evidence(label=s.pattern_id, value="%s -- %s" % (s.matched, s.note))
                    for s in hits
                ],
            )
