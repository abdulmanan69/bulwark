"""Rules about credentials, permissions and hooks -- the local blast radius.

Where the supply-chain rules ask "whose code is this", these ask "and what is
it allowed to do once it runs".  Three surfaces, all of which live in ordinary
JSON that nobody security-reviews:

* secrets pasted into a server's ``env`` block;
* permission rules broad enough to authorise anything;
* hooks, which are shell commands the host runs automatically on agent events.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List

from ..analyzers import injection
from ..analyzers import secrets as secretlib
from ..core.frameworks import (
    CWE,
    EU_AI_ACT,
    ISO_42001,
    MITRE_ATLAS,
    NIST_AI_RMF,
    OWASP_LLM,
)
from ..core.models import ArtifactKind, Confidence, Evidence, Finding, Severity
from ..core.rulebase import Rule, ScanContext, register

# --------------------------------------------------------------------------
# Secrets
# --------------------------------------------------------------------------


@register
class PlaintextCredentialInConfig(Rule):
    id = "BW-SEC-001"
    title = "Live credential stored in plaintext in an agent config"
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    category = "secrets"
    description = (
        "A credential is written literally into a configuration file rather "
        "than referenced from the environment or a secret manager. These files "
        "get committed, synced between machines and backed up, and because the "
        "agent can read its own configuration, the credential can also end up "
        "quoted back into a transcript."
    )
    remediation = (
        "Replace the literal with an environment reference (`${VAR}`) or a "
        "secret-manager URI, then rotate the credential -- it should be "
        "treated as disclosed from the moment it was written to disk."
    )
    frameworks = {
        OWASP_LLM: ["LLM02"],
        NIST_AI_RMF: ["NIST.GAI.DATA"],
        ISO_42001: ["ISO42001.A.7.4"],
        CWE: ["CWE-522", "CWE-200"],
    }
    tags = ["secrets", "credentials"]

    def check(self, ctx: ScanContext) -> Iterable[Finding]:
        for server in ctx.of_kind(ArtifactKind.MCP_SERVER):
            blocks: Dict[str, Any] = {}
            env = server.data.get("env")
            if isinstance(env, dict) and env:
                blocks["env"] = env
            headers = server.data.get("headers")
            if isinstance(headers, dict) and headers:
                blocks["headers"] = headers
            args = server.data.get("args")
            if isinstance(args, list) and args:
                blocks["args"] = {str(i): v for i, v in enumerate(args)}

            for block_name, block in blocks.items():
                for hit in secretlib.scan_mapping(block):
                    high = hit.confidence == "high"
                    yield self.finding(
                        server,
                        title="Server '%s' stores a %s in its %s block"
                        % (server.identity, hit.label, block_name),
                        severity=Severity.HIGH if high else Severity.MEDIUM,
                        confidence=Confidence.HIGH if high else Confidence.MEDIUM,
                        evidence=[
                            Evidence(
                                label="field", value="%s.%s" % (block_name, hit.key)
                            ),
                            Evidence(label="value", value=hit.preview),
                            Evidence(label="detector", value=hit.pattern_id),
                            Evidence(label="fingerprint", value=hit.digest),
                        ],
                    )

        for env_file in ctx.of_kind(ArtifactKind.ENV_FILE):
            hits = secretlib.scan_text(env_file.text)
            if not hits:
                continue
            ignored = bool(env_file.data.get("gitignored"))
            yield self.finding(
                env_file,
                title="%s contains %d credential(s)" % (env_file.name, len(hits)),
                severity=Severity.MEDIUM if ignored else Severity.HIGH,
                evidence=[
                    Evidence(label=hit.label, value="%s = %s" % (hit.key, hit.preview))
                    for hit in hits[:8]
                ]
                + [
                    Evidence(
                        label="git-ignored",
                        value="yes" if ignored else "no - at risk of being committed",
                    )
                ],
            )


# --------------------------------------------------------------------------
# Permissions
# --------------------------------------------------------------------------

#: Tools whose unbounded grant is equivalent to handing over the machine.
HIGH_POWER_TOOLS = {
    "bash": "arbitrary shell commands",
    "shell": "arbitrary shell commands",
    "powershell": "arbitrary shell commands",
    "execute": "arbitrary command execution",
    "run": "arbitrary command execution",
    "write": "arbitrary file writes",
    "edit": "arbitrary file edits",
    "multiedit": "arbitrary file edits",
    "notebookedit": "arbitrary notebook edits",
}

#: Argument patterns that authorise something a reader would not expect.
DANGEROUS_ARGUMENTS = (
    (r"rm\s+-[a-z]*[rf]", "recursive or forced deletion", Severity.HIGH),
    (r"\bsudo\b|\bdoas\b", "privilege escalation", Severity.HIGH),
    (r"~[/\\]\.(?:ssh|aws|gnupg|kube)", "access to credential directories", Severity.HIGH),
    (r"\bcurl\b|\bwget\b|\biwr\b", "arbitrary network fetch", Severity.MEDIUM),
    (r"\bchmod\b|\bchown\b|\bicacls\b", "permission changes", Severity.MEDIUM),
    (r"\bgit\s+push\b", "publishing code", Severity.MEDIUM),
    (r"\bdocker\b|\bkubectl\b", "container or cluster control", Severity.MEDIUM),
    (
        r"\bnpm\s+(?:publish|install)\b|\bpip\s+install\b",
        "package installation",
        Severity.MEDIUM,
    ),
    (r"\bprintenv\b", "environment disclosure", Severity.MEDIUM),
)


@register
class OverbroadPermissionRule(Rule):
    id = "BW-PRM-001"
    title = "Permission rule grants a high-power tool without constraint"
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    category = "permissions"
    description = (
        "An allow-rule names a tool that can run commands or write files, but "
        "constrains nothing about how. Once such a rule exists the approval "
        "prompt stops appearing for that tool, which means any instruction the "
        "model follows -- including one injected through content it read -- "
        "executes without a human seeing it first."
    )
    remediation = (
        "Narrow the rule to the specific commands or paths that actually need "
        "to be automatic, for example `Bash(git status:*)` rather than `Bash`. "
        "Keep the unconstrained form out of committed settings entirely."
    )
    frameworks = {
        OWASP_LLM: ["LLM06"],
        MITRE_ATLAS: ["AML.T0011"],
        EU_AI_ACT: ["EUAIACT.ART14"],
        CWE: ["CWE-250", "CWE-269", "CWE-284"],
    }
    tags = ["permissions", "excessive-agency"]

    def check(self, ctx: ScanContext) -> Iterable[Finding]:
        for rule in ctx.of_kind(ArtifactKind.PERMISSION_RULE):
            if rule.data.get("effect") != "allow":
                continue
            if rule.data.get("wildcard") != "unbounded":
                continue
            tool = str(rule.data.get("tool", "")).strip().lower()
            power = HIGH_POWER_TOOLS.get(tool)

            if power:
                yield self.finding(
                    rule,
                    title="Allow-rule `%s` permits %s with no constraint"
                    % (rule.name, power),
                    severity=Severity.HIGH,
                    evidence=[
                        Evidence(label="rule", value=rule.name),
                        Evidence(label="scope", value=str(rule.data.get("scope", ""))),
                        Evidence(label="breadth", value="unbounded"),
                    ],
                )
            else:
                yield self.finding(
                    rule,
                    title="Allow-rule `%s` is unbounded" % rule.name,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    evidence=[
                        Evidence(label="rule", value=rule.name),
                        Evidence(
                            label="why",
                            value="the argument matches everything the tool can reach",
                        ),
                    ],
                )


@register
class DangerousPermissionArgument(Rule):
    id = "BW-PRM-002"
    title = "Permission rule pre-approves a dangerous operation"
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    category = "permissions"
    description = (
        "The allow-rule's argument authorises an operation that is destructive, "
        "escalates privilege, reaches credentials, or publishes data. These are "
        "precisely the operations a human should be asked about, and the rule "
        "removes the asking."
    )
    remediation = (
        "Delete the rule. If the operation genuinely needs to be automatic, "
        "wrap it in a script with its own checks and allow only that script."
    )
    frameworks = {
        OWASP_LLM: ["LLM06", "LLM02"],
        MITRE_ATLAS: ["AML.T0011"],
        EU_AI_ACT: ["EUAIACT.ART14"],
        CWE: ["CWE-250", "CWE-269", "CWE-78"],
    }
    tags = ["permissions", "excessive-agency"]

    def check(self, ctx: ScanContext) -> Iterable[Finding]:
        for rule in ctx.of_kind(ArtifactKind.PERMISSION_RULE):
            if rule.data.get("effect") != "allow":
                continue
            argument = str(rule.data.get("argument", ""))
            if not argument:
                continue
            for pattern, label, severity in DANGEROUS_ARGUMENTS:
                if re.search(pattern, argument, re.IGNORECASE):
                    yield self.finding(
                        rule,
                        title="Allow-rule `%s` pre-approves %s" % (rule.name, label),
                        severity=severity,
                        evidence=[
                            Evidence(label="rule", value=rule.name),
                            Evidence(label="authorises", value=label),
                            Evidence(
                                label="scope", value=str(rule.data.get("scope", ""))
                            ),
                        ],
                    )
                    break


@register
class PermissionPromptDisabled(Rule):
    id = "BW-PRM-003"
    title = "Settings disable the human approval step"
    severity = Severity.CRITICAL
    confidence = Confidence.HIGH
    category = "permissions"
    description = (
        "A settings flag or default mode removes the confirmation prompt for "
        "tool calls. Every other control in an agent stack assumes a human is "
        "the last check before an irreversible action; this setting deletes "
        "that check globally, for every tool, including ones added later."
    )
    remediation = (
        "Remove the flag from committed settings. If a sandboxed CI run truly "
        "needs it, set it there via an environment variable on the runner, "
        "never in a file that a developer machine also reads."
    )
    frameworks = {
        OWASP_LLM: ["LLM06"],
        EU_AI_ACT: ["EUAIACT.ART14"],
        NIST_AI_RMF: ["NIST.GAI.HUMAN"],
        CWE: ["CWE-250", "CWE-284"],
    }
    tags = ["permissions", "human-oversight"]

    def check(self, ctx: ScanContext) -> Iterable[Finding]:
        for settings in ctx.of_kind(ArtifactKind.SETTINGS):
            flags = settings.data.get("risky_flags")
            if not isinstance(flags, dict) or not flags:
                continue
            critical = any(
                key.startswith("defaultMode=") or "Permission" in key or key == "yolo"
                for key in flags
            )
            yield self.finding(
                settings,
                title="%s weakens or disables approval prompts" % settings.name,
                severity=Severity.CRITICAL if critical else Severity.HIGH,
                evidence=[
                    Evidence(label=key, value=explanation)
                    for key, explanation in sorted(flags.items())
                ],
            )


# --------------------------------------------------------------------------
# Hooks
# --------------------------------------------------------------------------

#: Hook events that fire without the user doing anything deliberate.
AMBIENT_EVENTS = {
    "sessionstart", "userpromptsubmit", "pretooluse", "posttooluse",
    "notification", "stop", "subagentstop", "precompact", "sessionend",
}

DANGEROUS_HOOK_PATTERNS = (
    (
        r"\|\s*(?:ba|z|k)?sh\b|\|\s*(?:iex|invoke-expression)\b",
        "pipes downloaded content into a shell",
        Severity.CRITICAL,
    ),
    (
        r"(?:~|\$HOME|%USERPROFILE%)?[/\\]?\.(?:ssh|aws|gnupg|kube|npmrc|netrc)\b",
        "reads a credential directory",
        Severity.CRITICAL,
    ),
    (
        r"(?:curl|wget|iwr|invoke-webrequest)\b",
        "makes an outbound network request",
        Severity.HIGH,
    ),
    (
        r"\b(?:cat|type|Get-Content)\b[^|;&]{0,40}\.env\b",
        "reads a .env file",
        Severity.HIGH,
    ),
    (
        r"\b(?:printenv|Get-ChildItem\s+Env:)\b",
        "dumps the environment",
        Severity.HIGH,
    ),
    (
        r"\brm\s+-[a-z]*[rf]|\bRemove-Item\b[^|;&]*-Recurse",
        "deletes files recursively",
        Severity.HIGH,
    ),
    (r"\b(?:nc|ncat|netcat|socat)\b", "opens a raw network connection", Severity.HIGH),
    (
        r"\bsudo\b|\bdoas\b|\bStart-Process\b[^|;&]*-Verb\s+RunAs",
        "escalates privilege",
        Severity.HIGH,
    ),
    (r"\bgit\s+push\b", "publishes code automatically", Severity.MEDIUM),
    (r"\bbase64\b|\bFromBase64String\b", "encodes or decodes data inline", Severity.MEDIUM),
)


@register
class DangerousHook(Rule):
    id = "BW-HOOK-001"
    title = "Hook executes a dangerous command automatically"
    severity = Severity.CRITICAL
    confidence = Confidence.HIGH
    category = "hooks"
    description = (
        "A hook is a shell command the host runs on its own when an agent "
        "event fires -- no model decision, no approval prompt, no tool-call "
        "record. That makes hooks the highest-privilege extension point in the "
        "stack, and this one performs an action that would be alarming even "
        "with a human in the loop."
    )
    remediation = (
        "Review who added the hook and why. Replace ad-hoc commands with a "
        "reviewed script committed to the repository, and treat any hook that "
        "reads credentials or calls out to the network as an incident until "
        "proven otherwise."
    )
    frameworks = {
        OWASP_LLM: ["LLM06", "LLM02"],
        MITRE_ATLAS: ["AML.T0011", "AML.T0025"],
        NIST_AI_RMF: ["NIST.GAI.INFO"],
        CWE: ["CWE-78", "CWE-77", "CWE-200"],
    }
    tags = ["hooks", "rce"]

    def check(self, ctx: ScanContext) -> Iterable[Finding]:
        for hook in ctx.of_kind(ArtifactKind.HOOK):
            command = hook.text or ""
            if not command:
                continue
            matches: List[Evidence] = []
            severity = Severity.INFO
            for pattern, label, level in DANGEROUS_HOOK_PATTERNS:
                if re.search(pattern, command, re.IGNORECASE):
                    matches.append(Evidence(label=label, value=pattern))
                    severity = max(severity, level)
            if not matches:
                continue

            event = str(hook.data.get("event", "")).lower()
            ambient = event in AMBIENT_EVENTS
            if ambient and severity >= Severity.HIGH:
                severity = Severity.CRITICAL

            yield self.finding(
                hook,
                title="Hook on %s runs a dangerous command" % hook.name,
                severity=severity,
                evidence=[
                    Evidence(label="command", value=command[:300]),
                    Evidence(
                        label="trigger",
                        value="%s (%s)"
                        % (
                            hook.data.get("event", "?"),
                            "fires automatically" if ambient else "fires on demand",
                        ),
                    ),
                    *matches,
                ],
            )


@register
class HookInjectsUntrustedInput(Rule):
    id = "BW-HOOK-002"
    title = "Hook interpolates agent-controlled data into a shell command"
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    category = "hooks"
    description = (
        "The hook command substitutes a variable that carries model or "
        "user-supplied text -- a prompt, a file path, a tool argument -- "
        "directly into a shell. Shell metacharacters in that text become part "
        "of the command, which turns any content the agent reads into a "
        "potential command-injection vector."
    )
    remediation = (
        "Read hook input from stdin as JSON inside a script rather than "
        "interpolating it into the command string, and quote every expansion. "
        "Never build a shell command by concatenating agent-supplied text."
    )
    frameworks = {
        OWASP_LLM: ["LLM01", "LLM05"],
        MITRE_ATLAS: ["AML.T0051"],
        CWE: ["CWE-77", "CWE-78"],
    }
    tags = ["hooks", "injection"]

    #: Variables the host populates from model or user text.
    TAINTED = re.compile(
        r"\$\{?(?:CLAUDE_|AGENT_|TOOL_|USER_)[A-Z_]*\}?"
        r"|\$\{?(?:PROMPT|FILE_PATH|TOOL_INPUT|TOOL_ARGS|MESSAGE|ARGUMENTS)\}?"
        r"|%(?:CLAUDE_|AGENT_|TOOL_)[A-Z_]*%",
        re.IGNORECASE,
    )

    def check(self, ctx: ScanContext) -> Iterable[Finding]:
        for hook in ctx.of_kind(ArtifactKind.HOOK):
            command = hook.text or ""
            found = self.TAINTED.findall(command)
            if not found:
                continue
            quoted = re.search(
                r"[\"'][^\"']*\$\{?(?:CLAUDE_|TOOL_|AGENT_|USER_)", command
            )
            yield self.finding(
                hook,
                title="Hook on %s interpolates agent-controlled data" % hook.name,
                severity=Severity.MEDIUM if quoted else Severity.HIGH,
                evidence=[
                    Evidence(label="command", value=command[:300]),
                    Evidence(
                        label="interpolated", value=", ".join(sorted(set(found))[:6])
                    ),
                    Evidence(
                        label="quoting",
                        value=(
                            "expansion appears quoted"
                            if quoted
                            else "expansion is unquoted"
                        ),
                    ),
                ],
            )


@register
class InstructionFileInjection(Rule):
    id = "BW-HOOK-003"
    title = "Persistent instruction file contains an injected directive"
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    category = "hooks"
    description = (
        "A rules or memory file (CLAUDE.md, AGENTS.md, .cursorrules and "
        "equivalents) contains text that reads as an attack on the agent "
        "rather than as project guidance. These files load into every session "
        "automatically and are edited through ordinary pull requests, so they "
        "are the most durable place to leave an instruction and the least "
        "likely to be security-reviewed."
    )
    remediation = (
        "Treat instruction files as security-relevant code: require review on "
        "changes, and diff them in CI with `bulwark scan --fail-on high`."
    )
    frameworks = {
        OWASP_LLM: ["LLM01", "LLM04"],
        MITRE_ATLAS: ["AML.T0051", "AML.T0031"],
        CWE: ["CWE-94"],
    }
    tags = ["rules-file", "prompt-injection", "persistence"]

    def check(self, ctx: ScanContext) -> Iterable[Finding]:
        for artifact in ctx.of_kind(ArtifactKind.SKILL):
            if "rules" not in artifact.tags and "cursor-rule" not in artifact.tags:
                continue
            report = injection.scan(artifact.text or "")
            if not report.triggered:
                continue
            malicious = report.verdict() in {"smuggled", "malicious"}
            yield self.finding(
                artifact,
                title="Instruction file %s contains directives aimed at the agent"
                % artifact.name,
                severity=Severity.CRITICAL if malicious else Severity.HIGH,
                evidence=[
                    Evidence(
                        label="verdict",
                        value="%s (families: %s)"
                        % (report.verdict(), ", ".join(report.families)),
                    )
                ]
                + [
                    Evidence(label=s.pattern_id, value=s.matched)
                    for s in report.signals[:6]
                ],
            )
