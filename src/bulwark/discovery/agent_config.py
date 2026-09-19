"""Discover the agent surfaces that are not MCP servers.

MCP gets the attention, but a coding agent's blast radius is set just as much
by four other things, and nothing inventories them:

* **Permission rules** -- what the agent may run without asking.
* **Hooks** -- shell commands the host executes automatically on agent events.
  A hook is unconditional code execution triggered by model behaviour, which
  makes it the highest-privilege extension point of the lot.
* **Skills, subagents and slash commands** -- markdown whose body is loaded
  straight into the model's context, and which frequently arrives by git clone.
* **Rules / memory files** -- ``CLAUDE.md``, ``AGENTS.md``, ``.cursorrules``
  and friends: persistent instructions that survive every session and are
  edited by anyone who can open a pull request.

All five are prompt-injection sinks or privilege grants, and all five are
treated here as first-class artifacts.
"""

from __future__ import annotations

import os
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from ..core.models import Artifact, ArtifactKind, SourceRef
from .base import (
    CollectionResult,
    Collector,
    app_data_dirs,
    existing,
    is_world_readable,
    iter_files,
    load_json_file,
    read_text,
    source_for,
    split_front_matter,
)

#: Persistent-instruction files, by convention across hosts.
RULES_FILES = (
    "CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", "AGENT.md", ".cursorrules",
    ".windsurfrules", ".clinerules", "GEMINI.md", "QWEN.md",
)

#: Settings keys that widen what the agent may do without asking.
RISKY_SETTINGS = {
    "dangerouslySkipPermissions": "disables the permission prompt entirely",
    "bypassPermissions": "disables the permission prompt entirely",
    "enableAllProjectMcpServers": "auto-enables every MCP server a project declares",
    "autoApprove": "pre-approves tool calls",
    "yolo": "disables confirmations",
    "autoAcceptEdits": "applies file edits without review",
}

#: Permission-mode values that remove the human from the loop.
UNSAFE_MODES = {
    "bypasspermissions": "every tool call is auto-approved",
    "dangerouslyskippermissions": "every tool call is auto-approved",
    "acceptedits": "file edits apply without review",
    "auto": "tool calls are auto-approved",
    "yolo": "every tool call is auto-approved",
}


class AgentConfigCollector(Collector):
    """Collects settings, hooks, permissions, skills, subagents and rules."""

    name = "agent-config"

    def collect(self, roots: Sequence[str], home: str) -> CollectionResult:
        result = CollectionResult()
        dirs = app_data_dirs(home)

        settings_files: List[Tuple[str, str]] = [
            (os.path.join(home, ".claude", "settings.json"), "user"),
            (os.path.join(home, ".claude", "settings.local.json"), "user"),
            (os.path.join(home, ".codex", "config.json"), "user"),
            (os.path.join(dirs["xdg_config"], "opencode", "config.json"), "user"),
        ]
        agent_dirs: List[Tuple[str, str]] = [(os.path.join(home, ".claude"), "user")]

        for root in roots:
            settings_files.append((os.path.join(root, ".claude", "settings.json"), "project"))
            settings_files.append(
                (os.path.join(root, ".claude", "settings.local.json"), "local")
            )
            agent_dirs.append((os.path.join(root, ".claude"), "project"))

        for path, scope in settings_files:
            if os.path.isfile(path):
                self._collect_settings(path, scope, result)

        for directory, scope in agent_dirs:
            if os.path.isdir(directory):
                self._collect_markdown_surfaces(directory, scope, result)

        for root in roots:
            self._collect_rules_files(root, result)
            self._collect_cursor_rules(root, result)
            self._collect_env_files(root, result)

        return result

    # ---- settings.json ---------------------------------------------------

    def _collect_settings(self, path: str, scope: str, result: CollectionResult) -> None:
        data = load_json_file(path, result)
        if not isinstance(data, dict):
            return
        text = read_text(path) or ""

        result.artifacts.append(
            Artifact(
                kind=ArtifactKind.SETTINGS,
                identity="settings:" + path,
                name=os.path.basename(path),
                platform="claude-code",
                source=SourceRef(path=path),
                data={
                    "scope": scope,
                    "world_readable": is_world_readable(path),
                    "risky_flags": _risky_flags(data),
                    "raw": data,
                },
                tags=["settings", scope],
            )
        )

        result.artifacts.extend(_permission_artifacts(data, path, text, scope))
        result.artifacts.extend(_hook_artifacts(data, path, text, scope))

    # ---- markdown surfaces ------------------------------------------------

    def _collect_markdown_surfaces(
        self, directory: str, scope: str, result: CollectionResult
    ) -> None:
        specs = (
            ("skills", ArtifactKind.SKILL, "skill"),
            ("agents", ArtifactKind.SUBAGENT, "subagent"),
            ("commands", ArtifactKind.SLASH_COMMAND, "slash-command"),
        )
        for folder, kind, tag in specs:
            base = os.path.join(directory, folder)
            if not os.path.isdir(base):
                continue
            for path in iter_files(base, ["*.md", "*.markdown", "*.mdc"], max_depth=4):
                artifact = _markdown_artifact(path, kind, tag, scope)
                if artifact is not None:
                    result.files_seen.append(path)
                    result.artifacts.append(artifact)

    # ---- rules / memory files ---------------------------------------------

    def _collect_rules_files(self, root: str, result: CollectionResult) -> None:
        for name in RULES_FILES:
            path = os.path.join(root, name)
            if not os.path.isfile(path):
                continue
            text = read_text(path)
            if text is None:
                continue
            result.files_seen.append(path)
            result.artifacts.append(
                Artifact(
                    kind=ArtifactKind.SKILL,
                    identity="rules:" + name,
                    name=name,
                    platform="agent-rules",
                    source=SourceRef(path=path),
                    text=text,
                    data={"kind": "persistent-instructions", "bytes": len(text)},
                    tags=["rules", "persistent-context"],
                )
            )

    def _collect_cursor_rules(self, root: str, result: CollectionResult) -> None:
        base = os.path.join(root, ".cursor", "rules")
        if not os.path.isdir(base):
            return
        for path in iter_files(base, ["*.mdc", "*.md"], max_depth=3):
            artifact = _markdown_artifact(
                path, ArtifactKind.SKILL, "cursor-rule", "project"
            )
            if artifact is not None:
                result.files_seen.append(path)
                result.artifacts.append(artifact)

    # ---- .env -------------------------------------------------------------

    def _collect_env_files(self, root: str, result: CollectionResult) -> None:
        names = (".env", ".env.local", ".env.development", ".env.production")
        for path in existing(*[os.path.join(root, name) for name in names]):
            text = read_text(path)
            if text is None:
                continue
            result.files_seen.append(path)
            result.artifacts.append(
                Artifact(
                    kind=ArtifactKind.ENV_FILE,
                    identity="env:" + os.path.basename(path),
                    name=os.path.basename(path),
                    platform="project",
                    source=SourceRef(path=path),
                    text=text,
                    data={
                        "world_readable": is_world_readable(path),
                        "gitignored": _is_probably_ignored(root, path),
                    },
                    tags=["env"],
                )
            )


# --------------------------------------------------------------------------
# Settings decomposition
# --------------------------------------------------------------------------


def _risky_flags(data: Dict[str, Any]) -> Dict[str, str]:
    """Collect the boolean switches that widen the agent's authority."""
    found: Dict[str, str] = {}
    for key, explanation in RISKY_SETTINGS.items():
        if data.get(key) is True:
            found[key] = explanation

    permissions = data.get("permissions")
    raw_mode = (
        permissions.get("defaultMode")
        if isinstance(permissions, dict)
        else data.get("defaultMode")
    )
    mode = str(raw_mode or "")
    normalised = mode.lower().replace("_", "").replace("-", "")
    if normalised in UNSAFE_MODES:
        found["defaultMode=" + mode] = UNSAFE_MODES[normalised]
    return found


def _permission_artifacts(
    data: Dict[str, Any], path: str, text: str, scope: str
) -> List[Artifact]:
    """One artifact per permission rule, so each can be judged individually."""
    permissions = data.get("permissions")
    if not isinstance(permissions, dict):
        return []

    out: List[Artifact] = []
    for bucket in ("allow", "deny", "ask"):
        rules = permissions.get(bucket)
        if not isinstance(rules, list):
            continue
        for rule in rules:
            if not isinstance(rule, str) or not rule.strip():
                continue
            tool, _, argument = rule.partition("(")
            argument = argument.rstrip(")")
            out.append(
                Artifact(
                    kind=ArtifactKind.PERMISSION_RULE,
                    identity="perm:%s:%s" % (bucket, rule),
                    name=rule,
                    platform="claude-code",
                    source=source_for(path, text, rule),
                    text=rule,
                    data={
                        "effect": bucket,
                        "tool": tool.strip(),
                        "argument": argument.strip(),
                        "scope": scope,
                        "wildcard": _wildcard_breadth(argument.strip(), bool(_)),
                        "config_path": path,
                    },
                    tags=["permission", bucket, scope],
                )
            )
    return out


def _wildcard_breadth(argument: str, had_parens: bool) -> str:
    """How wide a permission argument is: exact, prefix, or unbounded.

    A rule with no parentheses at all (``Bash``) grants the whole tool, which
    is the widest grant available -- wider than ``Bash(*)`` looks to a reader.
    """
    if not had_parens:
        return "unbounded"
    stripped = argument.strip().strip("\"'")
    if not stripped or stripped in {"*", "**", ":*", "*:*"}:
        return "unbounded"
    if stripped.endswith("*"):
        # `Bash(git status:*)` names a real command prefix and is bounded.
        # `WebFetch(domain:*)` reads like a constraint but names no domain at
        # all -- the text before the star is only the qualifier keyword, so
        # the rule matches everything the tool can reach.
        prefix = stripped.rstrip("*").rstrip(":")
        if not prefix or prefix.lower() in QUALIFIER_KEYWORDS:
            return "unbounded"
        return "prefix"
    return "exact"


#: Words that introduce a constraint rather than being one.  A rule whose
#: argument is only one of these plus a wildcard has constrained nothing.
QUALIFIER_KEYWORDS = frozenset(
    {
        "domain", "host", "hostname", "url", "uri", "scheme", "port",
        "path", "file", "dir", "directory", "cmd", "command", "tool", "any",
    }
)


def _hook_artifacts(
    data: Dict[str, Any], path: str, text: str, scope: str
) -> List[Artifact]:
    """Flatten the nested hook structure into one artifact per command.

    Shape handled::

        {"hooks": {"PreToolUse": [{"matcher": "Bash",
                                   "hooks": [{"type": "command",
                                              "command": "..."}]}]}}
    """
    hooks = data.get("hooks")
    if not isinstance(hooks, dict):
        return []

    out: List[Artifact] = []
    for event, groups in hooks.items():
        for index, group in enumerate(_as_list(groups)):
            if not isinstance(group, dict):
                continue
            matcher = str(group.get("matcher", "*"))
            raw_entries = group.get("hooks")
            entries = _as_list(raw_entries) if raw_entries is not None else [group]
            for position, entry in enumerate(entries):
                if not isinstance(entry, dict):
                    continue
                command = str(entry.get("command") or entry.get("run") or "")
                if not command:
                    continue
                out.append(
                    Artifact(
                        kind=ArtifactKind.HOOK,
                        identity="hook:%s:%s:%d.%d" % (event, matcher, index, position),
                        name="%s/%s" % (event, matcher),
                        platform="claude-code",
                        source=source_for(path, text, command[:60]),
                        text=command,
                        data={
                            "event": str(event),
                            "matcher": matcher,
                            "type": str(entry.get("type") or "command"),
                            "timeout": entry.get("timeout"),
                            "scope": scope,
                            "config_path": path,
                        },
                        tags=["hook", str(event).lower(), scope],
                    )
                )
    return out


def _as_list(value: Any) -> List[Any]:
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]


# --------------------------------------------------------------------------
# Markdown surfaces
# --------------------------------------------------------------------------


def _markdown_artifact(
    path: str, kind: ArtifactKind, tag: str, scope: str
) -> Optional[Artifact]:
    text = read_text(path)
    if text is None:
        return None
    front, body = split_front_matter(text)
    name = str(front.get("name") or os.path.splitext(os.path.basename(path))[0])
    description = str(front.get("description") or "")

    allowed = (
        front.get("allowed-tools") or front.get("tools") or front.get("allowedTools")
    )
    if isinstance(allowed, str):
        allowed_list = [part.strip() for part in allowed.split(",") if part.strip()]
    elif isinstance(allowed, list):
        allowed_list = [str(part) for part in allowed]
    else:
        allowed_list = []

    return Artifact(
        kind=kind,
        identity="%s:%s" % (tag, name),
        name=name,
        platform="claude-code",
        source=SourceRef(path=path),
        # Both the front-matter description and the body reach the model: the
        # description at selection time, the body once loaded.  Injection can
        # live in either, so both are scanned as one string.
        text="\n".join(part for part in (description, body) if part),
        data={
            "front_matter": front,
            "allowed_tools": allowed_list,
            "scope": scope,
            "body_bytes": len(body),
            "description": description,
        },
        tags=[tag, scope],
    )


def _is_probably_ignored(root: str, path: str) -> bool:
    """Cheap .gitignore check: does any ignore file mention this basename?

    Deliberately not a full gitignore implementation.  The question a finding
    needs answered is "did anyone think about this file at all", and a literal
    mention answers it without shelling out to git.
    """
    name = os.path.basename(path)
    wanted = {name, ".env", "*.env", ".env*"}
    for ignore_name in (".gitignore", os.path.join(".git", "info", "exclude")):
        content = read_text(os.path.join(root, ignore_name))
        if not content:
            continue
        for line in content.splitlines():
            entry = line.strip()
            if not entry or entry.startswith("#"):
                continue
            if entry.strip("/") in wanted:
                return True
    return False


def iter_rules_files(root: str) -> Iterable[str]:
    """Public helper: the persistent-instruction files present under ``root``."""
    return existing(*[os.path.join(root, name) for name in RULES_FILES])
