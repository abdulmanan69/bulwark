"""Discover MCP servers from every configuration shape in the wild.

There is no single MCP config format.  Each host invented its own container
key, its own server-entry dialect and its own auto-approval mechanism, and a
developer machine typically has three or four of them side by side -- which is
exactly why nobody has an inventory of what their agents can reach.

This collector normalises all of them into one artifact model so the rules
never have to care which editor a server came from.

Supported containers
--------------------
``mcpServers``            Claude Desktop, Claude Code (.mcp.json), Cursor,
                          Windsurf, Cline, Roo, most third-party hosts
``servers``               VS Code ``.vscode/mcp.json``
``mcp.servers``           VS Code ``settings.json``
``context_servers``       Zed
``projects.*.mcpServers`` Claude Code's ``~/.claude.json``
"""

from __future__ import annotations

import os
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from ..analyzers import capability as cap
from ..analyzers import provenance as prov
from ..core.models import Artifact, ArtifactKind, SourceRef
from .base import (
    CollectionResult,
    Collector,
    app_data_dirs,
    existing,
    is_world_readable,
    load_json_file,
    read_text,
    source_for,
)

#: Container key -> the platform it implies, most specific first.
CONTAINER_KEYS: Tuple[Tuple[str, str], ...] = (
    ("mcpServers", ""),
    ("servers", "vscode"),
    ("context_servers", "zed"),
    ("mcp_servers", ""),
)


class McpConfigCollector(Collector):
    """Finds MCP server declarations in user-level and project-level configs."""

    name = "mcp-config"

    def collect(self, roots: Sequence[str], home: str) -> CollectionResult:
        result = CollectionResult()
        for path, platform in self._candidate_files(roots, home):
            self._collect_file(path, platform, result)
        return result

    # ---- where to look --------------------------------------------------

    def _candidate_files(self, roots: Sequence[str], home: str) -> List[Tuple[str, str]]:
        dirs = app_data_dirs(home)
        candidates: List[Tuple[str, str]] = []

        def add(path: str, platform: str) -> None:
            candidates.append((path, platform))

        # --- user scope, per host -----------------------------------------
        for base in (dirs["win_appdata"], dirs["mac_support"], dirs["xdg_config"]):
            add(os.path.join(base, "Claude", "claude_desktop_config.json"), "claude-desktop")

        add(os.path.join(home, ".claude.json"), "claude-code")
        add(os.path.join(home, ".claude", "settings.json"), "claude-code")
        add(os.path.join(home, ".claude", ".mcp.json"), "claude-code")

        add(os.path.join(home, ".cursor", "mcp.json"), "cursor")
        add(os.path.join(dirs["xdg_config"], "cursor", "mcp.json"), "cursor")

        add(os.path.join(home, ".codeium", "windsurf", "mcp_config.json"), "windsurf")
        add(os.path.join(home, ".windsurf", "mcp_config.json"), "windsurf")

        add(os.path.join(home, ".continue", "config.json"), "continue")
        add(os.path.join(dirs["xdg_config"], "zed", "settings.json"), "zed")

        for base in (dirs["win_appdata"], dirs["mac_support"], dirs["xdg_config"]):
            for editor in ("Code", "Code - Insiders", "VSCodium", "Cursor"):
                add(os.path.join(base, editor, "User", "settings.json"), "vscode")
                add(os.path.join(base, editor, "User", "mcp.json"), "vscode")
                # Cline and Roo keep MCP settings in their extension storage.
                add(
                    os.path.join(
                        base, editor, "User", "globalStorage",
                        "saoudrizwan.claude-dev", "settings",
                        "cline_mcp_settings.json",
                    ),
                    "cline",
                )
                add(
                    os.path.join(
                        base, editor, "User", "globalStorage",
                        "rooveterinaryinc.roo-cline", "settings",
                        "mcp_settings.json",
                    ),
                    "roo",
                )

        # --- project scope --------------------------------------------------
        for root in roots:
            add(os.path.join(root, ".mcp.json"), "claude-code")
            add(os.path.join(root, ".claude", "settings.json"), "claude-code")
            add(os.path.join(root, ".claude", "settings.local.json"), "claude-code")
            add(os.path.join(root, ".cursor", "mcp.json"), "cursor")
            add(os.path.join(root, ".vscode", "mcp.json"), "vscode")
            add(os.path.join(root, ".vscode", "settings.json"), "vscode")
            add(os.path.join(root, "mcp.json"), "generic")
            add(os.path.join(root, "mcp_config.json"), "generic")
            add(os.path.join(root, ".windsurf", "mcp_config.json"), "windsurf")

        present = set(existing(*[path for path, _ in candidates]))
        seen: Set[str] = set()
        out: List[Tuple[str, str]] = []
        for path, platform in candidates:
            if path in present and path not in seen:
                seen.add(path)
                out.append((path, platform))
        return out

    # ---- parsing ---------------------------------------------------------

    def _collect_file(self, path: str, platform: str, result: CollectionResult) -> None:
        data = load_json_file(path, result)
        if not isinstance(data, dict):
            return
        text = read_text(path) or ""

        # The config file itself is an artifact: its permissions and the
        # secrets inside it are findings in their own right.
        result.artifacts.append(
            Artifact(
                kind=ArtifactKind.SETTINGS,
                identity="config:" + path,
                name=os.path.basename(path),
                platform=platform,
                source=SourceRef(path=path),
                data={
                    "world_readable": is_world_readable(path),
                    "size": len(text),
                    "raw": data,
                },
                tags=["mcp-config"],
            )
        )

        for scope, container in _iter_containers(data):
            host = platform or scope.platform_hint or "generic"
            for name, entry in _iter_entries(container):
                artifact = _build_server(
                    name=name,
                    entry=entry,
                    path=path,
                    text=text,
                    platform=host,
                    scope=scope.label,
                )
                if artifact is not None:
                    result.artifacts.append(artifact)
                    result.artifacts.extend(
                        _declared_tool_artifacts(artifact, entry, path, text)
                    )


# --------------------------------------------------------------------------
# Container walking
# --------------------------------------------------------------------------


class _Scope:
    __slots__ = ("label", "platform_hint")

    def __init__(self, label: str, platform_hint: str = "") -> None:
        self.label = label
        self.platform_hint = platform_hint


def _iter_containers(data: Dict[str, Any]) -> Iterable[Tuple[_Scope, Any]]:
    """Yield every server container in a parsed config document."""
    for key, platform_hint in CONTAINER_KEYS:
        container = data.get(key)
        if isinstance(container, (dict, list)) and container:
            yield _Scope("user", platform_hint), container

    # VS Code settings.json nests the container under "mcp".
    mcp_block = data.get("mcp")
    if isinstance(mcp_block, dict):
        for key in ("servers", "mcpServers"):
            container = mcp_block.get(key)
            if isinstance(container, (dict, list)) and container:
                yield _Scope("user", "vscode"), container

    # Claude Code's ~/.claude.json keys servers by absolute project path, so
    # one file can describe a dozen different projects' tool surfaces.
    projects = data.get("projects")
    if isinstance(projects, dict):
        for project_path, project in projects.items():
            if not isinstance(project, dict):
                continue
            for key, _ in CONTAINER_KEYS:
                container = project.get(key)
                if isinstance(container, (dict, list)) and container:
                    yield _Scope("project:" + str(project_path), "claude-code"), container


def _iter_entries(container: Any) -> Iterable[Tuple[str, Dict[str, Any]]]:
    """Normalise dict-keyed and list-of-objects containers into pairs."""
    if isinstance(container, dict):
        for name, entry in container.items():
            if isinstance(entry, dict):
                yield str(name), entry
    elif isinstance(container, list):
        for index, entry in enumerate(container):
            if isinstance(entry, dict):
                name = entry.get("name") or entry.get("id") or "server-%d" % index
                yield str(name), entry


# --------------------------------------------------------------------------
# Entry -> artifact
# --------------------------------------------------------------------------

#: Keys that switch a server off, across the different hosts.
DISABLED_KEYS = ("disabled", "enabled", "isActive", "active")

#: Keys that pre-authorise tool calls without asking the user.
AUTO_APPROVE_KEYS = ("autoApprove", "alwaysAllow", "autoApproved", "allowedTools")


def _build_server(
    *,
    name: str,
    entry: Dict[str, Any],
    path: str,
    text: str,
    platform: str,
    scope: str,
) -> Optional[Artifact]:
    command = entry.get("command")
    url = entry.get("url") or entry.get("serverUrl") or entry.get("endpoint")
    args = _as_string_list(entry.get("args"))
    env = _as_string_map(entry.get("env"))
    headers = _as_string_map(entry.get("headers"))

    if command:
        report = prov.analyze_command(str(command), args)
    elif url:
        report = prov.analyze_endpoint(str(url))
    else:
        # Neither a command nor a URL: not a server entry we can reason about.
        return None

    declared_type = str(entry.get("type") or entry.get("transport") or "").lower()
    if declared_type in {"sse", "http", "streamable-http", "websocket"}:
        report.transport = "sse" if declared_type == "sse" else "http"
    elif command:
        report.transport = "stdio"

    auto_approve: List[str] = []
    for key in AUTO_APPROVE_KEYS:
        value = entry.get(key)
        if isinstance(value, list):
            auto_approve.extend(str(v) for v in value)
        elif value is True:
            auto_approve.append("*")

    return Artifact(
        kind=ArtifactKind.MCP_SERVER,
        identity=name,
        name=name,
        platform=platform,
        source=source_for(path, text, '"%s"' % name),
        text=str(entry.get("description") or ""),
        trust=report.trust,
        data={
            "scope": scope,
            "command": str(command) if command else "",
            "args": args,
            "env": env,
            "headers": headers,
            "url": str(url) if url else "",
            "disabled": _is_disabled(entry),
            "auto_approve": sorted(set(auto_approve)),
            "provenance": report.to_dict(),
            "config_path": path,
            "raw": entry,
        },
        tags=["mcp", report.transport],
    )


def _as_string_list(value: Any) -> List[str]:
    """Coerce a config field to a list of strings.

    Config files are written by hand, so a field documented as a list arrives
    as a string, a number or nothing at all often enough to be worth handling
    once here rather than guarding at every use.
    """
    if isinstance(value, list):
        return [str(item) for item in value]
    if value is None or isinstance(value, (dict, bool)):
        return []
    return [str(value)]


def _as_string_map(value: Any) -> Dict[str, str]:
    """Coerce a config field to a flat string map."""
    if not isinstance(value, dict):
        return {}
    return {str(k): str(v) for k, v in value.items()}


def _is_disabled(entry: Dict[str, Any]) -> bool:
    """Honour every host's spelling of "off".

    ``disabled: true`` and ``enabled: false`` mean the same thing and appear in
    different hosts; treating a disabled server as live produces noise nobody
    can act on.
    """
    for key in DISABLED_KEYS:
        if key not in entry:
            continue
        value = entry[key]
        if key == "disabled":
            if value is True:
                return True
        elif value is False:
            return True
    return False


def _declared_tool_artifacts(
    server: Artifact, entry: Dict[str, Any], path: str, text: str
) -> List[Artifact]:
    """Turn statically declared tools into artifacts.

    Most configs do not list tools -- that needs a live handshake, which
    ``bulwark scan --online`` performs.  But some hosts cache the tool list in
    the config, and an auto-approve list names tools too.  Both are worth
    modelling so offline scans are not blind.
    """
    out: List[Artifact] = []
    seen: Set[str] = set()

    declared = entry.get("tools")
    if isinstance(declared, list):
        for item in declared:
            if isinstance(item, str):
                name, description = item, ""
                schema: Dict[str, Any] = {}
                annotations: Dict[str, Any] = {}
            elif isinstance(item, dict):
                name = str(item.get("name") or "")
                description = str(item.get("description") or "")
                raw_schema = item.get("inputSchema") or item.get("input_schema") or {}
                schema = raw_schema if isinstance(raw_schema, dict) else {}
                raw_annotations = item.get("annotations") or {}
                annotations = raw_annotations if isinstance(raw_annotations, dict) else {}
            else:
                continue
            if not name or name in seen:
                continue
            seen.add(name)
            out.append(
                build_tool_artifact(
                    server=server,
                    name=name,
                    description=description,
                    schema=schema,
                    annotations=annotations,
                    path=path,
                    text=text,
                    origin="declared",
                )
            )

    for tool_name in server.data.get("auto_approve", []):
        if tool_name in {"*", ""} or tool_name in seen:
            continue
        seen.add(tool_name)
        out.append(
            build_tool_artifact(
                server=server,
                name=tool_name,
                description="",
                schema={},
                annotations={},
                path=path,
                text=text,
                origin="auto-approve-list",
            )
        )
    return out


def build_tool_artifact(
    *,
    server: Artifact,
    name: str,
    description: str,
    schema: Dict[str, Any],
    annotations: Dict[str, Any],
    path: str,
    text: str = "",
    origin: str = "live",
) -> Artifact:
    """Build a tool artifact with capabilities already inferred.

    Shared by the static collector and the live MCP introspector so both paths
    produce identical artifacts -- which is what lets an offline lockfile be
    compared against an online scan.
    """
    report = cap.infer(name, description, schema, annotations)
    approvals = server.data.get("auto_approve", [])
    auto_approved = name in approvals or "*" in approvals
    return Artifact(
        kind=ArtifactKind.MCP_TOOL,
        identity="%s:%s" % (server.identity, name),
        name=name,
        platform=server.platform,
        parent=server.identity,
        source=source_for(path, text, '"%s"' % name) if text else SourceRef(path=path),
        text=description,
        trust=server.trust,
        capabilities=report.capabilities,
        data={
            "schema": schema,
            "annotations": annotations,
            "roles": report.roles,
            "agency_score": report.agency_score,
            "capability_evidence": report.evidence,
            "auto_approved": auto_approved,
            "origin": origin,
            "server": server.identity,
        },
        tags=["mcp-tool", origin] + (["auto-approved"] if auto_approved else []),
    )
