"""Supply-chain analysis of how an MCP server actually gets started.

An MCP server entry is a command line.  That command line is the install step,
the update step and the execution step all at once, and it runs with the user's
full privileges every time the agent starts.  ``npx -y some-server@latest`` is
therefore not a dependency declaration -- it is an unreviewed, unpinned,
auto-confirming remote code fetch that re-resolves on every launch.

This module classifies that command line: where the code comes from, whether
the version is pinned, whether a human ever gets to approve it, and whether the
package name is one character away from something popular.
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

# --------------------------------------------------------------------------
# Trust classes
# --------------------------------------------------------------------------

TRUST_LOCAL = "local"        # a path inside the project or an absolute local file
TRUST_REGISTRY = "registry"  # a named package from a public registry
TRUST_REMOTE = "remote"      # fetched over the network at launch
TRUST_UNKNOWN = "unknown"

#: Launchers that resolve and execute a package in one step.
EPHEMERAL_RUNNERS = {
    "npx": "npm",
    "pnpx": "npm",
    "bunx": "npm",
    "uvx": "pypi",
    "pipx": "pypi",
    "dlx": "npm",
    "yarn": "npm",
    "pnpm": "npm",
}

#: Flags that suppress the "do you want to install X?" confirmation.
AUTO_CONFIRM_FLAGS = {"-y", "--yes", "--force", "-f", "--no-input", "--non-interactive"}

#: Version specifiers that do not pin anything.
FLOATING_SPECS = re.compile(
    r"^(?:latest|next|beta|alpha|canary|dev|\*|x|)$", re.IGNORECASE
)
RANGE_SPECS = re.compile(r"^[\^~><=]")

#: Shells that will execute whatever bytes arrive on stdin.
PIPE_TO_SHELL = re.compile(
    r"(?:curl|wget|iwr|invoke-webrequest|fetch)\b[^|;&]*[|]\s*"
    r"(?:sudo\s+)?(?:ba|z|k|da)?sh\b"
    r"|(?:iwr|invoke-webrequest|curl)\b[^|;&]*[|]\s*(?:iex|invoke-expression)\b",
    re.IGNORECASE,
)

#: Interpreters invoked with an inline program rather than a file.
INLINE_CODE = re.compile(
    r"\b(?:python3?|node|deno|bun|ruby|perl|php)\b\s+(?:-\w+\s+)*"
    r"(?:-c|-e|--eval|--execute|-p)\b",
    re.IGNORECASE,
)

#: Well-known MCP package names used as the typosquat reference set.  Not
#: exhaustive by design: these are the names an attacker gains most from
#: impersonating, and the list is overridable from policy.
KNOWN_PACKAGES: Tuple[str, ...] = (
    "@modelcontextprotocol/server-filesystem",
    "@modelcontextprotocol/server-github",
    "@modelcontextprotocol/server-gitlab",
    "@modelcontextprotocol/server-git",
    "@modelcontextprotocol/server-google-maps",
    "@modelcontextprotocol/server-postgres",
    "@modelcontextprotocol/server-sqlite",
    "@modelcontextprotocol/server-slack",
    "@modelcontextprotocol/server-memory",
    "@modelcontextprotocol/server-puppeteer",
    "@modelcontextprotocol/server-brave-search",
    "@modelcontextprotocol/server-fetch",
    "@modelcontextprotocol/server-sequential-thinking",
    "@modelcontextprotocol/server-everything",
    "@modelcontextprotocol/inspector",
    "@playwright/mcp",
    "mcp-server-fetch",
    "mcp-server-git",
    "mcp-server-sqlite",
    "mcp-server-time",
    "firecrawl-mcp",
    "figma-developer-mcp",
    "@upstash/context7-mcp",
    "@notionhq/notion-mcp-server",
    "@sentry/mcp-server",
    "@stripe/mcp",
    "supabase-mcp",
    "@cloudflare/mcp-server-cloudflare",
)

#: Organisations whose names are worth impersonating.
PROTECTED_SCOPES = (
    "@modelcontextprotocol", "@anthropic-ai", "@openai", "@playwright",
    "@github", "@cloudflare", "@stripe", "@notionhq", "@sentry", "@upstash",
)


@dataclass
class ProvenanceReport:
    trust: str = TRUST_UNKNOWN
    ecosystem: str = ""
    package: str = ""
    version: str = ""
    pinned: bool = False
    integrity: bool = False       # a hash or lockfile governs the fetch
    auto_confirm: bool = False    # a -y style flag suppresses the prompt
    ephemeral: bool = False       # resolved fresh on every launch
    transport: str = "stdio"      # stdio | http | sse | unknown
    endpoint: str = ""
    issues: List[str] = field(default_factory=list)
    notes: Dict[str, str] = field(default_factory=dict)

    def add(self, issue: str, note: str = "") -> None:
        if issue not in self.issues:
            self.issues.append(issue)
        if note:
            self.notes.setdefault(issue, note)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "trust": self.trust,
            "ecosystem": self.ecosystem,
            "package": self.package,
            "version": self.version,
            "pinned": self.pinned,
            "integrity": self.integrity,
            "auto_confirm": self.auto_confirm,
            "ephemeral": self.ephemeral,
            "transport": self.transport,
            "endpoint": self.endpoint,
            "issues": list(self.issues),
            "notes": dict(self.notes),
        }


# --------------------------------------------------------------------------
# Command-line analysis
# --------------------------------------------------------------------------


def analyze_command(
    command: str,
    args: Optional[Sequence[str]] = None,
    *,
    known_packages: Optional[Sequence[str]] = None,
) -> ProvenanceReport:
    """Classify a stdio MCP server launch command."""
    report = ProvenanceReport()
    args = list(args or [])
    full = " ".join([str(command)] + [str(a) for a in args]).strip()
    if not full:
        report.add("empty_command", "the server entry has no command to run")
        return report

    binary = posixpath.basename(str(command).replace("\\", "/")).lower()
    binary = re.sub(r"\.(exe|cmd|bat|ps1)$", "", binary)

    if PIPE_TO_SHELL.search(full):
        report.trust = TRUST_REMOTE
        report.add(
            "pipe_to_shell",
            "downloads a script and pipes it straight into a shell; the bytes "
            "executed are whatever the server returns at that moment",
        )

    if INLINE_CODE.search(full):
        report.add(
            "inline_code",
            "runs an inline program rather than a reviewable file on disk",
        )

    runner_ecosystem = EPHEMERAL_RUNNERS.get(binary)
    if runner_ecosystem:
        report.ephemeral = True
        report.ecosystem = runner_ecosystem
        report.trust = TRUST_REGISTRY
        _analyze_runner(report, args)
    elif binary in {"node", "python", "python3", "deno", "bun", "ruby", "java"}:
        _analyze_interpreter(report, args)
    elif binary in {"docker", "podman"}:
        _analyze_container(report, args)
    elif binary in {"uv", "pip", "pipenv", "poetry"}:
        report.ecosystem = "pypi"
        report.trust = TRUST_REGISTRY
        _analyze_runner(report, args)
    else:
        # A bare executable: trusted only insofar as the path is.  Never
        # upgrade a command already classified as remote by pipe-to-shell --
        # `sh -c "curl ... | sh"` has an innocuous-looking binary.
        if report.trust != TRUST_REMOTE:
            report.trust = (
                TRUST_LOCAL if _looks_like_path(str(command)) else TRUST_UNKNOWN
            )
        report.package = str(command)
        if report.trust == TRUST_UNKNOWN:
            report.add(
                "unresolved_binary",
                "the command is not a path and not a recognised package runner, "
                "so what actually executes depends on PATH at launch time",
            )

    if any(str(a).lower() in AUTO_CONFIRM_FLAGS for a in args):
        report.auto_confirm = True

    if report.ephemeral and report.auto_confirm and not report.pinned:
        report.add(
            "unreviewed_auto_install",
            "the package is re-resolved, auto-confirmed and unpinned on every "
            "launch, so an upstream change ships to this machine with no review",
        )
    elif report.ephemeral and not report.pinned:
        report.add(
            "floating_version",
            "no version pin, so the code that runs can change between launches",
        )

    if report.package:
        squat = find_typosquat(report.package, known_packages or KNOWN_PACKAGES)
        if squat:
            target, distance = squat
            report.add(
                "typosquat_candidate",
                "package name is %d edit(s) from the well-known %s" % (distance, target),
            )
            report.notes["typosquat_target"] = target

        scope_issue = check_scope_impersonation(report.package)
        if scope_issue:
            report.add("scope_impersonation", scope_issue)

    return report


def _analyze_runner(report: ProvenanceReport, args: Sequence[str]) -> None:
    """Pull the package spec out of an ``npx``/``uvx``-style invocation."""
    skip_next = False
    for raw in args:
        token = str(raw)
        if skip_next:
            skip_next = False
            continue
        lowered = token.lower()
        if lowered in {"dlx", "exec", "run", "tool", "--"}:
            continue
        if lowered in AUTO_CONFIRM_FLAGS:
            continue
        if token.startswith("-"):
            # Flags that consume the following token.
            if lowered in {"-p", "--package", "--from", "-w", "--registry", "--index-url"}:
                skip_next = True
            if lowered in {"--registry", "--index-url"}:
                report.add(
                    "custom_registry", "resolves packages from a non-default registry"
                )
            continue
        report.package, report.version = split_spec(token)
        break

    if not report.package:
        return

    if _looks_like_url(report.package):
        report.trust = TRUST_REMOTE
        report.add(
            "url_package",
            "installs directly from a URL rather than a registry name, so the "
            "registry's own integrity and revocation machinery does not apply",
        )
        return

    if report.package.startswith(("git+", "github:", "gitlab:", "bitbucket:")):
        report.trust = TRUST_REMOTE
        report.add(
            "vcs_package",
            "installs from a version-control URL; branches move, so this is "
            "only pinned if the reference is a full commit SHA",
        )
        if re.search(r"#[0-9a-f]{40}$", report.package):
            report.pinned = True
            report.integrity = True
        else:
            report.add("vcs_unpinned", "the VCS reference is not a full commit SHA")
        return

    if _looks_like_path(report.package):
        report.trust = TRUST_LOCAL
        return

    report.pinned = is_pinned(report.version)


def _analyze_interpreter(report: ProvenanceReport, args: Sequence[str]) -> None:
    """``node ./server.js`` and friends: trust follows the script path."""
    report.ecosystem = "local"
    for raw in args:
        token = str(raw)
        if token.startswith("-"):
            if token in {"-m", "--module"}:
                report.ecosystem = "pypi"
            continue
        report.package = token
        break
    if report.package and _looks_like_path(report.package):
        report.trust = TRUST_LOCAL
        report.pinned = True  # a file on disk does not silently re-resolve
    else:
        report.trust = TRUST_UNKNOWN
        report.add(
            "module_from_environment",
            "runs a module resolved from the ambient environment rather than a "
            "path, so the installed version governs what executes",
        )


def _analyze_container(report: ProvenanceReport, args: Sequence[str]) -> None:
    report.ecosystem = "oci"
    report.trust = TRUST_REGISTRY
    image = ""
    skip_next = False
    for raw in args:
        token = str(raw)
        if skip_next:
            skip_next = False
            continue
        if token.startswith("-"):
            if token in {"-e", "--env", "-v", "--volume", "--mount", "--network", "-p"}:
                skip_next = True
            continue
        if token in {"run", "exec", "start"}:
            continue
        image = token
        break

    report.package = image
    if not image:
        return
    if "@sha256:" in image:
        report.pinned = True
        report.integrity = True
    elif ":" in image.rsplit("/", 1)[-1]:
        tag = image.rsplit(":", 1)[-1]
        report.version = tag
        report.pinned = not FLOATING_SPECS.match(tag) and tag != "latest"
        if not report.pinned:
            report.add(
                "mutable_image_tag",
                "the image tag is mutable, so the container contents can change "
                "without the configuration changing",
            )
    else:
        report.add("implicit_latest_tag", "no tag given, so :latest is implied")

    for raw in args:
        token = str(raw)
        if token == "--privileged":
            report.add(
                "privileged_container",
                "the container runs privileged, which removes the isolation that "
                "made containerising the server worthwhile",
            )
        if token.startswith("--network=host"):
            report.add("host_network", "the container shares the host network namespace")


# --------------------------------------------------------------------------
# Remote transports
# --------------------------------------------------------------------------

TUNNEL_HOSTS = (
    "ngrok.io", "ngrok.app", "ngrok-free.app", "trycloudflare.com", "loca.lt",
    "serveo.net", "localhost.run", "telebit.io", "pagekite.me", "bore.pub",
)


def analyze_endpoint(url: str) -> ProvenanceReport:
    """Classify a remote (HTTP/SSE) MCP server endpoint."""
    report = ProvenanceReport(trust=TRUST_REMOTE, transport="http", endpoint=url)
    if not url:
        report.add("empty_endpoint", "the server entry has no URL")
        return report

    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower()

    if scheme == "http":
        report.add(
            "cleartext_transport",
            "the MCP session, including any bearer token, travels unencrypted",
        )
    elif scheme == "ws":
        report.add("cleartext_websocket", "websocket transport without TLS")
    elif scheme not in {"https", "wss"}:
        report.add("unknown_scheme", "unrecognised transport scheme: %s" % scheme)

    if parsed.query and re.search(
        r"(?:token|key|secret|password|auth)=", parsed.query, re.IGNORECASE
    ):
        report.add(
            "credential_in_url",
            "a credential is embedded in the query string, where it lands in "
            "proxy logs, browser history and referrer headers",
        )

    if host and re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
        report.add(
            "bare_ip_endpoint", "the endpoint is a bare IP with no hostname to verify"
        )

    if _is_tunnel_host(host):
        report.add(
            "ephemeral_tunnel",
            "the endpoint is a temporary tunnel domain; whoever holds the tunnel "
            "at connect time receives the session",
        )

    if host in {"localhost", "127.0.0.1", "::1"}:
        report.trust = TRUST_LOCAL
    return report


def _is_tunnel_host(host: str) -> bool:
    return any(host == domain or host.endswith("." + domain) for domain in TUNNEL_HOSTS)


# --------------------------------------------------------------------------
# Name analysis
# --------------------------------------------------------------------------


def split_spec(spec: str) -> Tuple[str, str]:
    """Split ``@scope/name@1.2.3`` or ``name==1.2.3`` into name and version."""
    spec = spec.strip()
    for separator in ("==", ">=", "<=", "~=", "!="):
        if separator in spec:
            name, _, version = spec.partition(separator)
            return name.strip(), version.strip()
    if spec.startswith("@"):
        at = spec.find("@", 1)
        if at > 0:
            return spec[:at], spec[at + 1 :]
        return spec, ""
    name, sep, version = spec.partition("@")
    return (name, version) if sep else (spec, "")


def is_pinned(version: str) -> bool:
    """True only for an exact, immutable version."""
    version = (version or "").strip()
    if not version:
        return False
    if FLOATING_SPECS.match(version) or RANGE_SPECS.match(version):
        return False
    if version.startswith("sha256:") or re.match(r"^[0-9a-f]{40}$", version):
        return True
    return bool(re.match(r"^\d+(?:\.\d+){0,3}(?:[-+][0-9A-Za-z.]+)?$", version))


def levenshtein(left: str, right: str, *, cap: int = 4) -> int:
    """Edit distance, short-circuiting once it exceeds ``cap``.

    The cap keeps typosquat screening cheap: we only care whether two names are
    *close*, and abandoning early avoids the full quadratic cost on the pairs
    that are obviously unrelated.
    """
    if left == right:
        return 0
    if abs(len(left) - len(right)) > cap:
        return cap + 1
    previous = list(range(len(right) + 1))
    for i, lc in enumerate(left, start=1):
        current = [i]
        best = i
        for j, rc in enumerate(right, start=1):
            cost = 0 if lc == rc else 1
            value = min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost)
            current.append(value)
            best = min(best, value)
        if best > cap:
            return cap + 1
        previous = current
    return previous[-1]


def find_typosquat(
    package: str, known: Sequence[str] = KNOWN_PACKAGES
) -> Optional[Tuple[str, int]]:
    """Return the closest well-known package when the name is suspiciously near.

    Exact matches are not squats.  The allowed distance scales with name length
    so that a two-character difference in a long scoped name is still caught,
    while short names are not flagged for every neighbour.
    """
    candidate = package.strip().lower()
    if not candidate or candidate in {k.lower() for k in known}:
        return None
    if len(candidate) < 6:
        return None

    best: Optional[Tuple[str, int]] = None
    for reference in known:
        target = reference.lower()
        allowed = 1 if len(target) < 16 else 2
        distance = levenshtein(candidate, target, cap=allowed)
        if distance <= allowed and (best is None or distance < best[1]):
            best = (reference, distance)
    return best


def check_scope_impersonation(package: str) -> str:
    """Detect names that borrow a protected scope without being in it.

    ``@modelcontextprotocol-server/x`` and ``modelcontextprotocol-server-x``
    both read as official at a glance and neither is.
    """
    lowered = package.strip().lower()
    if not lowered:
        return ""
    actual_scope = lowered.split("/", 1)[0] if lowered.startswith("@") else ""

    for scope in PROTECTED_SCOPES:
        bare = scope.lstrip("@")
        if actual_scope == scope:
            return ""
        if lowered.startswith(scope + "-") or lowered.startswith(scope + "."):
            return (
                "the name begins with the protected scope %s but is not inside "
                "it; anything before the first slash is just a name" % scope
            )
        if not actual_scope and lowered.startswith(bare + "-"):
            return (
                "unscoped package borrows the %s name; official packages for "
                "that project are published under %s/" % (bare, scope)
            )
    return ""


def _looks_like_path(value: str) -> bool:
    value = value.strip()
    if not value:
        return False
    if value.startswith(("./", "../", "/", "~", ".\\", "..\\", "\\\\")):
        return True
    return bool(re.match(r"^[A-Za-z]:[\\/]", value))


def _looks_like_url(value: str) -> bool:
    return bool(re.match(r"^(?:https?|ftp|file)://", value.strip(), re.IGNORECASE))


def summarise(reports: Iterable[ProvenanceReport]) -> Dict[str, int]:
    """Count issue kinds across a set of servers, for the report header."""
    out: Dict[str, int] = {}
    for report in reports:
        for issue in report.issues:
            out[issue] = out.get(issue, 0) + 1
    return out
