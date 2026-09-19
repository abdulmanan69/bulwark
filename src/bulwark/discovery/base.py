"""Shared plumbing for discovery collectors.

Discovery is the only part of Bulwark that touches the filesystem, so every
tolerance for real-world mess lives here: configuration files with comments and
trailing commas, files in four different encodings, YAML front matter, and
paths that exist on one operating system but not another.

The guiding rule is that discovery never raises.  A malformed config on one
machine must degrade into a recorded error and an otherwise complete scan, not
an empty report -- a scanner that fails closed on bad input is a scanner people
turn off.
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import stat
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

from ..core.models import Artifact, ScanError, SourceRef

#: Files larger than this are almost certainly not configuration, and reading
#: them would turn a scan into an I/O benchmark.
MAX_FILE_BYTES = 8 * 1024 * 1024

#: Directories never worth walking.
SKIP_DIRS = frozenset(
    {
        ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
        "env", ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache", "dist",
        "build", "target", ".next", ".nuxt", ".cache", "vendor", ".gradle",
        ".idea", "site-packages", ".terraform", "coverage",
    }
)


@dataclass
class CollectionResult:
    artifacts: List[Artifact] = field(default_factory=list)
    errors: List[ScanError] = field(default_factory=list)
    files_seen: List[str] = field(default_factory=list)

    def extend(self, other: "CollectionResult") -> None:
        self.artifacts.extend(other.artifacts)
        self.errors.extend(other.errors)
        self.files_seen.extend(other.files_seen)

    def fail(self, where: str, exc: BaseException, kind: str = "parse_error") -> None:
        self.errors.append(
            ScanError(
                where=where, message="%s: %s" % (type(exc).__name__, exc), kind=kind
            )
        )

    def note(self, where: str, message: str, kind: str = "info") -> None:
        self.errors.append(ScanError(where=where, message=message, kind=kind))


class Collector:
    """Base class for anything that turns files into artifacts."""

    name: str = ""
    platform: str = ""

    def collect(
        self, roots: Sequence[str], home: str, exclude: Sequence[str] = ()
    ) -> CollectionResult:
        raise NotImplementedError


# --------------------------------------------------------------------------
# Tolerant file reading
# --------------------------------------------------------------------------


def read_text(path: str) -> Optional[str]:
    """Read a config file, tolerating the encodings these files show up in.

    Returns ``None`` rather than raising when the file is missing, too large,
    unreadable, or binary.
    """
    try:
        if not os.path.isfile(path):
            return None
        if os.path.getsize(path) > MAX_FILE_BYTES:
            return None
        with open(path, "rb") as handle:
            raw = handle.read()
    except (OSError, ValueError):
        return None

    # UTF-16 is only attempted when a BOM says so.  Without that check the
    # UTF-16 codec happily "succeeds" on any even-length single-byte file and
    # returns confident garbage, which would silently corrupt a config read.
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return raw.decode("utf-16")
        except UnicodeDecodeError:
            pass
    elif b"\x00" in raw[:4096]:
        return None  # binary

    for encoding in ("utf-8-sig", "utf-8", "cp1252", "latin-1"):
        try:
            return raw.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", errors="replace")


_TRAILING_COMMA = re.compile(r",(\s*[}\]])")


def parse_jsonc(text: str) -> Any:
    """Parse JSON that may contain comments and trailing commas.

    Every editor that ships an MCP config accepts JSONC, so a strict parser
    reports "invalid config" on files the editor itself loads happily.  Comment
    stripping is string-aware so a ``//`` inside a URL survives.
    """
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    cleaned = _TRAILING_COMMA.sub(r"\1", _strip_comments(text))
    return json.loads(cleaned)


def _strip_comments(text: str) -> str:
    """Remove // and /* */ comments without touching string literals."""
    out: List[str] = []
    index = 0
    length = len(text)
    in_string = False
    quote = ""

    while index < length:
        ch = text[index]
        if in_string:
            out.append(ch)
            if ch == "\\" and index + 1 < length:
                out.append(text[index + 1])
                index += 2
                continue
            if ch == quote:
                in_string = False
            index += 1
            continue

        if ch in "\"'":
            in_string = True
            quote = ch
            out.append(ch)
            index += 1
            continue

        if ch == "/" and index + 1 < length:
            nxt = text[index + 1]
            if nxt == "/":
                while index < length and text[index] not in "\r\n":
                    index += 1
                continue
            if nxt == "*":
                end = text.find("*/", index + 2)
                index = length if end == -1 else end + 2
                continue

        out.append(ch)
        index += 1
    return "".join(out)


def load_json_file(path: str, result: CollectionResult) -> Optional[Any]:
    """Read and parse a JSON/JSONC file, recording failures on ``result``."""
    text = read_text(path)
    if text is None:
        return None
    result.files_seen.append(path)
    if not text.strip():
        return None
    try:
        return parse_jsonc(text)
    except (json.JSONDecodeError, ValueError) as exc:
        result.fail(path, exc)
        return None


# --------------------------------------------------------------------------
# Locating things inside a file, for actionable findings
# --------------------------------------------------------------------------


def locate(text: str, *needles: str) -> Tuple[Optional[int], str]:
    """Find the first line containing all of ``needles``.

    Good enough to put a finding on the right line without carrying a full JSON
    parser with position tracking, and it degrades to ``(None, "")`` rather
    than guessing wrong.
    """
    if not text or not needles:
        return None, ""
    lines = text.splitlines()
    primary = needles[0]
    for number, line in enumerate(lines, start=1):
        if primary in line and all(n in line for n in needles):
            return number, line.strip()[:200]
    for number, line in enumerate(lines, start=1):
        if primary in line:
            return number, line.strip()[:200]
    return None, ""


def source_for(path: str, text: str, *needles: str, pointer: str = "") -> SourceRef:
    line, snippet = locate(text, *needles)
    return SourceRef(path=path, line=line, snippet=snippet, json_pointer=pointer)


# --------------------------------------------------------------------------
# Filesystem helpers
# --------------------------------------------------------------------------


def iter_files(
    root: str,
    patterns: Sequence[str],
    *,
    max_depth: int = 6,
    skip_dirs: Iterable[str] = SKIP_DIRS,
) -> Iterator[str]:
    """Walk ``root`` yielding files whose basename matches any glob pattern."""
    root = os.path.abspath(root)
    if not os.path.isdir(root):
        return
    skip = set(skip_dirs)
    root_depth = root.rstrip(os.sep).count(os.sep)

    for current, dirnames, filenames in os.walk(root, topdown=True):
        depth = current.rstrip(os.sep).count(os.sep) - root_depth
        if depth >= max_depth:
            dirnames[:] = []
        dirnames[:] = [d for d in dirnames if d not in skip and d != ".git"]
        for filename in filenames:
            for pattern in patterns:
                if fnmatch.fnmatch(filename, pattern):
                    yield os.path.join(current, filename)
                    break


def is_excluded(path: str, patterns: Sequence[str], root: str = "") -> bool:
    """True when a path matches an operator exclusion.

    Matched against both the absolute path and the root-relative one, so
    `--exclude 'examples/**'` works the way a person expects without them
    having to know which form the scanner happens to hold.
    """
    if not patterns:
        return False
    absolute = os.path.abspath(path).replace("\\", "/")
    candidates = [absolute]
    if root:
        relative = relative_to(path, root)
        candidates.append(relative)
        candidates.append("./" + relative)

    for pattern in patterns:
        pattern = pattern.replace("\\", "/")
        for candidate in candidates:
            if fnmatch.fnmatch(candidate, pattern):
                return True
            # A directory pattern should exclude everything beneath it, which
            # bare fnmatch does not do because * does not cross the trailing
            # boundary in the way people assume.
            trimmed = pattern.rstrip("/*")
            if trimmed and (
                candidate == trimmed or candidate.startswith(trimmed + "/")
            ):
                return True
    return False


#: How deep to look for agent config inside a scanned project.  Eight levels
#: reaches `packages/*/apps/*/.cursor/mcp.json` in the monorepo layouts people
#: actually use, while the skip list keeps the walk off vendored trees.
PROJECT_CONFIG_DEPTH = 8


def find_nested(
    root: str,
    patterns: Sequence[str],
    *,
    max_depth: int = PROJECT_CONFIG_DEPTH,
    exclude: Sequence[str] = (),
) -> List[str]:
    """Every file under ``root`` matching any pattern, the root included.

    Agent config does not only live at the top of a repository.  A monorepo
    puts a `.mcp.json` in each package, and a scanner that only stats the root
    reports a clean result for a project full of them -- which is worse than
    reporting nothing at all, because a clean result is believed.

    One traversal covers all patterns, so adding a filename costs no extra I/O.
    """
    found = iter_files(root, patterns, max_depth=max_depth)
    return sorted({p for p in found if not is_excluded(p, exclude, root)})


def find_nested_dirs(
    root: str,
    names: Sequence[str],
    *,
    max_depth: int = PROJECT_CONFIG_DEPTH,
    exclude: Sequence[str] = (),
) -> List[str]:
    """Every directory under ``root`` with one of these names.

    Finds the `.claude` and `.cursor` directories of each package in a
    monorepo, which is where skills, subagents and slash commands live.
    """
    root = os.path.abspath(root)
    if not os.path.isdir(root):
        return []
    wanted = {n.lower() for n in names}
    found: List[str] = []
    root_depth = root.rstrip(os.sep).count(os.sep)

    for current, dirnames, _ in os.walk(root, topdown=True):
        if current.rstrip(os.sep).count(os.sep) - root_depth >= max_depth:
            dirnames[:] = []
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and d != ".git"]
        # Prune excluded directories from the walk itself, so a huge
        # vendored tree costs nothing rather than being filtered afterwards.
        dirnames[:] = [
            d
            for d in dirnames
            if not is_excluded(os.path.join(current, d), exclude, root)
        ]
        for name in dirnames:
            if name.lower() in wanted:
                found.append(os.path.join(current, name))
    return sorted(set(found))


def existing(*candidates: str) -> List[str]:
    """Return the candidate paths that exist, deduplicated, order preserved."""
    out: List[str] = []
    seen = set()
    for candidate in candidates:
        if not candidate:
            continue
        normalised = os.path.normcase(os.path.abspath(candidate))
        if normalised in seen:
            continue
        if os.path.exists(candidate):
            seen.add(normalised)
            out.append(candidate)
    return out


def is_world_readable(path: str) -> bool:
    """True when a file's permissions let other local accounts read it.

    POSIX only.  Windows ACLs are not representable in ``st_mode``, so we
    return False there rather than inventing a result -- a wrong "your secrets
    are exposed" is worse than a missing one.
    """
    if os.name == "nt":
        return False
    try:
        mode = os.stat(path).st_mode
    except OSError:
        return False
    return bool(mode & (stat.S_IROTH | stat.S_IRGRP))


def relative_to(path: str, root: str) -> str:
    """Display path: relative when inside ``root``, absolute otherwise."""
    try:
        rel = os.path.relpath(path, root)
    except ValueError:  # different drive on Windows
        return path
    return path if rel.startswith("..") else rel.replace("\\", "/")


# --------------------------------------------------------------------------
# Markdown front matter (skills, subagents, slash commands)
# --------------------------------------------------------------------------

_FRONT_MATTER = re.compile(r"^---[ \t]*\r?\n(.*?)\r?\n---[ \t]*\r?\n?", re.DOTALL)


def split_front_matter(text: str) -> Tuple[Dict[str, Any], str]:
    """Split YAML front matter from a markdown body.

    Uses PyYAML when available and falls back to a deliberately small
    key/value parser otherwise, because front matter in these files is almost
    always flat scalars and lists -- and a hard PyYAML dependency would make
    the scanner harder to deploy than the thing it scans.
    """
    match = _FRONT_MATTER.match(text or "")
    if not match:
        return {}, text or ""
    raw = match.group(1)
    body = text[match.end() :]

    try:
        import yaml  # type: ignore

        loaded = yaml.safe_load(raw)
        if isinstance(loaded, dict):
            return loaded, body
    except Exception:
        pass

    return _parse_simple_yaml(raw), body


def _parse_simple_yaml(raw: str) -> Dict[str, Any]:
    data: Dict[str, Any] = {}
    current_key: Optional[str] = None
    for line in raw.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if (
            line.startswith((" ", "\t"))
            and line.lstrip().startswith("- ")
            and current_key
        ):
            existing_value = data.get(current_key)
            if not isinstance(existing_value, list):
                existing_value = []
                data[current_key] = existing_value
            existing_value.append(_scalar(line.lstrip()[2:]))
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        current_key = key
        data[key] = _scalar(value) if value else []
    return data


def _scalar(value: str) -> Any:
    value = value.strip().strip("'\"")
    lowered = value.lower()
    if lowered in {"true", "yes"}:
        return True
    if lowered in {"false", "no"}:
        return False
    if lowered in {"null", "none", "~"}:
        return None
    if re.match(r"^-?\d+$", value):
        return int(value)
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        return [_scalar(part) for part in inner.split(",")] if inner else []
    return value


# --------------------------------------------------------------------------
# Platform paths
# --------------------------------------------------------------------------


def home_dir() -> str:
    return os.path.expanduser("~")


def app_data_dirs(home: str) -> Dict[str, str]:
    """Per-platform application-support directories, as a flat lookup.

    Returned unconditionally for every platform: a config synced from a
    colleague's Mac onto a Windows box is still a config worth scanning, and
    non-existent paths are filtered out by :func:`existing` at use time.

    ``APPDATA`` and ``XDG_CONFIG_HOME`` are only consulted when ``home`` is the
    real home directory.  Otherwise the caller has deliberately redirected the
    home -- a test, or a scan of a mounted image -- and letting an environment
    variable drag in the live machine's configs would silently mix two systems
    into one report.
    """
    is_real_home = os.path.normcase(os.path.abspath(home)) == os.path.normcase(
        os.path.abspath(home_dir())
    )
    env = os.environ.get if is_real_home else (lambda _key: None)
    return {
        "win_appdata": env("APPDATA") or os.path.join(home, "AppData", "Roaming"),
        "win_localappdata": env("LOCALAPPDATA")
        or os.path.join(home, "AppData", "Local"),
        "mac_support": os.path.join(home, "Library", "Application Support"),
        "xdg_config": env("XDG_CONFIG_HOME") or os.path.join(home, ".config"),
        "home": home,
    }
