"""Secret detection for agent configuration.

MCP server configs carry an ``env`` block, and the path of least resistance is
to paste a live token straight into it.  Those files then get committed, synced
between machines, and -- because they are also read by the agent -- sometimes
summarised back into a transcript.

Two detectors, in priority order:

1. **Shaped credentials.**  Provider tokens with a recognisable prefix and
   length.  Near-zero false positive rate, so these are reported with high
   confidence and the verified prefix quoted as evidence.
2. **High-entropy assignments.**  A secret-sounding key bound to a value that
   is too random to be prose.  Noisier, so it carries extra suppression for
   placeholders, references and obvious non-secrets.

Nothing here ever emits the secret itself: findings carry a masked preview and
a hash, which is enough to confirm a match and to deduplicate across scans.
"""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Set, Tuple

# --------------------------------------------------------------------------
# Shaped credentials
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class SecretPattern:
    id: str
    label: str
    regex: "re.Pattern[str]"
    #: Entropy floor for the captured group; 0 disables the check for formats
    #: whose prefix alone is conclusive.
    min_entropy: float = 0.0


def _sp(
    pattern_id: str, label: str, source: str, min_entropy: float = 0.0
) -> SecretPattern:
    return SecretPattern(pattern_id, label, re.compile(source), min_entropy)


SHAPED_PATTERNS: List[SecretPattern] = [
    _sp("SEC.AWS.AKID", "AWS access key id",
        r"\b((?:AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA|ACCA)[0-9A-Z]{16})\b"),
    _sp("SEC.GITHUB.PAT", "GitHub token",
        r"\b((?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{22,255})\b"),
    _sp("SEC.SLACK.TOKEN", "Slack token", r"\b(xox[abprs]-[A-Za-z0-9-]{10,})\b"),
    _sp("SEC.SLACK.WEBHOOK", "Slack webhook URL",
        r"(https://hooks\.slack\.com/services/T[A-Za-z0-9_/+-]{20,})"),
    _sp("SEC.STRIPE.KEY", "Stripe secret key",
        r"\b((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,})\b"),
    _sp("SEC.OPENAI.KEY", "OpenAI API key",
        r"\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,})\b"),
    _sp("SEC.ANTHROPIC.KEY", "Anthropic API key", r"\b(sk-ant-[A-Za-z0-9_-]{24,})\b"),
    _sp("SEC.GOOGLE.APIKEY", "Google API key", r"\b(AIza[0-9A-Za-z_-]{35})\b"),
    _sp("SEC.GCP.SA", "Google service-account key material",
        r"(\"type\"\s*:\s*\"service_account\")"),
    _sp("SEC.AZURE.SECRET", "Azure client secret",
        r"\b([A-Za-z0-9~._-]{3}8Q~[A-Za-z0-9~._-]{34})\b"),
    _sp("SEC.NPM.TOKEN", "npm token", r"\b(npm_[A-Za-z0-9]{36})\b"),
    _sp("SEC.PYPI.TOKEN", "PyPI token",
        r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,})\b"),
    _sp("SEC.SENDGRID.KEY", "SendGrid key",
        r"\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b"),
    _sp("SEC.TWILIO.SID", "Twilio account SID", r"\b(AC[0-9a-fA-F]{32})\b"),
    _sp("SEC.JWT", "JSON Web Token",
        r"\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b"),
    _sp("SEC.PRIVATEKEY", "private key block",
        r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----)"),
    _sp("SEC.DBURL", "database URL with inline password",
        r"\b((?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://"
        r"[^\s:/@]+:[^\s:/@]{6,}@[^\s/]+)"),
    _sp("SEC.HFTOKEN", "Hugging Face token", r"\b(hf_[A-Za-z0-9]{34,})\b"),
    _sp("SEC.GITLAB.PAT", "GitLab token", r"\b(glpat-[A-Za-z0-9_-]{20,})\b"),
    _sp("SEC.DIGITALOCEAN", "DigitalOcean token", r"\b(dop_v1_[a-f0-9]{64})\b"),
    _sp("SEC.SQUARE", "Square access token", r"\b(sq0[a-z]{3}-[A-Za-z0-9_-]{22,})\b"),
    _sp("SEC.TELEGRAM", "Telegram bot token",
        r"\b([0-9]{8,10}:AA[A-Za-z0-9_-]{33})\b"),
]


# --------------------------------------------------------------------------
# Entropy-based detection
# --------------------------------------------------------------------------

#: Keys whose value is expected to be a secret.
SECRET_KEY_RE = re.compile(
    r"(?:^|[_\-.])(?:secret|password|passwd|pwd|token|api[_-]?key|apikey|"
    r"access[_-]?key|private[_-]?key|client[_-]?secret|auth|credential|"
    r"session[_-]?key|encryption[_-]?key|signing[_-]?key|bearer)"
    r"(?:$|[_\-.])",
    re.IGNORECASE,
)

#: Keys that hold a literal password.  Passwords are frequently short and
#: low-entropy -- "hunter2" is still a leaked credential -- so they get their
#: own, looser threshold rather than being lost under the generic floor.
PASSWORD_KEY_RE = re.compile(
    r"(?:^|[_\-.])(?:password|passwd|pwd|passphrase)(?:$|[_\-.])", re.IGNORECASE
)

#: Keys that merely *sound* secret but conventionally are not.
BENIGN_KEY_RE = re.compile(
    r"(?:public[_-]?key|key[_-]?id|token[_-]?(?:url|endpoint|path|name|type|"
    r"count|limit|expiry)|auth[_-]?(?:url|type|method|endpoint|provider)|"
    r"key[_-]?file|secret[_-]?(?:name|ref|path|arn|id))",
    re.IGNORECASE,
)

#: Values that are obviously not live credentials.
PLACEHOLDER_RE = re.compile(
    r"^(?:"
    r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?"                      # ${VAR} / $VAR
    r"|%[A-Za-z_][A-Za-z0-9_]*%"                            # %VAR%
    r"|<[^>]{1,60}>"                                        # <your-token>
    r"|\{\{[^}]{1,60}\}\}"                                  # {{ token }}
    r"|op://[^\s]+|vault:[^\s]+|aws-secrets?:[^\s]+|sops:[^\s]+"
    r"|(?:x{4,}|\*{4,}|\.{4,}|0{8,})"                       # masked
    r")$",
    re.IGNORECASE,
)

PLACEHOLDER_WORDS = re.compile(
    r"^(?:(?:your|my|the)[_-]?)?(?:api[_-]?)?(?:key|token|secret|password|"
    r"value)[_-]?(?:here|goes[_-]?here|placeholder)$"
    r"|^(?:changeme|change[_-]?me|replace[_-]?me|todo|tbd|none|null|nil|"
    r"example|sample|dummy|fake|test|placeholder|redacted|xxx+|notset|"
    r"not[_-]?set|undefined|abc123|foobar|password|secret|insert[_-]?key)$",
    re.IGNORECASE,
)

#: key = value in JSON, YAML, TOML, .env and shell export form.
ASSIGNMENT_RE = re.compile(
    r"""(?P<key>[A-Za-z_][A-Za-z0-9_.\-]{2,64})\s*[:=]\s*"""
    r"""(?P<quote>["']?)(?P<value>[^\s"',}\]]{8,512})(?P=quote)"""
)


@dataclass
class SecretHit:
    pattern_id: str
    label: str
    key: str
    preview: str
    digest: str
    entropy: float
    offset: int
    confidence: str  # high | medium

    def to_dict(self) -> Dict[str, object]:
        return {
            "pattern_id": self.pattern_id,
            "label": self.label,
            "key": self.key,
            "preview": self.preview,
            "digest": self.digest,
            "entropy": round(self.entropy, 2),
            "offset": self.offset,
            "confidence": self.confidence,
        }


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def entropy(value: str) -> float:
    """Shannon entropy in bits per character."""
    if not value:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    length = float(len(value))
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def mask(value: str) -> str:
    """Show just enough to recognise a secret without reproducing it."""
    if len(value) <= 8:
        return value[:2] + "*" * max(0, len(value) - 2)
    return "%s...%s (%d chars)" % (value[:4], value[-2:], len(value))


def digest(value: str) -> str:
    """Stable short hash, so the same secret dedupes across files and runs."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def is_placeholder(value: str) -> bool:
    stripped = value.strip()
    if not stripped:
        return True
    if PLACEHOLDER_RE.match(stripped):
        return True
    if PLACEHOLDER_WORDS.match(stripped):
        return True
    # A value made of one or two distinct characters is never a credential.
    return len(set(stripped)) <= 2


def _looks_structural(value: str) -> bool:
    """Filter values that are paths, plain URLs, versions, emails or numbers."""
    if value.startswith(("/", "./", "../", "~/", "\\\\")):
        return True
    if re.match(r"^[A-Za-z]:[\\/]", value):
        return True
    if re.match(r"^https?://", value) and "@" not in value:
        return True
    if re.match(r"^v?\d+(?:\.\d+){1,3}(?:[-+][\w.]+)?$", value):
        return True
    if re.match(r"^[\w.-]+@[\w.-]+\.[a-z]{2,}$", value, re.IGNORECASE):
        return True
    return bool(re.match(r"^\d{1,5}$", value))


# --------------------------------------------------------------------------
# Scanners
# --------------------------------------------------------------------------


def scan_text(text: str, *, entropy_floor: float = 3.6) -> List[SecretHit]:
    """Find credentials in an arbitrary blob of configuration text."""
    hits: List[SecretHit] = []
    seen: Set[str] = set()

    for pattern in SHAPED_PATTERNS:
        for match in pattern.regex.finditer(text):
            value = match.group(1)
            if is_placeholder(value):
                continue
            if pattern.min_entropy and entropy(value) < pattern.min_entropy:
                continue
            key = digest(value)
            if key in seen:
                continue
            seen.add(key)
            hits.append(
                SecretHit(
                    pattern_id=pattern.id,
                    label=pattern.label,
                    key=_nearest_key(text, match.start()),
                    preview=mask(value),
                    digest=key,
                    entropy=entropy(value),
                    offset=match.start(),
                    confidence="high",
                )
            )

    for match in ASSIGNMENT_RE.finditer(text):
        name = match.group("key")
        value = match.group("value")
        if not SECRET_KEY_RE.search(name) or BENIGN_KEY_RE.search(name):
            continue
        if is_placeholder(value) or _looks_structural(value):
            continue
        if entropy(value) < entropy_floor or len(value) < 12:
            continue
        key = digest(value)
        if key in seen:
            continue
        seen.add(key)
        hits.append(
            SecretHit(
                pattern_id="SEC.ENTROPY.ASSIGNMENT",
                label="high-entropy value bound to a secret-named key",
                key=name,
                preview=mask(value),
                digest=key,
                entropy=entropy(value),
                offset=match.start(),
                confidence="medium",
            )
        )

    hits.sort(key=lambda h: h.offset)
    return hits


def scan_mapping(
    mapping: Dict[str, object], *, prefix: str = "", entropy_floor: float = 3.6
) -> List[SecretHit]:
    """Find credentials in an already-parsed config mapping (an ``env`` block).

    More precise than :func:`scan_text` because the key is unambiguous.
    """
    hits: List[SecretHit] = []
    for raw_key, raw_value in _walk(mapping, prefix):
        value = str(raw_value)
        if is_placeholder(value):
            continue

        shaped = match_shaped(value)
        if shaped:
            pattern_id, label = shaped
            hits.append(
                SecretHit(
                    pattern_id=pattern_id,
                    label=label,
                    key=raw_key,
                    preview=mask(value),
                    digest=digest(value),
                    entropy=entropy(value),
                    offset=-1,
                    confidence="high",
                )
            )
            continue

        if not SECRET_KEY_RE.search(raw_key) or BENIGN_KEY_RE.search(raw_key):
            continue
        if _looks_structural(value):
            continue

        # Passwords are held to a lower bar than API keys: they are chosen by
        # humans, so they are short and predictable by construction, and a
        # weak one sitting in a config file is worse news, not better.
        is_password = bool(PASSWORD_KEY_RE.search(raw_key))
        min_length = 6 if is_password else 12
        min_entropy = 2.0 if is_password else entropy_floor
        if len(value) < min_length or entropy(value) < min_entropy:
            continue

        hits.append(
            SecretHit(
                pattern_id=(
                    "SEC.LITERAL.PASSWORD" if is_password else "SEC.ENTROPY.ASSIGNMENT"
                ),
                label=(
                    "literal password in configuration"
                    if is_password
                    else "high-entropy value bound to a secret-named key"
                ),
                key=raw_key,
                preview=mask(value),
                digest=digest(value),
                entropy=entropy(value),
                offset=-1,
                confidence="medium",
            )
        )
    return hits


def match_shaped(value: str) -> Optional[Tuple[str, str]]:
    """Return ``(pattern_id, label)`` when a value matches a known format."""
    for pattern in SHAPED_PATTERNS:
        match = pattern.regex.search(value)
        if match and not is_placeholder(match.group(1)):
            return pattern.id, pattern.label
    return None


def _walk(mapping: object, prefix: str) -> Iterable[Tuple[str, object]]:
    if isinstance(mapping, dict):
        for key, value in mapping.items():
            path = "%s.%s" % (prefix, key) if prefix else str(key)
            if isinstance(value, (dict, list)):
                for item in _walk(value, path):
                    yield item
            elif value is not None and not isinstance(value, bool):
                yield path, value
    elif isinstance(mapping, list):
        for index, value in enumerate(mapping):
            path = "%s[%d]" % (prefix, index)
            if isinstance(value, (dict, list)):
                for item in _walk(value, path):
                    yield item
            elif value is not None and not isinstance(value, bool):
                yield path, value


def _nearest_key(text: str, offset: int) -> str:
    """Best-effort name of the field a shaped secret was found in."""
    window = text[max(0, offset - 120) : offset]
    matches = re.findall(r"([A-Za-z_][A-Za-z0-9_.\-]{2,64})\s*[:=]\s*[\"']?$", window)
    return matches[-1] if matches else ""


def redact(text: str, *, entropy_floor: float = 3.6) -> str:
    """Replace every detected credential in ``text`` with a stable marker.

    Used by the runtime proxy before a tool result reaches the model, and by
    the reporters before a snippet reaches a file.
    """
    replacements: List[Tuple[int, int, str]] = []
    for pattern in SHAPED_PATTERNS:
        for match in pattern.regex.finditer(text):
            value = match.group(1)
            if is_placeholder(value):
                continue
            replacements.append(
                (
                    match.start(1),
                    match.end(1),
                    "[REDACTED:%s:%s]" % (pattern.id, digest(value)),
                )
            )
    for match in ASSIGNMENT_RE.finditer(text):
        name = match.group("key")
        value = match.group("value")
        if not SECRET_KEY_RE.search(name) or BENIGN_KEY_RE.search(name):
            continue
        if is_placeholder(value) or _looks_structural(value):
            continue
        if entropy(value) < entropy_floor or len(value) < 12:
            continue
        replacements.append(
            (match.start("value"), match.end("value"), "[REDACTED:%s]" % digest(value))
        )

    if not replacements:
        return text

    replacements.sort()
    out: List[str] = []
    cursor = 0
    for start, end, marker in replacements:
        if start < cursor:  # overlapping match already covered
            continue
        out.append(text[cursor:start])
        out.append(marker)
        cursor = end
    out.append(text[cursor:])
    return "".join(out)
