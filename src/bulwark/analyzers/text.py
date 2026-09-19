"""Text forensics for model-visible strings.

Tool descriptions, skill bodies and prompt templates are concatenated straight
into a model's context window.  An attacker who controls any of that text
controls part of the prompt -- and the text a *human* reviews in a UI is often
not the text the *model* receives.  This module finds that gap.

Everything here is pure: a string in, structured observations out.  No I/O, no
regex catastrophes (all patterns are linear), no dependencies.
"""

from __future__ import annotations

import base64
import binascii
import math
import re
import unicodedata
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

# --------------------------------------------------------------------------
# Codepoint classes that carry meaning to a model but not to a reviewer's eye
# --------------------------------------------------------------------------

#: Characters that render as nothing at all.
ZERO_WIDTH = {
    0x200B: "ZERO WIDTH SPACE",
    0x200C: "ZERO WIDTH NON-JOINER",
    0x200D: "ZERO WIDTH JOINER",
    0x2060: "WORD JOINER",
    0x2061: "FUNCTION APPLICATION",
    0x2062: "INVISIBLE TIMES",
    0x2063: "INVISIBLE SEPARATOR",
    0x2064: "INVISIBLE PLUS",
    0xFEFF: "ZERO WIDTH NO-BREAK SPACE (BOM)",
    0x180E: "MONGOLIAN VOWEL SEPARATOR",
}

#: Bidirectional overrides.  The Trojan Source class of attack: the rendered
#: order of the line differs from the logical order the parser (or model) sees.
BIDI_CONTROLS = {
    0x200E: "LEFT-TO-RIGHT MARK",
    0x200F: "RIGHT-TO-LEFT MARK",
    0x202A: "LEFT-TO-RIGHT EMBEDDING",
    0x202B: "RIGHT-TO-LEFT EMBEDDING",
    0x202C: "POP DIRECTIONAL FORMATTING",
    0x202D: "LEFT-TO-RIGHT OVERRIDE",
    0x202E: "RIGHT-TO-LEFT OVERRIDE",
    0x2066: "LEFT-TO-RIGHT ISOLATE",
    0x2067: "RIGHT-TO-LEFT ISOLATE",
    0x2068: "FIRST STRONG ISOLATE",
    0x2069: "POP DIRECTIONAL ISOLATE",
}

#: Unicode Tags block.  Deprecated for language tagging, renders as nothing in
#: every mainstream UI, and maps 1:1 onto printable ASCII -- which makes it the
#: cleanest available channel for hiding a full sentence of instructions inside
#: a string that looks empty.  U+E0001 is the language-tag introducer;
#: U+E0020..U+E007E are tagged ASCII; U+E007F cancels.
TAG_BLOCK_START = 0xE0000
TAG_BLOCK_END = 0xE007F

#: Variation selectors.  VS1-16 plus the supplement; a recent smuggling channel
#: because each selector can encode a byte while attaching to any base char.
VARIATION_SELECTORS = frozenset(
    list(range(0xFE00, 0xFE10)) + list(range(0xE0100, 0xE01F0))
)

#: Private Use Areas -- no standard meaning, tokenises unpredictably, and is a
#: common carrier for model-specific control sequences.
PRIVATE_USE_RANGES = ((0xE000, 0xF8FF), (0xF0000, 0xFFFFD), (0x100000, 0x10FFFD))

#: Scripts that supply look-alikes for Latin letters.
CONFUSABLE_SCRIPTS = ("CYRILLIC", "GREEK", "ARMENIAN", "CHEROKEE", "COPTIC")

#: The subset of confusables that matter in practice: identical-looking glyphs
#: used to smuggle a different token sequence past a human reviewer.
HOMOGLYPHS: Dict[str, str] = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "у": "y", "х": "x", "і": "i", "ј": "j", "һ": "h",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M",
    "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T",
    "Х": "X", "Ѕ": "S", "І": "I", "Ј": "J",
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "υ": "u",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H",
    "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O",
    "Ρ": "P", "Τ": "T", "Χ": "X",
    "Ꭰ": "D", "Ꭱ": "R", "Ꮩ": "V",
    "ａ": "a", "ｏ": "o",  # fullwidth
}


@dataclass
class Observation:
    """One suspicious thing found in a string."""

    kind: str
    detail: str
    offset: int = -1
    sample: str = ""
    count: int = 1

    def to_dict(self) -> Dict[str, object]:
        return {
            "kind": self.kind,
            "detail": self.detail,
            "offset": self.offset,
            "sample": self.sample,
            "count": self.count,
        }


# --------------------------------------------------------------------------
# Primitives
# --------------------------------------------------------------------------


def codepoint_name(ch: str) -> str:
    try:
        return unicodedata.name(ch)
    except ValueError:
        return "U+%04X" % ord(ch)


def in_private_use(cp: int) -> bool:
    return any(low <= cp <= high for low, high in PRIVATE_USE_RANGES)


def decode_tag_block(text: str) -> str:
    """Recover the ASCII hidden in Unicode Tag characters.

    U+E0020..U+E007E map onto U+0020..U+007E by subtracting 0xE0000, which is
    what makes the block a clean smuggling channel.  Returns "" when the text
    carries no tag characters.
    """
    out: List[str] = []
    for ch in text:
        cp = ord(ch)
        if 0xE0020 <= cp <= 0xE007E:
            out.append(chr(cp - 0xE0000))
    return "".join(out)


def strip_invisible(text: str) -> str:
    """Return the text with every invisible carrier removed.

    This is the string a human effectively reads.  Comparing it against the raw
    string is how we prove a description renders differently than it parses.
    """
    keep: List[str] = []
    for ch in text:
        cp = ord(ch)
        if cp in ZERO_WIDTH or cp in BIDI_CONTROLS:
            continue
        if TAG_BLOCK_START <= cp <= TAG_BLOCK_END:
            continue
        if cp in VARIATION_SELECTORS:
            continue
        if in_private_use(cp):
            continue
        if unicodedata.category(ch) == "Cf":
            continue
        keep.append(ch)
    return "".join(keep)


def normalise_homoglyphs(text: str) -> str:
    """Fold known look-alike letters onto their Latin equivalents."""
    return "".join(HOMOGLYPHS.get(ch, ch) for ch in text)


def visible_text(text: str) -> str:
    """What a reviewer sees: invisibles stripped, homoglyphs folded, NFKC."""
    return unicodedata.normalize("NFKC", normalise_homoglyphs(strip_invisible(text)))


def shannon_entropy(data: str) -> float:
    """Bits per character.  Used to spot encoded payloads in prose."""
    if not data:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in data:
        counts[ch] = counts.get(ch, 0) + 1
    length = float(len(data))
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


# --------------------------------------------------------------------------
# Scanners
# --------------------------------------------------------------------------


def find_invisible(text: str) -> List[Observation]:
    """Zero-width, bidi, tag-block, variation-selector and PUA characters."""
    observations: List[Observation] = []
    buckets: Dict[str, List[Tuple[int, str]]] = {}

    for index, ch in enumerate(text):
        cp = ord(ch)
        kind: Optional[str] = None
        detail = ""
        if cp in ZERO_WIDTH:
            kind, detail = "zero_width", ZERO_WIDTH[cp]
        elif cp in BIDI_CONTROLS:
            kind, detail = "bidi_control", BIDI_CONTROLS[cp]
        elif TAG_BLOCK_START <= cp <= TAG_BLOCK_END:
            kind, detail = "tag_block", "U+%05X" % cp
        elif cp in VARIATION_SELECTORS:
            kind, detail = "variation_selector", "U+%04X" % cp
        elif in_private_use(cp):
            kind, detail = "private_use", "U+%04X" % cp
        elif unicodedata.category(ch) == "Cc" and ch not in "\n\r\t":
            kind, detail = "control_char", "U+%04X" % cp
        if kind:
            buckets.setdefault(kind, []).append((index, detail))

    for kind, hits in buckets.items():
        names = sorted({detail for _, detail in hits})
        observations.append(
            Observation(
                kind=kind,
                detail=", ".join(names[:6]) + ("..." if len(names) > 6 else ""),
                offset=hits[0][0],
                count=len(hits),
            )
        )

    hidden = decode_tag_block(text)
    if hidden:
        observations.append(
            Observation(
                kind="tag_block_payload",
                detail="ASCII recovered from Unicode Tag characters",
                sample=hidden[:400],
                count=len(hidden),
            )
        )
    return observations


def find_homoglyphs(text: str) -> List[Observation]:
    """Mixed-script words that read as Latin but tokenise differently."""
    observations: List[Observation] = []
    for match in re.finditer(r"[^\W\d_]{2,}", text, re.UNICODE):
        word = match.group(0)
        scripts = set()
        for ch in word:
            name = codepoint_name(ch)
            for script in CONFUSABLE_SCRIPTS:
                if name.startswith(script):
                    scripts.add(script)
        has_latin = any(codepoint_name(ch).startswith("LATIN") for ch in word)
        if scripts and has_latin:
            observations.append(
                Observation(
                    kind="mixed_script",
                    detail="Latin mixed with " + ", ".join(sorted(scripts)),
                    offset=match.start(),
                    sample=word,
                )
            )
    return observations


_BASE64_RE = re.compile(
    r"(?<![A-Za-z0-9+/=])((?:[A-Za-z0-9+/]{4}){6,}(?:[A-Za-z0-9+/]{2,3}={0,2})?)"
)
_HEX_BLOB_RE = re.compile(r"(?<![0-9A-Fa-f])((?:[0-9A-Fa-f]{2}){16,})(?![0-9A-Fa-f])")


def find_encoded_payloads(text: str) -> List[Observation]:
    """Base64 / hex blobs that decode to readable instructions.

    Only reported when the decode succeeds *and* the result is mostly printable
    -- an opaque binary blob in a description is odd but not itself an attack,
    while a base64 sentence is a deliberate reviewer-evasion step.
    """
    observations: List[Observation] = []

    for match in _BASE64_RE.finditer(text):
        blob = match.group(1)
        if len(blob) > 4096:
            continue
        decoded = _try_base64(blob)
        if decoded and _printable_ratio(decoded) > 0.85:
            observations.append(
                Observation(
                    kind="base64_payload",
                    detail="base64 decodes to readable text",
                    offset=match.start(),
                    sample=decoded[:300],
                )
            )

    for match in _HEX_BLOB_RE.finditer(text):
        blob = match.group(1)
        if len(blob) > 8192:
            continue
        try:
            decoded = binascii.unhexlify(blob).decode("utf-8", "strict")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if _printable_ratio(decoded) > 0.85:
            observations.append(
                Observation(
                    kind="hex_payload",
                    detail="hex decodes to readable text",
                    offset=match.start(),
                    sample=decoded[:300],
                )
            )
    return observations


def _try_base64(blob: str) -> str:
    padded = blob + "=" * (-len(blob) % 4)
    try:
        raw = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return ""
    try:
        return raw.decode("utf-8", "strict")
    except UnicodeDecodeError:
        return ""


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\n\r\t")
    return printable / len(text)


_HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
_HTML_HIDDEN_RE = re.compile(
    r"<[^>]*(?:style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|"
    r"font-size\s*:\s*0|opacity\s*:\s*0)[^\"']*[\"']|hidden(?:\s|=|>))[^>]*>",
    re.IGNORECASE,
)


def find_hidden_markup(text: str) -> List[Observation]:
    """HTML comments and CSS-hidden elements carrying instructions."""
    observations: List[Observation] = []
    for match in _HTML_COMMENT_RE.finditer(text):
        body = match.group(1).strip()
        if len(body) >= 12:
            observations.append(
                Observation(
                    kind="html_comment",
                    detail="instruction-length text inside an HTML comment",
                    offset=match.start(),
                    sample=body[:300],
                )
            )
    for match in _HTML_HIDDEN_RE.finditer(text):
        observations.append(
            Observation(
                kind="hidden_markup",
                detail="element styled to be invisible",
                offset=match.start(),
                sample=match.group(0)[:200],
            )
        )
    return observations


def find_layout_evasion(text: str) -> List[Observation]:
    """Padding tricks that push a payload out of a reviewer's viewport."""
    observations: List[Observation] = []

    blank_run = re.search(r"(?:[ \t]*\n){8,}", text)
    if blank_run:
        observations.append(
            Observation(
                kind="blank_padding",
                detail="long run of blank lines hides text below the fold",
                offset=blank_run.start(),
                count=blank_run.group(0).count("\n"),
            )
        )

    space_run = re.search(r"[ \t]{120,}", text)
    if space_run:
        observations.append(
            Observation(
                kind="space_padding",
                detail="long horizontal run pushes text off-screen",
                offset=space_run.start(),
                count=len(space_run.group(0)),
            )
        )

    for line_no, line in enumerate(text.splitlines(), start=1):
        if len(line) > 2000:
            observations.append(
                Observation(
                    kind="long_line",
                    detail="line %d is %d characters" % (line_no, len(line)),
                    offset=line_no,
                    count=len(line),
                )
            )
            break
    return observations


def render_gap(text: str) -> Optional[Observation]:
    """Report when the rendered string differs materially from the raw one."""
    shown = visible_text(text)
    if shown == text:
        return None
    removed = len(text) - len(shown)
    if removed <= 0:
        return None
    return Observation(
        kind="render_gap",
        detail="%d characters are invisible or folded when rendered" % removed,
        sample=shown[:200],
        count=removed,
    )


def analyze(text: str) -> List[Observation]:
    """Run every text scanner and return the merged observation list."""
    if not text:
        return []
    observations: List[Observation] = []
    observations.extend(find_invisible(text))
    observations.extend(find_homoglyphs(text))
    observations.extend(find_encoded_payloads(text))
    observations.extend(find_hidden_markup(text))
    observations.extend(find_layout_evasion(text))
    gap = render_gap(text)
    if gap:
        observations.append(gap)
    return observations


def summarise(observations: Sequence[Observation]) -> Dict[str, int]:
    """Collapse observations into ``kind -> total count`` for reporting."""
    out: Dict[str, int] = {}
    for obs in observations:
        out[obs.kind] = out.get(obs.kind, 0) + obs.count
    return out
