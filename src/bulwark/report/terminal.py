"""Human-readable terminal output.

Plain ANSI, no dependency.  Security tooling runs in minimal containers, and a
report that only renders with an optional package is a report someone will
eventually not see.

Two levels of detail.  The summary answers "is anything on fire"; the detail
view answers "what exactly, where, and what do I type to fix it" -- because a
finding a reader cannot act on is just anxiety.
"""

from __future__ import annotations

import os
import sys
import textwrap
from typing import Any, Dict, List, Optional, Sequence, TextIO

from ..core.frameworks import describe
from ..core.models import Artifact, Finding, ScanResult, Severity

#: ANSI colours, used only when the stream is a real terminal.
_COLOURS = {
    Severity.CRITICAL: "\033[1;97;41m",
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[1;33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[90m",
}
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"

_GRADE_COLOUR = {
    "A": "\033[1;32m",
    "B": "\033[1;32m",
    "C": "\033[1;33m",
    "D": "\033[1;31m",
    "F": "\033[1;97;41m",
}

_ORDERED = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)


def supports_colour(stream: TextIO) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    if not hasattr(stream, "isatty") or not stream.isatty():
        return False
    if sys.platform == "win32":
        # Modern Windows terminals handle ANSI; the legacy console does not,
        # and it is identifiable by the absence of these markers.
        return bool(
            os.environ.get("WT_SESSION")
            or os.environ.get("ANSICON")
            or os.environ.get("TERM_PROGRAM")
        )
    return os.environ.get("TERM", "") != "dumb"


class TerminalReporter:
    def __init__(
        self,
        stream: Optional[TextIO] = None,
        *,
        colour: Optional[bool] = None,
        width: int = 0,
    ) -> None:
        self.stream = stream or sys.stdout
        self.colour = supports_colour(self.stream) if colour is None else colour
        self.width = width or _terminal_width()

    # ---- helpers ---------------------------------------------------------

    def paint(self, text: str, code: str) -> str:
        return "%s%s%s" % (code, text, _RESET) if self.colour else text

    def write(self, text: str = "") -> None:
        try:
            self.stream.write(text + "\n")
        except UnicodeEncodeError:
            # A legacy code page cannot render every character we might quote
            # from a config.  Losing the decoration is fine; losing the report
            # is not.
            self.stream.write(text.encode("ascii", "replace").decode("ascii") + "\n")

    def rule(self, char: str = "-") -> None:
        self.write(self.paint(char * min(self.width, 100), _DIM))

    # ---- sections --------------------------------------------------------

    def summary(self, result: ScanResult) -> None:
        counts = result.counts()
        grade = result.grade()

        self.write()
        self.write(self.paint("  BULWARK  agent security posture", _BOLD))
        self.rule("=")

        painted_grade = (
            self.paint(" %s " % grade, _GRADE_COLOUR.get(grade, ""))
            if self.colour
            else "[%s]" % grade
        )
        self.write(
            "  posture %s  %d/100     %d artifacts    %d findings    %d waived"
            % (
                painted_grade,
                result.posture_score(),
                len(result.artifacts),
                len(result.active_findings),
                result.waived_count(),
            )
        )

        parts: List[str] = []
        for severity in _ORDERED:
            count = counts[severity.label]
            if count:
                parts.append(
                    self.paint(
                        "%d %s" % (count, severity.label.lower()), _COLOURS[severity]
                    )
                )
        self.write("  " + ("   ".join(parts) if parts else "no findings"))

        lock = result.metadata.get("lockfile") or {}
        if lock.get("present"):
            changes = lock.get("changes") or []
            state = (
                self.paint(
                    "%d change(s) since pin" % len(changes), _COLOURS[Severity.HIGH]
                )
                if changes
                else self.paint("matches pin", _COLOURS[Severity.INFO])
            )
            self.write("  lockfile: %s entries, %s" % (lock.get("entries", 0), state))
        else:
            self.write(
                "  lockfile: %s"
                % self.paint("none - run `bulwark pin`", _COLOURS[Severity.MEDIUM])
            )
        self.rule("=")

    def findings(
        self,
        result: ScanResult,
        *,
        minimum: Severity = Severity.INFO,
        detail: bool = True,
        limit: int = 0,
        show_waived: bool = False,
    ) -> None:
        shown = [
            f
            for f in result.findings
            if (show_waived or not f.waived) and f.severity >= minimum
        ]
        total = len(shown)
        if limit:
            shown = shown[:limit]

        if not shown:
            self.write()
            self.write("  No findings at or above %s." % minimum.label)
            return

        current: Optional[Severity] = None
        for index, finding in enumerate(shown, start=1):
            if finding.severity != current:
                current = finding.severity
                self.write()
                self.write(self.paint("  %s " % current.label, _COLOURS[current]))
            self._finding(index, finding, detail)

        self.write()
        if limit and total > limit:
            self.write(
                "  ... %d more finding(s). Use --limit 0 to see all." % (total - limit)
            )

    def _finding(self, index: int, finding: Finding, detail: bool) -> None:
        marker = self.paint("[waived] ", _DIM) if finding.waived else ""
        self.write()
        self.write(
            "  %s%s  %s%s"
            % (
                marker,
                self.paint(finding.rule_id, _BOLD),
                finding.title,
                self.paint("  (%s confidence)" % finding.confidence.name.lower(), _DIM),
            )
        )

        location = finding.location
        if location.path:
            where = location.path
            if location.line:
                where += ":%d" % location.line
            self.write("      %s %s" % (self.paint("at", _DIM), where))

        if not detail:
            return

        if finding.description:
            for line in _wrap(finding.description, self.width - 8):
                self.write("      " + line)

        if finding.evidence:
            self.write("      " + self.paint("evidence", _DIM))
            for item in finding.evidence[:6]:
                self.write(
                    "        - %s: %s"
                    % (self.paint(item.label, _BOLD), _one_line(item.value, self.width - 20))
                )

        if finding.remediation:
            self.write("      " + self.paint("fix", _BOLD))
            for line in _wrap(finding.remediation, self.width - 10):
                self.write("        " + line)

        if finding.frameworks:
            mapped = describe(finding.frameworks)
            self.write("      " + self.paint("maps to  " + "; ".join(mapped[:4]), _DIM))

        if finding.waived and finding.waiver_reason:
            self.write("      " + self.paint("waived: " + finding.waiver_reason, _DIM))

    def errors(self, result: ScanResult) -> None:
        real = [e for e in result.errors if e.kind not in {"info", "skipped"}]
        if not real:
            return
        self.write()
        self.write(self.paint("  scan warnings", _COLOURS[Severity.MEDIUM]))
        for error in real[:12]:
            self.write("    %s: %s" % (error.where, _one_line(error.message, 120)))
        if len(real) > 12:
            self.write("    ... and %d more" % (len(real) - 12))

    def next_steps(self, result: ScanResult) -> None:
        """Turn the report into the next thing to type.

        Deliberately specific.  "Review your configuration" is advice nobody
        acts on; a command they can paste is.
        """
        steps: List[str] = []
        rule_ids = {f.rule_id for f in result.active_findings}

        if not (result.metadata.get("lockfile") or {}).get("present"):
            steps.append("bulwark pin          # record today's definitions as approved")
        if "BW-DRF-001" in rule_ids:
            steps.append("bulwark diff         # see exactly what changed since the pin")
        if rule_ids & {"BW-INJ-001", "BW-INJ-002", "BW-INJ-003", "BW-CMP-003"}:
            steps.append("bulwark explain BW-INJ-001   # why a description can attack you")
        if rule_ids & {"BW-CMP-001", "BW-CMP-005"}:
            steps.append("bulwark proxy --server <name>   # enforce limits at runtime")
        steps.append("bulwark scan --format sarif -o bulwark.sarif   # for code scanning")

        self.write()
        self.write(self.paint("  next", _BOLD))
        for step in steps:
            self.write("    " + step)
        self.write()

    # ---- whole report ----------------------------------------------------

    def report(
        self,
        result: ScanResult,
        *,
        minimum: Severity = Severity.INFO,
        detail: bool = True,
        limit: int = 0,
        show_waived: bool = False,
        show_next: bool = True,
    ) -> None:
        self.summary(result)
        self.findings(
            result, minimum=minimum, detail=detail, limit=limit, show_waived=show_waived
        )
        self.errors(result)
        if show_next:
            self.next_steps(result)


# --------------------------------------------------------------------------
# Inventory and rule listings
# --------------------------------------------------------------------------


def print_inventory(result: ScanResult, reporter: TerminalReporter) -> None:
    """The plain answer to "what can my agents actually reach"."""
    by_kind: Dict[str, List[Artifact]] = {}
    for artifact in result.artifacts:
        by_kind.setdefault(artifact.kind.value, []).append(artifact)

    reporter.write()
    reporter.write(reporter.paint("  AGENT INVENTORY", _BOLD))
    reporter.rule("=")

    for kind in sorted(by_kind):
        items = by_kind[kind]
        reporter.write()
        reporter.write(
            "  %s (%d)" % (reporter.paint(kind.replace("_", " "), _BOLD), len(items))
        )
        for artifact in sorted(items, key=lambda a: a.identity)[:60]:
            bits: List[str] = []
            if artifact.trust and artifact.trust != "unknown":
                bits.append(artifact.trust)
            if artifact.capabilities:
                bits.append("+".join(artifact.capabilities[:4]))
            if artifact.data.get("disabled"):
                bits.append("disabled")
            if artifact.data.get("auto_approved"):
                bits.append("auto-approved")
            suffix = reporter.paint("  [%s]" % ", ".join(bits), _DIM) if bits else ""
            reporter.write("    %-44s%s" % (artifact.identity[:44], suffix))
        if len(items) > 60:
            reporter.write("    ... and %d more" % (len(items) - 60))
    reporter.write()


def print_rules(rules: Sequence[Any], reporter: TerminalReporter) -> None:
    reporter.write()
    reporter.write(reporter.paint("  RULES (%d)" % len(rules), _BOLD))
    reporter.rule("=")
    current = ""
    for rule in rules:
        info = rule.describe() if hasattr(rule, "describe") else rule
        if info["category"] != current:
            current = info["category"]
            reporter.write()
            reporter.write("  " + reporter.paint(current, _BOLD))
        severity = Severity.parse(info["severity"])
        reporter.write(
            "    %-12s %-9s %s"
            % (
                info["id"],
                reporter.paint(severity.label, _COLOURS[severity]),
                info["title"][:70],
            )
        )
    reporter.write()


# --------------------------------------------------------------------------
# Text helpers
# --------------------------------------------------------------------------


def _terminal_width() -> int:
    try:
        return max(60, min(120, os.get_terminal_size().columns))
    except OSError:
        return 100


def _wrap(text: str, width: int) -> List[str]:
    return textwrap.wrap(" ".join(text.split()), width=max(40, width)) or [""]


def _one_line(text: str, width: int) -> str:
    collapsed = " ".join(str(text).split())
    limit = max(40, width)
    return collapsed if len(collapsed) <= limit else collapsed[: limit - 3] + "..."
