"""Machine-readable and shareable report formats.

Five outputs, each for a different reader:

``json``      other tools and dashboards
``sarif``     GitHub code scanning, GitLab, Azure DevOps, any SARIF consumer
``junit``     CI systems that render test results but not SARIF
``markdown``  pull-request comments and tickets
``html``      the report someone forwards to a manager or an auditor

The HTML report is self-contained -- no external CSS, fonts or scripts -- so it
survives being emailed, opened from a file:// URL, or read on a machine with no
network.  A security report that phones out to render is not a security report.
"""

from __future__ import annotations

import datetime
import html
import json
from typing import Any, Dict, List

from ..core.frameworks import coverage, title_for
from ..core.models import Finding, ScanResult
from ..version import __version__

TOOL_URI = "https://github.com/abdulmanan69/bulwark"


def _iso(epoch: float) -> str:
    """Epoch seconds to an ISO-8601 UTC timestamp.

    SARIF and every downstream consumer want a formatted instant, while the
    scan result stores epoch floats.  The conversion happens once, here.
    """
    moment = datetime.datetime.fromtimestamp(epoch, tz=datetime.timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------
# JSON
# --------------------------------------------------------------------------


def to_json(result: ScanResult, *, indent: int = 2) -> str:
    return json.dumps(result.to_dict(), indent=indent, ensure_ascii=False)


# --------------------------------------------------------------------------
# SARIF 2.1.0
# --------------------------------------------------------------------------


def to_sarif(result: ScanResult) -> str:
    """Emit SARIF 2.1.0.

    Written against the spec rather than against one consumer: rules go in
    ``driver.rules`` with stable ids, every result carries a
    ``partialFingerprints`` entry so a platform can track a finding across
    commits, and ``security-severity`` is populated because that is what
    GitHub uses to decide whether an alert blocks a merge.
    """
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for finding in result.findings:
        if finding.waived:
            continue  # a waiver is a decision; do not re-raise it as an alert
        rules.setdefault(finding.rule_id, _sarif_rule(finding))
        results.append(_sarif_result(finding))

    return json.dumps(
        {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Bulwark",
                            "fullName": "Bulwark agent security posture scanner",
                            "version": __version__,
                            "semanticVersion": __version__,
                            "informationUri": TOOL_URI,
                            "rules": [rules[key] for key in sorted(rules)],
                        }
                    },
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "startTimeUtc": _iso(result.started_at),
                            "endTimeUtc": _iso(result.finished_at or result.started_at),
                            "toolExecutionNotifications": [
                                {
                                    "level": "warning",
                                    "message": {"text": "%s: %s" % (e.where, e.message)},
                                }
                                for e in result.errors[:50]
                            ],
                        }
                    ],
                    "results": results,
                    "properties": {
                        "postureScore": result.posture_score(),
                        "grade": result.grade(),
                        "artifacts": len(result.artifacts),
                        "waived": result.waived_count(),
                    },
                }
            ],
        },
        indent=2,
        ensure_ascii=False,
    )


def _sarif_rule(finding: Finding) -> Dict[str, Any]:
    tags = sorted(set(finding.tags))
    for framework, identifiers in finding.frameworks.items():
        tags.extend("%s/%s" % (framework, i) for i in identifiers)

    return {
        "id": finding.rule_id,
        "name": _pascal(finding.rule_id),
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.description or finding.title},
        "help": {
            "text": finding.remediation or "",
            "markdown": _rule_markdown(finding),
        },
        "helpUri": finding.references[0] if finding.references else TOOL_URI,
        "defaultConfiguration": {"level": finding.severity.sarif_level},
        "properties": {
            "tags": tags,
            "security-severity": str(finding.severity.score),
            "precision": {"LOW": "low", "MEDIUM": "medium", "HIGH": "high"}[
                finding.confidence.name
            ],
        },
    }


def _rule_markdown(finding: Finding) -> str:
    parts = [finding.description or finding.title]
    if finding.remediation:
        parts.append("**Remediation:** " + finding.remediation)
    if finding.frameworks:
        mapped = [
            "`%s %s` %s" % (framework, i, title_for(i))
            for framework, ids in sorted(finding.frameworks.items())
            for i in ids
        ]
        parts.append("**Maps to:** " + ", ".join(mapped))
    return "\n\n".join(parts)


def _sarif_result(finding: Finding) -> Dict[str, Any]:
    location = finding.location
    entry: Dict[str, Any] = {
        "ruleId": finding.rule_id,
        "level": finding.severity.sarif_level,
        "message": {"text": _result_message(finding)},
        "partialFingerprints": {"bulwarkFindingId/v1": finding.fingerprint},
        "properties": {
            "severity": finding.severity.label,
            "confidence": finding.confidence.name,
            "artifact": finding.artifact_identity,
        },
    }

    if location.path:
        region: Dict[str, Any] = {}
        if location.line:
            region["startLine"] = location.line
        if location.column:
            region["startColumn"] = location.column
        if location.snippet:
            region["snippet"] = {"text": location.snippet}
        physical: Dict[str, Any] = {"artifactLocation": {"uri": _uri(location.path)}}
        if region:
            physical["region"] = region
        entry["locations"] = [{"physicalLocation": physical}]
    return entry


def _result_message(finding: Finding) -> str:
    """SARIF shows this one string in the alert list, so it must stand alone."""
    parts = [finding.title]
    if finding.evidence:
        parts.append(
            "Evidence: "
            + "; ".join(
                "%s = %s" % (e.label, _clip(e.value, 120)) for e in finding.evidence[:3]
            )
        )
    if finding.remediation:
        parts.append("Fix: " + _clip(finding.remediation, 220))
    return " -- ".join(parts)


def _uri(path: str) -> str:
    return path.replace("\\", "/")


def _pascal(rule_id: str) -> str:
    return "".join(part.title() for part in rule_id.replace("-", " ").split())


# --------------------------------------------------------------------------
# JUnit
# --------------------------------------------------------------------------


def to_junit(result: ScanResult) -> str:
    """One test case per rule.

    Passing rules are emitted as passes rather than omitted, which is what
    makes a CI dashboard readable over time: a rule that stops firing looks
    different from a rule that stopped running.
    """
    from ..rules import REGISTRY

    failures: Dict[str, List[Finding]] = {}
    for finding in result.active_findings:
        failures.setdefault(finding.rule_id, []).append(finding)

    cases: List[str] = []
    failure_count = 0
    for rule_cls in REGISTRY:
        hits = failures.get(rule_cls.id, [])
        name = _xml(("%s %s" % (rule_cls.id, rule_cls.title))[:180])
        classname = _xml("bulwark." + rule_cls.category)
        if not hits:
            cases.append(
                '    <testcase classname="%s" name="%s" time="0"/>' % (classname, name)
            )
            continue
        failure_count += 1
        detail = "\n".join(
            "%s: %s (%s)" % (f.severity.label, f.title, f.location.path) for f in hits
        )
        cases.append(
            '    <testcase classname="%s" name="%s" time="0">\n'
            '      <failure message="%s" type="%s">%s</failure>\n'
            "    </testcase>"
            % (
                classname,
                name,
                _xml("%d finding(s)" % len(hits)),
                _xml(hits[0].severity.label),
                _xml(detail),
            )
        )

    duration = round((result.finished_at or result.started_at) - result.started_at, 3)
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<testsuites name="bulwark" tests="%d" failures="%d" time="%s">\n'
        '  <testsuite name="agent-security-posture" tests="%d" failures="%d" time="%s">\n'
        "%s\n"
        "  </testsuite>\n"
        "</testsuites>\n"
        % (
            len(cases),
            failure_count,
            duration,
            len(cases),
            failure_count,
            duration,
            "\n".join(cases),
        )
    )


def _xml(text: str) -> str:
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


# --------------------------------------------------------------------------
# Markdown
# --------------------------------------------------------------------------


def to_markdown(result: ScanResult, *, limit: int = 40) -> str:
    counts = result.counts()
    lines: List[str] = [
        "# Bulwark agent security report",
        "",
        "| | |",
        "|---|---|",
        "| **Posture** | %d/100 (grade %s) |"
        % (result.posture_score(), result.grade()),
        "| **Artifacts** | %d |" % len(result.artifacts),
        "| **Findings** | %d (%d waived) |"
        % (len(result.active_findings), result.waived_count()),
        "| **Critical / High** | %d / %d |" % (counts["CRITICAL"], counts["HIGH"]),
        "| **Scanned** | %s |" % _iso(result.started_at),
        "",
    ]

    if not result.active_findings:
        lines.append("No findings.")
        return "\n".join(lines)

    lines.extend(["## Findings", ""])
    for finding in result.active_findings[:limit]:
        location = finding.location
        where = location.path or "(no file)"
        if location.line:
            where += ":%d" % location.line
        lines.extend(
            [
                "### `%s` %s" % (finding.severity.label, finding.title),
                "",
                "- **Rule:** `%s` (%s confidence)"
                % (finding.rule_id, finding.confidence.name.lower()),
                "- **Where:** `%s`" % where,
            ]
        )
        if finding.evidence:
            lines.append("- **Evidence:**")
            for item in finding.evidence[:5]:
                lines.append("  - `%s`: %s" % (item.label, _clip(item.value, 200)))
        if finding.description:
            lines.extend(["", finding.description])
        if finding.remediation:
            lines.extend(["", "> **Fix:** " + finding.remediation])
        if finding.frameworks:
            mapped = [
                "`%s %s`" % (framework, i)
                for framework, ids in sorted(finding.frameworks.items())
                for i in ids
            ]
            lines.extend(["", "*Maps to:* " + ", ".join(mapped)])
        lines.append("")

    if len(result.active_findings) > limit:
        lines.append("_... and %d more._" % (len(result.active_findings) - limit))

    matrix = coverage([f.frameworks for f in result.active_findings])
    if matrix:
        lines.extend(["", "## Control coverage", ""])
        for framework in sorted(matrix):
            entries = ", ".join(
                "%s (%d)" % (i, n) for i, n in sorted(matrix[framework].items())
            )
            lines.append("- **%s:** %s" % (framework, entries))

    return "\n".join(lines)


# --------------------------------------------------------------------------
# HTML
# --------------------------------------------------------------------------

_SEVERITY_HUE = {
    "CRITICAL": "#b3123c",
    "HIGH": "#d4541f",
    "MEDIUM": "#b8860b",
    "LOW": "#2a6f97",
    "INFO": "#6b7280",
}


def to_html(result: ScanResult) -> str:
    counts = result.counts()
    grade = result.grade()

    cards = "".join(
        '<div class="card"><span class="n" style="color:%s">%d</span>'
        '<span class="l">%s</span></div>' % (_SEVERITY_HUE[s], counts[s], s.lower())
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    )

    findings_html = "".join(_html_finding(f) for f in result.active_findings) or (
        '<p class="ok">No findings. Every checked surface came back clean.</p>'
    )

    matrix = coverage([f.frameworks for f in result.active_findings])
    matrix_html = ""
    if matrix:
        rows = []
        for framework in sorted(matrix):
            entries = "".join(
                '<span class="tag">%s <em>%s</em> &times;%d</span>'
                % (html.escape(i), html.escape(title_for(i)), n)
                for i, n in sorted(matrix[framework].items())
            )
            rows.append(
                "<tr><th>%s</th><td>%s</td></tr>" % (html.escape(framework), entries)
            )
        matrix_html = (
            "<h2>Control coverage</h2><table class='matrix'>%s</table>" % "".join(rows)
        )

    return _HTML_TEMPLATE % {
        "title": "Bulwark agent security report",
        "grade": grade,
        "grade_hue": {
            "A": "#1a7f37",
            "B": "#1a7f37",
            "C": "#b8860b",
            "D": "#d4541f",
        }.get(grade, "#b3123c"),
        "score": result.posture_score(),
        "artifacts": len(result.artifacts),
        "findings": len(result.active_findings),
        "waived": result.waived_count(),
        "generated": _iso(result.started_at),
        "version": html.escape(__version__),
        "targets": html.escape(", ".join(result.targets)),
        "cards": cards,
        "findings_html": findings_html,
        "matrix_html": matrix_html,
    }


def _html_finding(finding: Finding) -> str:
    location = finding.location
    where = html.escape(location.path or "(no file)")
    if location.line:
        where += ":%d" % location.line

    evidence = "".join(
        "<li><code>%s</code> %s</li>"
        % (html.escape(item.label), html.escape(_clip(item.value, 400)))
        for item in finding.evidence[:8]
    )
    frameworks = " ".join(
        '<span class="tag">%s %s</span>' % (html.escape(f), html.escape(i))
        for f, ids in sorted(finding.frameworks.items())
        for i in ids
    )

    return (
        '<article class="finding sev-%s">'
        '<header><span class="sev" style="background:%s">%s</span>'
        "<h3>%s</h3></header>"
        '<p class="meta"><code>%s</code> &middot; %s confidence &middot; '
        '<span class="path">%s</span></p>'
        "<p>%s</p>%s"
        '<p class="fix"><strong>Fix:</strong> %s</p>'
        '<p class="tags">%s</p>'
        "</article>"
        % (
            finding.severity.label.lower(),
            _SEVERITY_HUE[finding.severity.label],
            finding.severity.label,
            html.escape(finding.title),
            html.escape(finding.rule_id),
            finding.confidence.name.lower(),
            where,
            html.escape(finding.description),
            ("<ul class='ev'>%s</ul>" % evidence) if evidence else "",
            html.escape(finding.remediation),
            frameworks,
        )
    )


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>%(title)s</title>
<style>
:root{--bg:#ffffff;--fg:#14181f;--muted:#5b6472;--line:#e3e7ed;--panel:#f7f8fa;}
@media (prefers-color-scheme:dark){:root{--bg:#10141a;--fg:#e8ecf2;--muted:#9aa4b2;--line:#252c36;--panel:#171d25;}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
 font:15px/1.6 ui-sans-serif,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:960px;margin:0 auto;padding:32px 16px 72px}
h1{font-size:26px;margin:0 0 4px}
h2{font-size:19px;margin:40px 0 12px;padding-top:20px;border-top:1px solid var(--line)}
h3{font-size:16px;margin:0;font-weight:600}
.sub{color:var(--muted);font-size:13px;margin:0 0 24px}
.hero{display:flex;gap:20px;align-items:center;background:var(--panel);
 border:1px solid var(--line);border-radius:14px;padding:20px;margin-bottom:20px}
.grade{font-size:44px;font-weight:800;line-height:1;width:76px;height:76px;
 display:flex;align-items:center;justify-content:center;border-radius:14px;
 color:#fff;background:%(grade_hue)s;flex:0 0 auto}
.score{font-size:15px;color:var(--muted)}
.score b{font-size:24px;color:var(--fg);display:block}
.cards{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:8px}
.card{flex:1 1 90px;background:var(--panel);border:1px solid var(--line);
 border-radius:10px;padding:12px;text-align:center}
.card .n{display:block;font-size:24px;font-weight:700}
.card .l{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}
.finding{border:1px solid var(--line);border-left-width:4px;border-radius:10px;
 padding:16px;margin:14px 0;background:var(--panel)}
.finding.sev-critical{border-left-color:#b3123c}
.finding.sev-high{border-left-color:#d4541f}
.finding.sev-medium{border-left-color:#b8860b}
.finding.sev-low{border-left-color:#2a6f97}
.finding.sev-info{border-left-color:#6b7280}
.finding header{display:flex;gap:10px;align-items:baseline;margin-bottom:6px}
.sev{color:#fff;font-size:10px;font-weight:700;letter-spacing:.08em;
 padding:3px 7px;border-radius:5px;flex:0 0 auto}
.meta{color:var(--muted);font-size:12px;margin:0 0 10px}
.path{word-break:break-all}
code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px;
 background:rgba(127,127,127,.14);padding:1px 5px;border-radius:4px}
ul.ev{margin:10px 0;padding-left:18px;font-size:13px}
ul.ev li{margin:3px 0;word-break:break-word}
.fix{font-size:13.5px;border-left:3px solid var(--line);padding-left:12px;margin:12px 0 8px}
.tags{margin:8px 0 0}
.tag{display:inline-block;font-size:11px;color:var(--muted);border:1px solid var(--line);
 border-radius:20px;padding:2px 9px;margin:2px 4px 2px 0}
.tag em{font-style:normal;opacity:.8}
.ok{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:20px}
table.matrix{width:100%%;border-collapse:collapse;font-size:13px}
table.matrix th{text-align:left;padding:10px 12px 10px 0;vertical-align:top;
 white-space:nowrap;border-bottom:1px solid var(--line)}
table.matrix td{padding:10px 0;border-bottom:1px solid var(--line)}
footer{margin-top:44px;color:var(--muted);font-size:12px}
@media (max-width:560px){.hero{flex-direction:column;align-items:flex-start}}
</style></head><body><div class="wrap">
<h1>Agent security posture</h1>
<p class="sub">%(targets)s &middot; generated %(generated)s by Bulwark %(version)s</p>
<div class="hero">
  <div class="grade">%(grade)s</div>
  <div class="score"><b>%(score)s / 100</b>
    %(artifacts)s artifacts scanned &middot; %(findings)s findings &middot; %(waived)s waived</div>
</div>
<div class="cards">%(cards)s</div>
<h2>Findings</h2>
%(findings_html)s
%(matrix_html)s
<footer>Bulwark scans the agent attack surface: MCP servers, tool descriptions,
hooks, permission rules and persistent instruction files. Findings are
evidence-backed; re-run with <code>--show-waived</code> to include accepted risk.</footer>
</div></body></html>
"""


# --------------------------------------------------------------------------


def _clip(text: str, limit: int) -> str:
    collapsed = " ".join(str(text).split())
    return collapsed if len(collapsed) <= limit else collapsed[: limit - 3] + "..."


FORMATTERS = {
    "json": to_json,
    "sarif": to_sarif,
    "junit": to_junit,
    "markdown": to_markdown,
    "md": to_markdown,
    "html": to_html,
}


def render(result: ScanResult, fmt: str) -> str:
    formatter = FORMATTERS.get(fmt.lower())
    if formatter is None:
        raise ValueError(
            "unknown format %r; available: %s" % (fmt, ", ".join(sorted(FORMATTERS)))
        )
    return formatter(result)
