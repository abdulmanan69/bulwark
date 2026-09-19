"""Command-line interface.

Nine commands, each answering one question:

``scan``      what is wrong right now
``inventory`` what can my agents reach at all
``pin``       record today's definitions as approved
``diff``      what changed since then
``verify``    fail the build if anything changed (CI)
``rules``     what does this tool actually check
``explain``   why does rule X matter
``aibom``     give me a bill of materials for the agent
``proxy``     enforce policy on a live server

Exit codes are part of the contract, because CI depends on them:
0 clean, 1 findings at or above the threshold, 2 usage error, 3 scan error.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import sys
import textwrap
from typing import List, Optional, Sequence

from .core.models import ScanResult, Severity
from .policy import Policy
from .version import __version__

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_ERROR = 3


def _force_utf8() -> None:
    """Make Unicode output survive a legacy Windows code page.

    This matters more than usual here: the tool's whole job includes reporting
    on characters a console cannot render, and crashing while describing a
    smuggled codepoint would be a poor showing.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            with contextlib.suppress(ValueError, OSError):
                reconfigure(encoding="utf-8", errors="replace")


# --------------------------------------------------------------------------
# Parser
# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bulwark",
        description=(
            "Agent security posture management. Inventories the surface your "
            "AI agents can reach -- MCP servers, tool descriptions, hooks, "
            "permission rules, instruction files -- and reports what is "
            "exploitable about it."
        ),
        epilog="Start with:  bulwark scan  then  bulwark pin",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version="bulwark " + __version__)
    subparsers = parser.add_subparsers(dest="command", metavar="<command>")

    def common(sub: argparse.ArgumentParser) -> None:
        sub.add_argument(
            "path", nargs="*", default=["."], help="project directories to scan"
        )
        sub.add_argument(
            "--no-user-scope",
            action="store_true",
            help="ignore user-level configs; scan only the given directories "
            "(use this in CI)",
        )
        sub.add_argument(
            "--home",
            default=None,
            help="treat this directory as the home directory (for testing or "
            "scanning a mounted image)",
        )
        sub.add_argument(
            "--policy", default=None, help="path to a bulwark.policy.yaml file"
        )
        sub.add_argument("--lock", default=None, help="path to the lockfile")

    # ---- scan ----
    scan_parser = subparsers.add_parser("scan", help="scan for agent security findings")
    common(scan_parser)
    scan_parser.add_argument(
        "--format",
        default="terminal",
        choices=["terminal", "json", "sarif", "junit", "markdown", "md", "html"],
        help="output format (default: terminal)",
    )
    scan_parser.add_argument("-o", "--output", default=None, help="write to a file")
    scan_parser.add_argument(
        "--min-severity",
        default="INFO",
        help="hide findings below this severity (default: INFO)",
    )
    scan_parser.add_argument(
        "--fail-on",
        default=None,
        help="exit non-zero at this severity or above (default: from policy, "
        "else HIGH; 'never' disables)",
    )
    scan_parser.add_argument(
        "--online",
        action="store_true",
        help="start each stdio server and read its real tool list. This runs "
        "third-party code, so it is off by default",
    )
    scan_parser.add_argument(
        "--online-timeout",
        type=float,
        default=20.0,
        help="seconds to wait for each server (default: 20)",
    )
    scan_parser.add_argument(
        "--rule", action="append", default=[], help="run only these rules"
    )
    scan_parser.add_argument(
        "--category", action="append", default=[], help="run only these categories"
    )
    scan_parser.add_argument("--limit", type=int, default=0, help="cap findings shown")
    scan_parser.add_argument("--brief", action="store_true", help="one line per finding")
    scan_parser.add_argument(
        "--show-waived", action="store_true", help="include waived findings"
    )
    scan_parser.add_argument("--no-color", action="store_true", help="disable colour")

    # ---- inventory ----
    inventory_parser = subparsers.add_parser(
        "inventory", help="list every agent surface found"
    )
    common(inventory_parser)
    inventory_parser.add_argument(
        "--format", default="terminal", choices=["terminal", "json"]
    )
    inventory_parser.add_argument("--online", action="store_true")
    inventory_parser.add_argument("--no-color", action="store_true")

    # ---- pin ----
    pin_parser = subparsers.add_parser(
        "pin", help="record the current tool definitions as approved"
    )
    common(pin_parser)
    pin_parser.add_argument("--online", action="store_true")
    pin_parser.add_argument("--note", default="", help="why this state was approved")

    # ---- diff ----
    diff_parser = subparsers.add_parser(
        "diff", help="show what changed since the last pin"
    )
    common(diff_parser)
    diff_parser.add_argument("--online", action="store_true")
    diff_parser.add_argument(
        "--format", default="terminal", choices=["terminal", "json"]
    )

    # ---- verify ----
    verify_parser = subparsers.add_parser(
        "verify", help="fail if anything changed since the pin (for CI)"
    )
    common(verify_parser)
    verify_parser.add_argument("--online", action="store_true")

    # ---- rules ----
    rules_parser = subparsers.add_parser("rules", help="list the available rules")
    rules_parser.add_argument(
        "--format", default="terminal", choices=["terminal", "json"]
    )
    rules_parser.add_argument("--category", default=None)
    rules_parser.add_argument("--no-color", action="store_true")

    # ---- explain ----
    explain_parser = subparsers.add_parser("explain", help="explain one rule in full")
    explain_parser.add_argument("rule_id")
    explain_parser.add_argument(
        "--format", default="terminal", choices=["terminal", "json"]
    )

    # ---- aibom ----
    aibom_parser = subparsers.add_parser(
        "aibom", help="emit an AI bill of materials (CycloneDX)"
    )
    common(aibom_parser)
    aibom_parser.add_argument("--online", action="store_true")
    aibom_parser.add_argument("-o", "--output", default=None)

    # ---- proxy ----
    proxy_parser = subparsers.add_parser(
        "proxy",
        help="run an MCP server behind a policy-enforcing guard",
        description=(
            "Wraps one MCP server. Speaks MCP to the host on stdio and to the "
            "real server on a child process, enforcing tool allow/deny lists, "
            "redacting credentials, scanning results for injected "
            "instructions, and writing an audit log of every call."
        ),
    )
    proxy_parser.add_argument(
        "--server", required=True, help="server name from your MCP config"
    )
    proxy_parser.add_argument("path", nargs="*", default=["."])
    proxy_parser.add_argument("--home", default=None)
    proxy_parser.add_argument("--policy", default=None)
    proxy_parser.add_argument("--lock", default=None)
    proxy_parser.add_argument(
        "--audit-log",
        default=None,
        help="JSONL audit file (default: .bulwark/audit.jsonl)",
    )
    proxy_parser.add_argument(
        "--allow-tool", action="append", default=[], help="only allow these tools"
    )
    proxy_parser.add_argument(
        "--deny-tool", action="append", default=[], help="block these tools"
    )
    proxy_parser.add_argument(
        "--no-redact", action="store_true", help="do not redact credentials"
    )
    proxy_parser.add_argument(
        "--block-injection",
        action="store_true",
        help="replace tool results that contain injected instructions",
    )
    proxy_parser.add_argument(
        "--max-result-bytes", type=int, default=0, help="cap tool result size"
    )
    proxy_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="log what would be blocked without blocking it",
    )

    return parser


# --------------------------------------------------------------------------
# Shared helpers
# --------------------------------------------------------------------------


def _load_policy(args: argparse.Namespace, roots: Sequence[str]) -> Policy:
    if getattr(args, "policy", None):
        try:
            return Policy.load(args.policy)
        except (OSError, ValueError) as exc:
            raise SystemExit(
                "cannot read policy %s: %s" % (args.policy, exc)
            ) from exc
    return Policy.discover(roots)


def _roots(args: argparse.Namespace) -> List[str]:
    return [os.path.abspath(p) for p in (getattr(args, "path", None) or ["."])]


def _run_scan(args: argparse.Namespace, policy: Policy) -> ScanResult:
    from .engine import Engine

    return Engine(policy).scan(
        _roots(args),
        home=getattr(args, "home", None),
        include_user_scope=not getattr(args, "no_user_scope", False),
        online=getattr(args, "online", False),
        lock_path=getattr(args, "lock", None),
        rule_ids=getattr(args, "rule", None) or None,
        categories=getattr(args, "category", None) or None,
        online_timeout=getattr(args, "online_timeout", 20.0),
    )


def _emit(text: str, output: Optional[str]) -> None:
    payload = text if text.endswith("\n") else text + "\n"
    if not output:
        sys.stdout.write(payload)
        return
    directory = os.path.dirname(os.path.abspath(output))
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(output, "w", encoding="utf-8") as handle:
        handle.write(payload)
    sys.stderr.write("wrote %s\n" % output)


def _severity(value: str, default: Severity) -> Severity:
    try:
        return Severity.parse(value)
    except ValueError as exc:
        raise SystemExit("unknown severity %r" % value) from exc


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------


def cmd_scan(args: argparse.Namespace) -> int:
    from .report import TerminalReporter, render

    policy = _load_policy(args, _roots(args))
    result = _run_scan(args, policy)

    if args.format == "terminal":
        reporter = TerminalReporter(colour=False if args.no_color else None)
        reporter.report(
            result,
            minimum=_severity(args.min_severity, Severity.INFO),
            detail=not args.brief,
            limit=args.limit,
            show_waived=args.show_waived,
        )
        _warn_expired(policy)
    else:
        _emit(render(result, args.format), args.output)

    return _exit_code(result, policy, args.fail_on)


def _exit_code(result: ScanResult, policy: Policy, fail_on: Optional[str]) -> int:
    if fail_on and fail_on.lower() in {"never", "none", "off"}:
        return EXIT_OK
    threshold = _severity(fail_on, policy.fail_on) if fail_on else policy.fail_on
    if result.active_findings and result.highest() >= threshold:
        return EXIT_FINDINGS
    return EXIT_OK


def _warn_expired(policy: Policy) -> None:
    if not policy.expired_waivers:
        return
    sys.stderr.write(
        "\n  %d waiver(s) have expired and are no longer suppressing findings:\n"
        % len(policy.expired_waivers)
    )
    for waiver in policy.expired_waivers[:10]:
        sys.stderr.write(
            "    %s (expired %s) %s\n" % (waiver.rule, waiver.expires, waiver.reason)
        )
    sys.stderr.write("\n")


def cmd_inventory(args: argparse.Namespace) -> int:
    from .report import TerminalReporter, print_inventory

    policy = _load_policy(args, _roots(args))
    result = _run_scan(args, policy)

    if args.format == "json":
        _emit(
            json.dumps(
                {
                    "artifacts": [a.to_dict() for a in result.artifacts],
                    "count": len(result.artifacts),
                    "targets": result.targets,
                },
                indent=2,
                ensure_ascii=False,
            ),
            None,
        )
    else:
        print_inventory(
            result, TerminalReporter(colour=False if args.no_color else None)
        )
    return EXIT_OK


def cmd_pin(args: argparse.Namespace) -> int:
    from .engine import pin

    policy = _load_policy(args, _roots(args))
    summary = pin(
        _roots(args),
        lock_path=args.lock,
        note=args.note,
        policy=policy,
        home=args.home,
        include_user_scope=not args.no_user_scope,
        online=args.online,
    )

    changes = summary["changes"]
    sys.stdout.write(
        "Pinned %d definition(s) to %s\n" % (summary["entries"], summary["path"])
    )
    if summary["previous_entries"]:
        sys.stdout.write(
            "  previous pin held %d definition(s)\n" % summary["previous_entries"]
        )
    if changes:
        sys.stdout.write(
            "  %d change(s) were recorded into the new pin:\n" % len(changes)
        )
        for change in changes[:20]:
            sys.stdout.write(
                "    %-18s %s -- %s\n"
                % (change["kind"], change["identity"], change["detail"])
            )
        if len(changes) > 20:
            sys.stdout.write("    ... and %d more\n" % (len(changes) - 20))
    sys.stdout.write(
        "\nCommit this file. `bulwark verify` in CI will now catch drift.\n"
    )
    return EXIT_OK


def cmd_diff(args: argparse.Namespace) -> int:
    policy = _load_policy(args, _roots(args))
    result = _run_scan(args, policy)
    lock_info = result.metadata.get("lockfile") or {}

    if not lock_info.get("present"):
        sys.stderr.write(
            "No lockfile found. Run `bulwark pin` once the current setup is reviewed.\n"
        )
        return EXIT_USAGE

    changes = lock_info.get("changes") or []
    if args.format == "json":
        _emit(json.dumps({"changes": changes}, indent=2, ensure_ascii=False), None)
        return EXIT_FINDINGS if changes else EXIT_OK

    if not changes:
        sys.stdout.write("No change. Every pinned definition matches the lockfile.\n")
        return EXIT_OK

    sys.stdout.write("%d change(s) since the last pin:\n\n" % len(changes))
    for change in changes:
        sys.stdout.write(
            "  %-18s %s\n    %s\n"
            % (change["kind"], change["identity"], change["detail"])
        )
        if change.get("before"):
            sys.stdout.write("    - was: %s\n" % change["before"][:200])
        if change.get("after"):
            sys.stdout.write("    + now: %s\n" % change["after"][:200])
        sys.stdout.write("\n")
    sys.stdout.write(
        "Explain each change before re-pinning. `bulwark pin` accepts them all.\n"
    )
    return EXIT_FINDINGS


def cmd_verify(args: argparse.Namespace) -> int:
    policy = _load_policy(args, _roots(args))
    result = _run_scan(args, policy)
    lock_info = result.metadata.get("lockfile") or {}

    if not lock_info.get("present"):
        sys.stderr.write("verify failed: no lockfile to verify against\n")
        return EXIT_USAGE

    changes = lock_info.get("changes") or []
    material = [c for c in changes if c.get("weight", 0) >= 3]
    if not material:
        sys.stdout.write(
            "verify passed: %s pinned definition(s) unchanged\n"
            % lock_info.get("entries", 0)
        )
        return EXIT_OK

    sys.stderr.write("verify FAILED: %d material change(s)\n" % len(material))
    for change in material[:20]:
        sys.stderr.write(
            "  %-18s %s -- %s\n"
            % (change["kind"], change["identity"], change["detail"])
        )
    return EXIT_FINDINGS


def cmd_rules(args: argparse.Namespace) -> int:
    from .report import TerminalReporter, print_rules
    from .rules import REGISTRY

    selected = [r for r in REGISTRY if not args.category or r.category == args.category]
    if args.format == "json":
        _emit(
            json.dumps([r.describe() for r in selected], indent=2, ensure_ascii=False),
            None,
        )
    else:
        print_rules(selected, TerminalReporter(colour=False if args.no_color else None))
    return EXIT_OK


def cmd_explain(args: argparse.Namespace) -> int:
    from .core.frameworks import describe
    from .rules import REGISTRY

    rule_cls = REGISTRY.get(args.rule_id.upper())
    if rule_cls is None:
        sys.stderr.write(
            "Unknown rule %r. Run `bulwark rules` to see the list.\n" % args.rule_id
        )
        return EXIT_USAGE

    info = rule_cls.describe()
    if args.format == "json":
        _emit(json.dumps(info, indent=2, ensure_ascii=False), None)
        return EXIT_OK

    write = sys.stdout.write
    write("\n%s  %s\n" % (info["id"], info["title"]))
    write("%s\n" % ("=" * min(78, len(info["id"]) + len(info["title"]) + 2)))
    write(
        "severity: %s    confidence: %s    category: %s\n\n"
        % (info["severity"], info["confidence"], info["category"])
    )
    for line in textwrap.wrap(info["description"], 78):
        write(line + "\n")
    if info["remediation"]:
        write("\nHow to fix\n----------\n")
        for line in textwrap.wrap(info["remediation"], 78):
            write(line + "\n")
    if info["frameworks"]:
        write("\nMaps to\n-------\n")
        for line in describe(info["frameworks"]):
            write("  " + line + "\n")
    if info["references"]:
        write("\nReferences\n----------\n")
        for reference in info["references"]:
            write("  " + reference + "\n")
    write("\n")
    return EXIT_OK


def cmd_aibom(args: argparse.Namespace) -> int:
    from .aibom import build

    policy = _load_policy(args, _roots(args))
    result = _run_scan(args, policy)
    _emit(json.dumps(build(result), indent=2, ensure_ascii=False), args.output)
    return EXIT_OK


def cmd_proxy(args: argparse.Namespace) -> int:
    from .proxy.guard import run_proxy

    return run_proxy(args)


COMMANDS = {
    "scan": cmd_scan,
    "inventory": cmd_inventory,
    "pin": cmd_pin,
    "diff": cmd_diff,
    "verify": cmd_verify,
    "rules": cmd_rules,
    "explain": cmd_explain,
    "aibom": cmd_aibom,
    "proxy": cmd_proxy,
}


def main(argv: Optional[Sequence[str]] = None) -> int:
    _force_utf8()
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return EXIT_USAGE

    handler = COMMANDS.get(args.command)
    if handler is None:  # pragma: no cover - argparse rejects these first
        parser.print_help()
        return EXIT_USAGE

    try:
        return handler(args)
    except SystemExit as exc:
        if isinstance(exc.code, int):
            return exc.code
        sys.stderr.write("%s\n" % exc.code)
        return EXIT_USAGE
    except KeyboardInterrupt:
        sys.stderr.write("\ninterrupted\n")
        return EXIT_ERROR
    except BrokenPipeError:  # `bulwark scan | head`
        return EXIT_OK
    except Exception as exc:
        sys.stderr.write("bulwark: %s: %s\n" % (type(exc).__name__, exc))
        if os.environ.get("BULWARK_DEBUG"):
            raise
        sys.stderr.write("Set BULWARK_DEBUG=1 for a traceback.\n")
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
