# Threat model

What Bulwark defends against, what it does not, and why the boundary is where
it is. Read this before relying on it.

## The system under consideration

An AI coding or task agent running on a developer machine or a CI runner, with:

- one or more **MCP servers**, each a process or endpoint the host starts and
  talks to over JSON-RPC;
- **tool descriptions and schemas** served by those servers, concatenated into
  the model's context window;
- **hooks**, shell commands the host runs automatically on agent events;
- **permission rules** deciding which tool calls skip the human prompt;
- **skills, subagents, slash commands and instruction files**, markdown loaded
  into context;
- the **model**, which reads all of the above as one undifferentiated stream of
  tokens.

That last point is the root of everything here. A model has no reliable way to
distinguish "documentation the operator wrote" from "text an attacker placed in
a tool description" from "content a web page returned". They arrive as the same
kind of thing.

## Adversaries

**A1 - Malicious or compromised MCP server author.** Controls tool names,
descriptions, schemas and returned content. Can change any of them at any time,
including after review. This is the primary adversary.

**A2 - Supply-chain attacker.** Controls a package the server resolves at
launch: a compromised maintainer account, a typosquatted name, a moved git tag.
Gains code execution with the developer's privileges on the next agent start.

**A3 - Content author.** Cannot touch configuration, but can write text the
agent will read: a GitHub issue, a support ticket, a web page, an email, a
filename. Attacks through indirect prompt injection.

**A4 - Insider or careless contributor.** Can open a pull request that edits
`CLAUDE.md`, `.mcp.json` or `.claude/settings.json`. These files change agent
behaviour permanently and are rarely security-reviewed.

**A5 - Local attacker.** Has read access to the filesystem. Harvests
credentials pasted into configuration.

Explicitly **out of scope**: an attacker with arbitrary code execution as the
user. Once that is true, Bulwark is one of the things they can disable.

## What Bulwark actually does

| Against | Control | Where |
|---|---|---|
| A1 poisons a description | Detect model-directed instructions, concealment and credential references in any model-visible string | `scan`, `proxy` |
| A1 hides the payload | Recover Unicode Tag / zero-width / bidi / base64 / HTML-comment content and compare against what renders | `scan`, `proxy` |
| A1 changes it after review | Content-hash every model-visible string; fail on any change | `pin`, `verify`, `proxy` |
| A1 shadows a peer's tool | Detect name collisions across servers and cross-origin directives | `scan` |
| A2 ships new code silently | Classify provenance: pinning, auto-confirm, typosquats, scope impersonation, mutable tags | `scan` |
| A3 injects through content | Scan tool results, strip invisible characters, quarantine on demand | `proxy` |
| A4 edits an instruction file | Treat instruction files as model-visible text and scan them; the lockfile covers them | `scan`, `verify` |
| A5 harvests credentials | Detect secrets in configs; mask them in output; redact them in transit | `scan`, `proxy` |
| Any | Composite exposure: the trifecta, excessive agency, auto-approved destructive tools | `scan` |
| Any | Append-only record of every tool call | `proxy` |

## What it does not do

**It does not make a model injection-proof.** The guard raises the cost of an
injection and records that one was attempted. A sufficiently well-crafted
instruction inside an allowed tool's result can still be followed. The durable
mitigation is architectural: remove one leg of the trifecta.

**It does not analyse server source code.** Bulwark reasons about what a server
*advertises* and *returns*. A server whose description is honest and whose
implementation is malicious will pass a description scan. Provenance rules are
the control for that, and they are about review, not about proof.

**It does not sandbox anything.** It reports that a tool can execute commands;
it does not stop the host from running it. `--deny-tool` removes a tool from
the advertised list, which is a real control, but it is enforced in the proxy,
not by the operating system.

**It does not verify a signature.** MCP has no signing story yet. When one
arrives, the lockfile is where it belongs.

**Capability inference is a heuristic.** It reads names, descriptions and
schemas. A tool that lies about all three will be mis-classified. The schema is
weighted most heavily because it is the hardest to lie about while remaining
functional.

**Offline scans see less than online ones.** Most configs do not list tools, so
a scan without `--online` sees servers but not their descriptions. The trade is
deliberate: `--online` starts third-party processes, which is not something a
scanner should do without being asked.

## Assumptions

1. The machine running Bulwark is not already compromised.
2. Configuration files on disk are the ones the agent will load.
3. `bulwark.lock` was generated from a state someone actually reviewed. A pin
   of an already-poisoned configuration faithfully preserves the poison.
4. The Python interpreter and standard library are trustworthy. Bulwark adds no
   runtime dependencies precisely to keep this list short.

## Bulwark's own attack surface

A security tool that reads attacker-controlled input is a target.

- **Parsing.** Every input is treated as hostile: file reads are size-capped,
  encoding failures degrade rather than raise, and one malformed config does
  not stop a scan.
- **Regex.** All patterns are linear; no nested unbounded quantifiers, so a
  crafted description cannot cause catastrophic backtracking.
- **Reporting.** Attacker text is quoted in reports, so the HTML reporter
  escapes every interpolation and emits no scripts. A test asserts a payload
  cannot open a tag.
- **Secrets.** Detected credentials are never written to a report, a lockfile
  or an audit log - only a masked preview and a hash.
- **The proxy** runs in the data path and fails open on anything it does not
  understand, because a guard that breaks tooling gets removed.
- **Subprocesses** are bounded: timeouts, output caps, forced kill.
- **No network egress.** Nothing is uploaded; remote endpoints are not
  contacted during a scan.

## Reporting a vulnerability

Please report privately through the repository's security advisory process
rather than a public issue.
