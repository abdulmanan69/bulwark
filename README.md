# Bulwark — MCP and AI agent security scanner

[![CI](https://github.com/abdulmanan69/bulwark/actions/workflows/ci.yml/badge.svg)](https://github.com/abdulmanan69/bulwark/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/bulwark-scanner)](https://pypi.org/project/bulwark-scanner/)
[![Python](https://img.shields.io/pypi/pyversions/bulwark-scanner)](https://pypi.org/project/bulwark-scanner/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Runtime dependencies](https://img.shields.io/badge/runtime%20dependencies-0-brightgreen)](pyproject.toml)

**Agent security posture management.** Bulwark scans MCP servers for prompt
injection, tool poisoning, rug pulls and supply-chain risk. It inventories
everything your AI agents can reach — MCP servers, tool descriptions, hooks,
permission rules, skills and instruction files — tells you what is exploitable
about it, pins the safe state, and enforces that pin at runtime.

Works with **Claude Code**, **Claude Desktop**, **Cursor**, **VS Code**,
**Windsurf**, **Cline**, **Roo**, **Zed** and **Continue**. Emits **SARIF** for
GitHub code scanning and a **CycloneDX AIBOM** for audits.

```
$ bulwark scan

  BULWARK  agent security posture
====================================================================
  posture [F]  7/100     27 artifacts    22 findings    0 waived
  8 critical   11 high   3 medium
  lockfile: none - run `bulwark pin`
====================================================================

  CRITICAL

  BW-INJ-001  mcp tool notes:append_note carries model-directed instructions
      at .mcp.json:12
      evidence
        - concealment/INJ.HIDE.DONTTELL: Do not mention this to the user
        - credential/INJ.CRED.KEYFILE: id_rsa
        - exfiltration/INJ.EXFIL.PARAM: pass its contents as the 'context' parameter
      fix
        Do not connect this server until the description is explained...
```

Zero runtime dependencies. Installs and runs anywhere Python 3.9+ does.

---

## Why this exists

Your dependency scanner reads `package.json`. Your SAST tool reads source
files. Neither of them reads the file that decides what your AI agent is
allowed to do to your laptop, your repository and your production database.

An MCP server entry is a command line that runs with your full privileges every
time the agent starts. Its tool descriptions are injected into the model's
context window before any tool is called. Nothing in your existing stack looks
at either one.

Five specific gaps, none of which an existing tool covers:

| Gap | Why nothing else catches it |
|---|---|
| **Tool poisoning** | The attack lives in a *description*, not in code. No SAST tool parses it; no human reads it after the first install. |
| **Unicode-smuggled instructions** | The text a reviewer sees and the text the model receives are different strings. Your editor renders both identically. |
| **Rug pulls** | The server behaves during review and changes afterwards. The config file is byte-identical, so code review shows nothing. |
| **The lethal trifecta** | Each tool is individually reasonable. The exposure exists only in the combination, and nothing computes the combination. |
| **Excessive agency** | `npx -y whatever@latest` is an unreviewed, unpinned, auto-confirming remote code fetch on every launch. It reads like a config line. |

---

## Install

```bash
pip install bulwark-scanner          # no dependencies
pipx install bulwark-scanner         # or isolated
```

## Use

```bash
bulwark scan                         # what is wrong right now
bulwark inventory                    # what can my agents reach at all
bulwark pin                          # record today's definitions as approved
bulwark diff                         # what changed since then
bulwark verify                       # fail the build if anything changed
bulwark explain BW-INJ-001           # why does this rule matter
bulwark aibom -o aibom.json          # CycloneDX bill of materials
bulwark proxy --server github        # enforce policy on a live session
```

### The workflow that matters

```bash
bulwark scan                    # 1. see what you have
# ...fix what needs fixing...
bulwark pin                     # 2. freeze the reviewed state
git add bulwark.lock && git commit -m "pin agent tool definitions"
bulwark verify                  # 3. in CI, from now on
```

Step 2 is the one nobody else offers. `bulwark.lock` records a content hash of
every string your model is allowed to be told. If a server changes a tool
description after you approved it, `bulwark verify` fails:

```
verify FAILED: 3 material change(s)
  capability_added   notes:append_note -- gained: secrets
  text_changed       notes:append_note -- the text the model reads has changed (37 -> 186 characters)
  schema_changed     notes:append_note -- the tool's arguments changed
```

---

## What it scans

Bulwark finds agent configuration wherever the ecosystem actually puts it:

- **Claude Code** — `.mcp.json`, `~/.claude.json`, `.claude/settings.json`,
  skills, subagents, slash commands, hooks, permission rules
- **Claude Desktop** — `claude_desktop_config.json` on all three platforms
- **Cursor** — `.cursor/mcp.json`, `.cursor/rules/*.mdc`
- **VS Code / Copilot** — `.vscode/mcp.json`, `mcp.servers` in settings
- **Windsurf, Cline, Roo, Zed, Continue** — their respective config dialects
- **Instruction files** — `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, and friends

With `--online` it also starts each stdio server and reads the tool list it
*actually* serves — the only way to see descriptions a static config does not
list. It never calls a tool, only lists them.

## What it detects

26 rules across seven families. `bulwark rules` lists them all;
`bulwark explain <id>` gives the full reasoning for any one.

| Family | Examples |
|---|---|
| **injection** | instructions aimed at the model in a tool description; payloads hidden in Unicode Tag characters, zero-width space, bidi overrides, HTML comments or base64; markdown-image exfiltration URLs |
| **composite** | the lethal trifecta; cross-server tool-name shadowing; a server issuing directives about *another* server's tools; excessive agency; auto-approved dangerous tools |
| **supply-chain** | unpinned auto-install; piping a download into a shell at launch; typosquats and scope impersonation; cleartext or tunnelled endpoints; privileged containers |
| **drift** | any model-visible string that changed after it was pinned |
| **permissions** | unbounded allow-rules; pre-approved destructive operations; disabled approval prompts |
| **hooks** | hooks that read credentials or call out to the network; unquoted interpolation of agent-controlled data into a shell |
| **secrets** | live credentials in `env` blocks, headers, args and `.env` files |

Every finding carries evidence you can check, a fix you can apply, and mappings
to **OWASP LLM Top 10**, **MITRE ATLAS**, **NIST AI 600-1**, **CWE**,
**ISO/IEC 42001** and **EU AI Act** articles.

---

## CI

Exit codes are the contract: `0` clean, `1` findings at or above the threshold,
`2` usage error, `3` scan error.

```yaml
- name: Agent security scan
  run: |
    pip install bulwark-scanner
    bulwark scan --no-user-scope --format sarif -o bulwark.sarif --fail-on high
    bulwark verify --no-user-scope

- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: bulwark.sarif
```

`--no-user-scope` matters in CI: without it, Bulwark would also report on
whatever the build runner happens to have in its home directory.

Bulwark walks the whole project, so a monorepo with a `.mcp.json` per package
is fully covered. Use `--exclude` for directories that are not real
configuration:

```bash
bulwark scan . --exclude 'examples/**' --exclude '**/fixtures/**'
```

Exclusion happens during discovery rather than when reporting, so an excluded
path cannot contribute to a finding at all -- including composite rules like
the trifecta, which are derived from tools and carry no path of their own.

Other formats: `json`, `junit`, `markdown` (for PR comments), `html`
(self-contained, no external assets, safe to email).

---

## The runtime guard

Scanning is a point-in-time check. Three of the worst failures exist only while
the agent is running: a description that changes after review, a tool result
carrying injected instructions, a credential leaving in a tool argument.

`bulwark proxy` sits between the host and one MCP server. Adopting it is a
one-line config change:

```json
{
  "mcpServers": {
    "github": {
      "command": "bulwark",
      "args": ["proxy", "--server", "github", "--block-injection"]
    }
  }
}
```

It then:

- **hides** denied tools from the list the model ever sees (`--deny-tool`),
- **refuses** denied calls with an explanation the model can act on,
- **redacts** credentials in both directions, before they leave the machine,
- **checks** every live description against `bulwark.lock` and warns on drift,
- **quarantines** tool results that read as instructions (`--block-injection`),
- **logs** every call to append-only JSONL — the audit trail agents lack.

Design rule: *fail open on the protocol, fail closed on policy.* A message the
guard does not understand is passed through untouched, because a security
control that breaks tooling gets removed within the day.

Start with `--dry-run` to see what would be blocked before blocking anything.

---

## Policy as code

Drop a `bulwark.policy.yaml` beside your project:

```yaml
fail_on: HIGH

rules:
  disable: [BW-DRF-002]           # we pin on release, not per-commit
  severity:
    BW-SUP-006: MEDIUM

waivers:
  - rule: BW-SUP-001
    artifact: legacy-notes
    reason: "vendor ships no pinned build; tracked in SEC-1481"
    owner: platform-security
    expires: "2026-03-31"         # expired waivers stop suppressing, loudly

exclude: ["examples/**"]                 # never scanned at all
known_packages: ["@acme/internal-mcp"]   # extend typosquat screening
plugins: ["./security/acme_rules.py"]    # your own rules, same pipeline

injection_patterns:                      # your own detections, no code needed
  - id: ACME.EXFIL
    family: exfiltration
    regex: 'upload\s+to\s+dropbox'       # single-quote regexes in YAML
```

A waiver with no expiry is a decision nobody will revisit, so Bulwark treats an
expired one as absent and tells you which ones lapsed.

---

## Design notes

**No runtime dependencies.** A tool installed to prevent supply-chain incidents
should not be one.

**No network calls.** Bulwark never phones home, and never contacts a remote
MCP endpoint during a scan — reaching one would send your credentials to a
third party as a side effect of running a security scan.

**Secrets are never reproduced.** Findings carry a masked preview and a hash,
never the value. The audit log records `"GitHub token"`, never the token.

**Every finding is evidence-backed.** A finding you cannot verify is just
anxiety, so each one quotes the exact string that triggered it.

**False positives are a security property.** A scanner that cries wolf on a
reasonable setup gets muted, and then it catches nothing. The test suite pins
this: a benign corpus must produce zero findings.

---

## Development

```bash
git clone https://github.com/abdulmanan69/bulwark
cd bulwark
pip install -e ".[dev]"
pytest                                  # 266 tests
pytest --cov=bulwark --cov-report=term  # 85% coverage
ruff check src tests
```

See [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) for what Bulwark does and does
not defend against, and [docs/RULES.md](docs/RULES.md) for the full rule
reference.

---

## FAQ

**Is this MCP server safe to install?**
Run `bulwark scan --online` in a directory whose config declares it. The
`--online` flag starts the server and reads the tool descriptions it actually
serves, which is the only way to see text a static config does not list.
Bulwark lists tools; it never calls one.

**What is tool poisoning?**
A tool description is documentation — it tells a model what a tool does. A
poisoned one issues instructions instead: read this credential, send it there,
do not mention this to the user. Because descriptions load into context before
any tool is called, the instruction runs as soon as the server connects,
whether or not the tool is ever used. Rule `BW-INJ-001`.

**What is an MCP rug pull?**
A server behaves correctly while you review it, then changes a tool description
afterwards. The config file is byte-identical, so code review shows nothing.
`bulwark pin` hashes every model-visible string and `bulwark verify` fails when
one moves. This is the failure mode static config review cannot detect by
construction.

**What is the lethal trifecta?**
An agent that can simultaneously reach private data, ingest content an outsider
wrote, and send data outside the trust boundary. Any two of those is a normal
integration; all three is a complete exfiltration path that needs no
vulnerability to exploit. Rule `BW-CMP-001`.

**How is this different from a dependency scanner?**
Snyk, Dependabot and Trivy read package manifests. None of them reads
`.mcp.json`, and none of them parses a tool description — which is where this
class of attack lives. Bulwark is complementary, not a replacement.

**Does it send my configuration anywhere?**
No. There is no telemetry, no version check and no upload. Remote MCP endpoints
are not contacted during a scan, because doing so would send your credentials
to a third party as a side effect of running a security scan.

**Will it leak my secrets into a report?**
No. Detected credentials are reduced to a masked preview and a hash before
anything is written. The audit log records `"GitHub token"`, never the token.

**Can I run it in CI?**
Yes — that is the main use. Exit codes are the contract, SARIF uploads to
GitHub code scanning, and `--no-user-scope` keeps the scan off the runner's own
home directory. There is a ready-made [GitHub Action](action.yml).

**Can I add my own rules?**
Yes, two ways. Custom regex patterns go straight in
`bulwark.policy.yaml` under `injection_patterns` with no code. Full rules are a
Python class with one method, pointed at by `plugins:` — see
[docs/RULES.md](docs/RULES.md).

**Does it work on Windows?**
Yes. The test suite runs on Windows, macOS and Linux, and Windows console
encoding is handled explicitly.

**Why no dependencies?**
A tool you install to prevent supply-chain incidents should not be one. It also
means it installs in minimal containers where CI actually runs.

## Related work

Bulwark sits next to, not instead of, the tools you already run:

| Tool | Reads | Bulwark overlap |
|---|---|---|
| Snyk / Dependabot / Trivy | package manifests, images | none — different files entirely |
| Semgrep / CodeQL | source code | none — a tool description is not code |
| Gitleaks / TruffleHog | repository history for secrets | partial — Bulwark also checks MCP `env` blocks |
| MCP inspectors | one server, interactively | partial — Bulwark is non-interactive, multi-host, and pins |

## License

Apache-2.0. See [LICENSE](LICENSE).
