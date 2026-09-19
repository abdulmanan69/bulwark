# Security policy

Bulwark is a security tool, so its own trustworthiness is the product. Reports
are taken seriously and handled quickly.

## Reporting a vulnerability

**Do not open a public issue.**

Use GitHub's private reporting: **Security → Report a vulnerability** on
<https://github.com/abdulmanan69/bulwark/security/advisories/new>.

Please include:

- what you found and where in the code,
- how to reproduce it (a config file or a string is usually enough),
- what an attacker gains,
- any suggested fix.

### What to expect

| Stage | Target |
|---|---|
| Acknowledgement | within 3 days |
| Initial assessment | within 7 days |
| Fix or mitigation plan | within 30 days for high severity |
| Public advisory | after a fix ships, crediting you unless you prefer otherwise |

## What counts as a vulnerability in Bulwark

Bulwark reads attacker-controlled input by design, so these are all in scope:

- **Detection bypass** — a payload that evades a rule it should trigger. A tool
  description that reaches the model as an instruction but scores clean is a
  real finding, not a feature request.
- **Report injection** — content from a scanned config that escapes escaping in
  the HTML, SARIF, JUnit or Markdown reporters.
- **Secret leakage** — any path where a detected credential reaches a report,
  a lockfile, an audit log or stdout in plaintext.
- **Denial of service** — input that makes a scan hang, exhaust memory, or
  backtrack catastrophically.
- **Proxy failures** — the guard forwarding something it should have blocked,
  or corrupting a valid MCP session.
- **Unexpected egress** — any code path that sends data off the machine.

## Out of scope

- False positives on benign input. Still report them as ordinary issues — they
  are treated as high-priority bugs — but they are not security advisories.
- Attacks requiring arbitrary code execution as the user. Once that is true,
  Bulwark is one of the things the attacker can disable. See
  [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).
- Vulnerabilities in MCP servers that Bulwark scans. Report those to their
  maintainers; Bulwark's job is to find them.

## Disclosure of findings in third-party servers

If Bulwark is used to find issues in someone else's MCP server, please give
that maintainer 90 days privately before publishing. Responsible disclosure is
what makes this kind of research welcome rather than adversarial.

## Supported versions

The latest released version is supported. Given the project's age, security
fixes ship as a new patch release rather than as backports.
