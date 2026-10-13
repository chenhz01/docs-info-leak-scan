# docs-info-leak-scan

A static scanner that catches internal information leaking into documents before they ship: secret-shaped strings, credentialed database URLs, private-range IPs, internal hostnames, non-allowlisted emails, and optional customer-name mentions. Strictly offline — it opens only the files you pass it. Pure standard library, single file. *No direct equivalent found as of 2026-10-13.*

<p align="center"><img src="docs/demo.gif" alt="demo" width="720"></p>

## Problem

Runbooks, postmortems, and RFC drafts routinely quote the internal reality — `postgres://admin:hunter2@db.internal`, the staging IP, the customer that filed the incident — because that is what makes them useful. Then they get pasted into a public repo or a shared doc export. Existing secret scanners target source code and git history; they do not cover prose documents, internal hostnames, or "we named the customer three times in this incident review".

## How it works

Eight built-in static rules, no network, no configuration required:

| Rule | Severity | Catches |
|---|---|---|
| SEC1–SEC3 | error | `sk-…`, `ghp_…`, `AKIA…` secret shapes |
| SEC4 | error | embedded `PRIVATE KEY` blocks |
| SEC5 | error | hardcoded `api_key = "…"` assignments |
| SEC6 | error | credentialed `postgres/mysql/redis/mongodb://` URLs |
| NET1 | warning | private-range IPs (10/8, 172.16/12, 192.168/16) |
| NET2 | warning | `.internal` / `.local` / `.corp` / `.intranet` hostnames |
| MAIL1 | warning | emails not on the allowlist (default: `hcac4735@agent.qq.com`, `example.com/org/net`) |

Plus an opt-in `--customer-names FILE` (one name per line, case-insensitive, regex-escaped → CUST1 warnings). Exit `1` only when an error-severity finding exists, so warnings can ramp adoption without blocking. Findings carry file, line, a ≤40-char excerpt, and print as text or `--json`.

**Defensive positioning / zero network:** the module imports no socket, urllib, http, or third-party code — the self-test asserts this against the module source. It reads local files (≤5 MB, UTF-8 with replacement) and writes only to stdout. Unreadable paths are skipped, never fetched.

## Quickstart

```console
$ python docs_info_leak_scan_scan.py docs/ --json          # ~0.2 s for 100 docs
scanned 100 file(s), 3 finding(s)
error   SEC6   docs/runbook.md:14 postgres://… — credentialed database URL
```

Add it as a pre-publication gate: `python docs_info_leak_scan.py docs/ || exit 1`.

## Why not X

- **gitleaks / truffleHog** — excellent for git history and code, but rules are code-centric; prose leaks (internal hostnames, customer mentions in a postmortem) are out of scope, and both want repo context.
- **GitHub secret scanning / push protection** — provider-side, covers supported token formats only, and does nothing for internal IPs or customer names in docs.
- **DLP appliances** — network/device-level, heavyweight, and invisible to the doc author; the feedback arrives after publication instead of before.
- **grep with a hand-written pattern list** — the naive fallback works, but has no severity model, no allowlists, no JSON contract, and no line-stable reporting.

## Performance

All numbers [Measured] locally (Python 3.13, Windows 10, single core):

| Workload | Result | Command |
|---|---|---|
| 1,000 synthetic docs (~8 rules) | 0.15 s (~6.7k docs/s) | `python docs_info_leak_scan.py docs/ --bench 1000` |
| 100-file directory | <0.2 s | `python docs_info_leak_scan.py docs/ --json` |

`bench` generates deterministic synthetic docs and times only the rule engine.

## Minimal Fallback

Without this tool: a two-line pre-commit grep — `grep -rEn "sk-|ghp_|AKIA|BEGIN.*PRIVATE KEY" docs/`. You lose the private-IP and hostname rules, the email allowlist semantics, the severity-based exit code, and JSON output — but even the grep alone catches the most embarrassing class (live tokens) before a push.

## Design Trade-offs

- **Patterns, not entropy.** Entropy scanners overfit on prose; a runbook full of base64-looking IDs would drown in false positives. Shape rules are explainable in review.
- **Warnings that never block.** Internal IPs are usually intentional in internal docs; blocking on them would get the tool disabled. Only secret-class findings exit 1.
- **Allowlist is deny-by-default for emails only.** IPs and hostnames are pattern-bounded, so allowlisting is unnecessary there and would invite drift.
- **Offline by construction, not by policy.** The zero-network property is enforced by the module's import surface and asserted by the test suite, not promised in a comment.

## Limits & Second-order Effects

- No rule catches a *paraphrased* leak ("our Berlin office's primary DB") — static patterns cannot see semantics.
- Teams may route around the scanner by writing leaks as images or rotating encodings; scanner clean does not equal leak free.
- Aggressive customer-name lists can flag false positives (common words), training authors to ignore CUST1 and miss real hits.
- Wide adoption of one ruleset creates monoculture blind spots; periodically re-derive rules from actual incident leaks, not from the tool's defaults.

## FAQ

**When NOT to use this?** If your documents already pass through a DLP pipeline that covers prose, or your "docs" are exclusively public-by-design marketing pages, this adds a redundant gate. Also skip it if you need content-aware classification — this is deliberately dumb, fast, and explainable.

**Why is a private IP only a warning?** Internal docs legitimately reference internal infrastructure. The tool's job is to make the reviewer *see* it before publication, not to forbid it.

**Does it send my documents anywhere?** No. There is no network code in the module; the self-test asserts that no socket/urllib/http import exists in the source.

**Can I add my own rules?** v0.1 keeps the ruleset fixed for predictability; the rule table is a plain list in the source — edit it and re-run the self-test.

## [Core Assumptions]

1. The highest-value prose leaks are shape-detectable (tokens, keys, credentialed URLs, private ranges) — semantic leaks are out of scope by design.
2. Teams will tolerate a warning-level nudge but disable a tool that blocks on legitimate internal references.
3. The default email allowlist fits the zhengming ecosystem; real adopters must override it via `--allowlist`.
4. Documents under 5 MB cover essentially all prose artifacts; larger files are asset bundles, not prose.

Confidence: High (≥80%) for the secret-shape rules and the zero-network property (both directly testable); Medium (60-79%) for the hostname/IP rule coverage across real networks. As of 2026-10-13.

---

Part of the [zhengming-toolbox](https://github.com/chenhz01/zhengming-toolbox) — 105 purpose-built AI-engineering tools across neglected niches.

Related tools: [data-classification-schema](https://github.com/chenhz01/data-classification-schema) · [file-permission-drift](https://github.com/chenhz01/file-permission-drift) · [cors-policy-validator](https://github.com/chenhz01/cors-policy-validator)
