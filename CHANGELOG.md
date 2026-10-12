# Changelog — docs-info-leak-scan

All releases are local drafts; no remote operations are performed.

## v0.1.1 — 2026-10-13

Fixed:
- customer-name matching now uses re.escape, so names containing regex
  metacharacters (e.g. `a.b`) match literally instead of crashing or over-matching.

Changed:
- self_test expanded to 66 cases across functional / exception / extreme-edge
  categories (scaffold v2 four defenses: SystemExit capture, Unicode-safe
  matching, Windows newline-safe fixtures, SUMMARY last line), including a
  zero-network import assertion on the module source.
- README: Performance numbers re-measured via the shipped `--bench` flag.

## v0.1.0 — 2026-10-13

Added:
- Initial local draft: 8 static leak rules (SEC1–SEC6 errors, NET1/NET2 warnings),
  email allowlist semantics, opt-in customer-name scanning, JSON/text reports,
  argparse CLI (`--bench` flag), zero-network defensive positioning and
  scaffold-v2 self_test.
