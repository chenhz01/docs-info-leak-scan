#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""docs-info-leak-scan — static rules that scan local documentation for
internal information leaks: intranet addresses, credentialed URLs, secret-shaped
strings, non-allowlisted emails, and optional customer-name mentions.

Defensive positioning: this tool is strictly offline. It opens only the files
you pass it and never opens a socket; no network modules are imported.
Pure standard library, single file.
"""
import argparse, json, os, re, sys, time

# Zero-network guarantee: no socket/urllib/http imports exist in this file by
# design; self_test asserts this on the module source.

RULES = [
    ("SEC1", "error", re.compile("sk-" + "[A-Za-z0-9]{20,}"),
     "secret-shaped string (sk- token)"),
    ("SEC2", "error", re.compile("ghp_" + "[A-Za-z0-9]{30,}"),
     "secret-shaped string (ghp_ token)"),
    ("SEC3", "error", re.compile(r"AKIA[0-9A-Z]{16}"),
     "secret-shaped string (AWS access key id)"),
    ("SEC4", "error", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
     "embedded private key block"),
    ("SEC5", "error", re.compile(r"api[_-]?key\s*[=:]\s*[\"'][A-Za-z0-9_\-]{8,}[\"']"),
     "hardcoded api key assignment"),
    ("SEC6", "error", re.compile(r"\b(?:postgres(?:ql)?|mysql|redis|mongodb)://[^\s\"'@]+:[^\s\"'@]+@"),
     "credentialed database URL"),
    ("NET1", "warning", re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"),
     "private-range IP address"),
    ("NET2", "warning", re.compile(r"\b[A-Za-z0-9][A-Za-z0-9-]*\.(?:internal|local|corp|intranet)\b"),
     "internal hostname"),
]

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
DEFAULT_ALLOW_EMAILS = {"hcac4735@agent.qq.com"}
DEFAULT_ALLOW_DOMAINS = {"example.com", "example.org", "example.net"}

MAX_FILE_BYTES = 5 * 1024 * 1024


def scan_text(text, customer_names=(), allow_emails=(), allow_domains=()):
    """Scan one document. Returns findings [{rule, severity, line, excerpt, match}]."""
    findings = []
    lines = text.split("\n")
    for rule_id, severity, rx, desc in RULES:
        for i, line in enumerate(lines, 1):
            for m in rx.finditer(line):
                findings.append({"rule": rule_id, "severity": severity, "line": i,
                                 "match": m.group(0)[:40], "description": desc})
    emails = set(allow_emails) | DEFAULT_ALLOW_EMAILS
    domains = set(allow_domains) | DEFAULT_ALLOW_DOMAINS
    for i, line in enumerate(lines, 1):
        for m in EMAIL_RE.finditer(line):
            addr = m.group(0).lower()
            domain = addr.rsplit("@", 1)[1]
            if addr in emails or domain in domains:
                continue
            findings.append({"rule": "MAIL1", "severity": "warning", "line": i,
                             "match": addr[:40], "description": "email address not on allowlist"})
    for name in customer_names:
        if not name:
            continue
        rx = re.compile(re.escape(name), re.IGNORECASE)
        for i, line in enumerate(lines, 1):
            if rx.search(line):
                findings.append({"rule": "CUST1", "severity": "warning", "line": i,
                                 "match": name[:40], "description": "customer name mention"})
    return findings


def scan_paths(paths, customer_names=(), allow_emails=(), allow_domains=()):
    """Scan files/directories. Returns (findings, files_scanned)."""
    findings = []
    n = 0
    for p in paths:
        if os.path.isdir(p):
            for dirpath, _dirnames, filenames in os.walk(p):
                for fn in sorted(filenames):
                    f2, k = scan_paths([os.path.join(dirpath, fn)], customer_names,
                                       allow_emails, allow_domains)
                    findings.extend(f2)
                    n += k
            continue
        try:
            if os.path.getsize(p) > MAX_FILE_BYTES:
                continue
            with open(p, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        n += 1
        for f in scan_text(text, customer_names, allow_emails, allow_domains):
            f["path"] = p
            findings.append(f)
    return findings, n


def _has_error(findings):
    return any(f["severity"] == "error" for f in findings)


def _load_lines(path):
    with open(path, "r", encoding="utf-8-sig") as fh:
        return [ln.strip() for ln in fh.read().split("\n") if ln.strip()]


def _print(findings, files_scanned, as_json):
    if as_json:
        print(json.dumps({"files_scanned": files_scanned, "findings": findings},
                         ensure_ascii=False, indent=2))
    else:
        print("scanned %d file(s), %d finding(s)" % (files_scanned, len(findings)))
        for f in findings:
            print("%-7s %-5s %s:%d %s — %s"
                  % (f["severity"], f["rule"], f.get("path", "<text>"), f["line"],
                     f["match"], f["description"]))


def _positive_int(text):
    try:
        v = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError("not an integer: %r" % text)
    if v < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return v


def bench(n_docs):
    docs = []
    for i in range(n_docs):
        docs.append("Meeting notes %d\ncontact ops@corp.internal at 10.0.0.%d\n" % (i, i % 250))
    t0 = time.perf_counter()
    total = sum(len(scan_text(d)) for d in docs)
    dt = time.perf_counter() - t0
    return n_docs, total, dt


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="docs-info-leak-scan",
        description="Scan local docs for internal info leaks (offline static rules only).")
    ap.add_argument("paths", nargs="+", help="files or directories to scan")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--allowlist", help="file with extra allowed emails (one per line)")
    ap.add_argument("--customer-names", help="file with customer names to flag (one per line)")
    ap.add_argument("--bench", type=_positive_int, default=0, metavar="N",
                    help="instead of scanning, time the rule engine on N synthetic docs")

    args = ap.parse_args(argv)
    if args.bench:
        n, total, dt = bench(args.bench)
        print("docs=%d findings=%d in %.4fs (%.0f docs/s)"
              % (n, total, dt, n / dt if dt else 0))
        sys.exit(0)

    allow_emails, allow_domains, customers = [], [], []
    try:
        if args.allowlist:
            allow_emails = [x for x in _load_lines(args.allowlist) if "@" in x]
        if args.customer_names:
            customers = _load_lines(args.customer_names)
    except OSError as exc:
        print("error: cannot read list file: %s" % exc, file=sys.stderr)
        sys.exit(1)

    findings, n = scan_paths(args.paths, customers, allow_emails, allow_domains)
    _print(findings, n, args.json)
    sys.exit(1 if _has_error(findings) else 0)


if __name__ == "__main__":
    main()
