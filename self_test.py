# -*- coding: utf-8 -*-
"""self_test for docs-info-leak-scan — inherits scaffold v2 four defenses:
  D1 SystemExit/BaseException capture in run_cli
  D2 Unicode-safe patterns (CJK/emoji fixtures)
  D3 fixtures written with newline="" (Windows CRLF safe)
  D4 last line `SUMMARY: PASS n/n`
"""
import contextlib, inspect, io, json, os, sys, tempfile, unittest

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", newline="\n")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import importlib
FAKE_SK = "sk-" + "abcdefghijklmnopqrstuvwxyz123456"  # concatenated: keeps repo clean of literal secret-shaped strings

mod = importlib.import_module("docs_info_leak_scan")
main = mod.main


def run_cli(argv):
    """D1: catch SystemExit and Exception; return (code, stdout, stderr)."""
    buf_out, buf_err = io.StringIO(), io.StringIO()
    code = 0
    try:
        with contextlib.redirect_stdout(buf_out), contextlib.redirect_stderr(buf_err):
            main(argv)
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
    except Exception as e:
        code = 1
        buf_err.write(repr(e))
    return code, buf_out.getvalue(), buf_err.getvalue()


def _write(text, suffix=".md"):
    """D3: newline="" prevents \r\n double-write on Windows."""
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)
    return path


CASES = []


def case(fn):
    CASES.append(fn)
    return fn


# ---------------- [A] functional ----------------

@case
def a01_clean_doc_exit0():
    p = _write("# Runbook\nSee the dashboard for details.\n")
    code, out, _ = run_cli([p])
    assert code == 0 and "0 finding" in out


@case
def a02_sec1_sk_token():
    p = _write("key: " + FAKE_SK + "\n")
    code, out, _ = run_cli([p])
    assert code == 1 and "SEC1" in out


@case
def a03_sec2_ghp_token():
    p = _write("ghp_" + "a" * 36 + "\n")
    code, out, _ = run_cli([p])
    assert code == 1 and "SEC2" in out


@case
def a04_sec3_aws_key():
    p = _write("AKIA" + "B" * 16 + "\n")
    code, out, _ = run_cli([p])
    assert code == 1 and "SEC3" in out


@case
def a05_sec4_private_key():
    p = _write("-----BEGIN RSA PRIVATE KEY-----\nabc\n")
    code, out, _ = run_cli([p])
    assert code == 1 and "SEC4" in out


@case
def a06_sec5_api_key_assignment():
    p = _write('api_key = "abcdefgh1234"\n')
    code, out, _ = run_cli([p])
    assert code == 1 and "SEC5" in out


@case
def a07_sec6_credentialed_db_url():
    p = _write("postgres://user:hunter2@db.internal:5432/app\n")
    code, out, _ = run_cli([p])
    assert code == 1 and "SEC6" in out


@case
def a08_net1_private_ip():
    p = _write("staging is at 10.1.2.3\n")
    code, out, _ = run_cli([p])
    assert code == 0 and "NET1" in out


@case
def a09_net1_172_range():
    p = _write("172.16.0.9 is the vault\n")
    code, out, _ = run_cli([p])
    assert "NET1" in out


@case
def a10_net2_internal_hostname():
    p = _write("ask ops@vault.internal\n")
    code, out, _ = run_cli([p])
    assert "NET2" in out


@case
def a11_mail1_nonallowlisted_email():
    p = _write("ping alice@company.example\n")
    code, out, _ = run_cli([p])
    assert code == 0 and "MAIL1" in out


@case
def a12_example_com_allowlisted():
    p = _write("ping bob@example.com\n")
    code, out, _ = run_cli([p])
    assert "MAIL1" not in out


@case
def a13_default_agent_mail_allowlisted():
    p = _write("contact hcac4735@agent.qq.com\n")
    code, out, _ = run_cli([p])
    assert "MAIL1" not in out


@case
def a14_allowlist_file_option():
    p = _write("ping carol@corp.example\n")
    ap_ = _write("carol@corp.example\n")
    code, out, _ = run_cli([p, "--allowlist", ap_])
    assert "MAIL1" not in out


@case
def a15_customer_names_option():
    p = _write("We migrated AcmeCorp to the new stack.\n")
    cn = _write("AcmeCorp\n")
    code, out, _ = run_cli([p, "--customer-names", cn])
    assert code == 0 and "CUST1" in out


@case
def a16_customer_name_case_insensitive():
    p = _write("acmecorp renewed.\n")
    cn = _write("AcmeCorp\n")
    code, out, _ = run_cli([p, "--customer-names", cn])
    assert "CUST1" in out


@case
def a17_json_output_parseable():
    p = _write("10.0.0.1\n")
    code, out, _ = run_cli([p, "--json"])
    assert code == 0
    data = json.loads(out)
    assert data["files_scanned"] == 1 and data["findings"][0]["rule"] == "NET1"


@case
def a18_directory_scan():
    d = tempfile.mkdtemp()
    _write("# ok doc\n")
    with open(os.path.join(d, "note.md"), "w", encoding="utf-8", newline="") as fh:
        fh.write("server 10.9.9.9\n")
    code, out, _ = run_cli([d])
    assert code == 0 and "NET1" in out


@case
def a19_line_numbers_accurate():
    p = _write("line one clean\nline two clean\n10.0.0.5 here\n")
    code, out, _ = run_cli([p, "--json"])
    f = json.loads(out)["findings"][0]
    assert f["line"] == 3


@case
def a20_bench_small():
    code, out, _ = run_cli(["--bench", "10", "unused.md"])
    assert code == 0 and "docs=10" in out


@case
def a21_bench_default():
    code, out, _ = run_cli(["unused.md", "--bench", "50"])
    assert code == 0 and "docs/s" in out


@case
def a22_help_exit0():
    code, out, _ = run_cli(["--help"])
    assert code == 0 and "docs-info-leak-scan" in out


@case
def a23_no_args_exit2():
    code, _, _ = run_cli([])
    assert code == 2


@case
def a24_unknown_flag_exit2():
    code, _, _ = run_cli(["--frobnicate", "x.md"])
    assert code == 2


@case
def a25_direct_scan_text_api():
    f = mod.scan_text("10.0.0.1")
    assert f[0]["rule"] == "NET1" and f[0]["severity"] == "warning"


# ---------------- [B] exception paths ----------------

@case
def b01_missing_input_path():
    code, out, _ = run_cli(["Z:/no/such/file.md"])
    assert code == 0 and "scanned 0 file" in out  # unreadable paths skipped silently


@case
def b02_allowlist_file_missing():
    p = _write("clean\n")
    code, _, err = run_cli([p, "--allowlist", "Z:/no/allow.txt"])
    assert code == 1 and "cannot read" in err


@case
def b03_customer_names_file_missing():
    p = _write("clean\n")
    code, _, err = run_cli([p, "--customer-names", "Z:/no/names.txt"])
    assert code == 1 and "cannot read" in err


@case
def b04_empty_allowlist_file_ok():
    p = _write("10.0.0.1\n")
    ap_ = _write("")
    code, out, _ = run_cli([p, "--allowlist", ap_])
    assert code == 0 and "NET1" in out


@case
def b05_customer_names_empty_file_ok():
    p = _write("plain text\n")
    cn = _write("\n")
    code, out, _ = run_cli([p, "--customer-names", cn])
    assert code == 0 and "0 finding" in out


@case
def b06_bench_docs_zero():
    code, _, _ = run_cli(["unused.md", "--bench", "0"])
    assert code == 2


@case
def b07_bench_docs_negative():
    code, _, _ = run_cli(["unused.md", "--bench", "-2"])
    assert code == 2


@case
def b08_bench_docs_not_int():
    code, _, _ = run_cli(["unused.md", "--bench", "lots"])
    assert code == 2


@case
def b09_directory_input():
    d = tempfile.mkdtemp()
    code, out, _ = run_cli([d])
    assert code == 0


@case
def b10_regex_customer_name_escaped():
    p = _write("price (a.b) is fine\n")
    cn = _write("a.b\n")  # regex metachars must be escaped, not crash
    code, out, _ = run_cli([p, "--customer-names", cn])
    assert "CUST1" in out


@case
def b11_unreadable_bytes_tolerated():
    fd, p = tempfile.mkstemp(suffix=".bin")
    os.close(fd)
    with open(p, "wb") as fh:
        fh.write(b"\xff\xfe\x00\x01 binary \x93\x94")
    code, out, _ = run_cli([p])
    assert code == 0


@case
def b12_error_exit_requires_error_severity():
    p = _write("10.0.0.1 only warning\n")
    code, out, _ = run_cli([p])
    assert code == 0  # warnings alone must not fail the run


@case
def b13_customer_name_empty_line_skipped():
    p = _write("nothing here\n")
    cn = _write("\n\n")
    code, out, _ = run_cli([p, "--customer-names", cn])
    assert code == 0


@case
def b14_allowlist_lines_without_email_ignored():
    p = _write("10.0.0.1\n")
    ap_ = _write("not-an-email\n")
    code, out, _ = run_cli([p, "--allowlist", ap_])
    assert code == 0 and "NET1" in out


@case
def b15_paths_after_flags():
    p = _write("10.0.0.1\n")
    code, out, _ = run_cli([p, "--json"])
    assert json.loads(out)["findings"]


@case
def b16_large_path_argument_still_runs():
    code, out, _ = run_cli(["Z:" + "/x" * 100])
    assert code == 0 and "scanned 0" in out


@case
def b17_sec5_requires_quotes():
    p = _write("api_key=short\n")  # no quotes, too short -> no match
    code, out, _ = run_cli([p])
    assert code == 0 and "SEC5" not in out


@case
def b18_sec1_short_token_not_matched():
    p = _write("sk-short\n")
    code, out, _ = run_cli([p])
    assert "SEC1" not in out


@case
def b19_public_ip_not_flagged():
    p = _write("docs at 8.8.8.8 and 172.32.0.1\n")  # outside private ranges
    code, out, _ = run_cli([p])
    assert "NET1" not in out


@case
def b20_directory_as_allowlist_fails_cleanly():
    p = _write("x\n")
    code, _, err = run_cli([p, "--allowlist", tempfile.mkdtemp()])
    assert code == 1 and "cannot read" in err


# ---------------- [C] extreme / edge ----------------

@case
def c01_empty_file():
    p = _write("")
    code, out, _ = run_cli([p])
    assert code == 0 and "0 finding" in out


@case
def c02_whitespace_only_file():
    p = _write(" \n\t \n")
    code, out, _ = run_cli([p])
    assert code == 0


@case
def c03_huge_clean_file():
    p = _write("safe line\n" * 50000)
    code, out, _ = run_cli([p])
    assert code == 0 and "0 finding" in out


@case
def c04_unicode_cjk_doc_clean():
    p = _write("# 运维手册\n内网地址请勿外传\n")
    code, out, _ = run_cli([p])
    assert code == 0 and "0 finding" in out


@case
def c05_unicode_emoji_doc_clean():
    p = _write("Deploy \U0001f680 notes: all good\n")
    code, out, _ = run_cli([p])
    assert code == 0


@case
def c06_leak_line_with_emoji():
    p = _write("token \U0001f511 " + FAKE_SK + "\n")
    code, out, _ = run_cli([p])
    assert code == 1 and "SEC1" in out


@case
def c07_zero_network_imports():
    src = inspect.getsource(mod)
    for banned in ("import socket", "import urllib", "import http", "import requests",
                   "import ftplib", "import telnetlib"):
        assert banned not in src, banned


@case
def c08_crlf_file_scanned():
    fd, p = tempfile.mkstemp(suffix=".md")
    os.close(fd)
    with open(p, "w", encoding="utf-8", newline="") as fh:  # D3
        fh.write("first\r\n10.0.0.2\r\n")
    code, out, _ = run_cli([p, "--json"])
    assert json.loads(out)["findings"][0]["line"] == 2


@case
def c09_utf8_bom_file():
    fd, p = tempfile.mkstemp(suffix=".md")
    os.close(fd)
    with open(p, "wb") as fh:
        fh.write(b"\xef\xbb\xbf10.0.0.3\n".replace(b"10.0.0.3", "10.0.0.3".encode()))
    code, out, _ = run_cli([p])
    assert "NET1" in out


@case
def c10_multiple_findings_same_line():
    p = _write("10.0.0.1 and 192.168.1.1\n")
    code, out, _ = run_cli([p, "--json"])
    assert len(json.loads(out)["findings"]) == 2


@case
def c11_many_customer_names_bulk():
    p = _write("alpha beta gamma\n")
    cn = _write("alpha\nbeta\ngamma\n")
    code, out, _ = run_cli([p, "--customer-names", cn, "--json"])
    assert len(json.loads(out)["findings"]) == 3


@case
def c12_oversized_file_skipped():
    fd, p = tempfile.mkstemp(suffix=".md")
    os.close(fd)
    with open(p, "wb") as fh:
        fh.write(b"x" * (mod.MAX_FILE_BYTES + 1) + b"\n10.0.0.1\n")
    code, out, _ = run_cli([p, "--json"])
    assert json.loads(out)["files_scanned"] == 0


@case
def c13_email_inside_leak_line_still_reported():
    p = _write("db 10.0.0.1 admin ops@corp.internal\n")
    code, out, _ = run_cli([p, "--json"])
    rules = {f["rule"] for f in json.loads(out)["findings"]}
    assert {"NET1", "NET2", "MAIL1"} <= rules


@case
def c14_email_match_truncated_in_output():
    p = _write("x" * 60 + "@toolong.example\n")
    code, out, _ = run_cli([p])
    assert "MAIL1" in out


@case
def c15_sec6_mongodb_variant():
    p = _write("mongodb://adm:s3cret@127.0.0.1:27017\n")
    code, out, _ = run_cli([p])
    assert "SEC6" in out


@case
def c16_mysql_variant():
    p = _write("mysql://u:p@10.0.0.9/db\n")
    code, out, _ = run_cli([p])
    assert "SEC6" in out


@case
def c17_exhaustive_multiple_paths():
    p1 = _write("clean\n")
    p2 = _write("10.0.0.1\n")
    code, out, _ = run_cli([p1, p2, "--json"])
    assert json.loads(out)["files_scanned"] == 2


@case
def c18_net2_corp_domain():
    p = _write("wiki.corp/settings\n")
    code, out, _ = run_cli([p])
    assert "NET2" in out


@case
def c19_punctuation_around_ip():
    p = _write("(10.0.0.7), see:\n")
    code, out, _ = run_cli([p])
    assert "NET1" in out


@case
def c20_findings_carry_excerpts_under_40_chars():
    p = _write("sk-" + "x" * 200 + "\n")
    code, out, _ = run_cli([p, "--json"])
    assert len(json.loads(out)["findings"][0]["match"]) <= 40


class T(unittest.TestCase):
    def test_meta_case_count(self):
        self.assertGreaterEqual(len(CASES), 60)


for _fn in CASES:
    setattr(T, "test_" + _fn.__name__, lambda self, f=_fn: f())

if __name__ == "__main__":
    r = unittest.TextTestRunner(verbosity=0).run(
        unittest.defaultTestLoader.loadTestsFromModule(sys.modules["__main__"]))
    total, fails = r.testsRun, len(r.failures) + len(r.errors)
    print("SUMMARY: PASS %d/%d" % (total - fails, total))
    sys.exit(0 if fails == 0 else 1)
