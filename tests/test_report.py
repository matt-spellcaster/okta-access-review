import csv
import hashlib
import json
from pathlib import Path

from access_review.cli import main

FIXTURES = Path(__file__).parent.parent / "fixtures"
DEMO_ARGS = [
    "--snapshot", str(FIXTURES / "demo_snapshot.json"),
    "--roster", str(FIXTURES / "demo_roster.csv"),
    "--config", str(FIXTURES / "demo_config.json"),
    "--as-of", "2026-09-15",
]


def run_dir(out: Path) -> Path:
    [d] = list(out.iterdir())
    return d


def test_writes_evidence_with_matching_hashes(tmp_path):
    assert main(DEMO_ARGS + ["--out", str(tmp_path)]) == 0
    d = run_dir(tmp_path)
    assert d.name == "20260915T140000Z"
    manifest = json.loads((d / "manifest.json").read_text())
    assert set(manifest["files"]) == {"report.md", "findings.csv", "access_matrix.csv", "snapshot.json"}
    for name, digest in manifest["files"].items():
        assert hashlib.sha256((d / name).read_bytes()).hexdigest() == digest
    assert manifest["finding_counts"]["critical"] == 1


def test_access_matrix_shows_group_and_direct_app_access(tmp_path):
    main(DEMO_ARGS + ["--out", str(tmp_path)])
    rows = {r["login"]: r for r in csv.DictReader((run_dir(tmp_path) / "access_matrix.csv").open())}
    assert len(rows) == 11
    assert rows["hannah.ortiz@acme.example"]["apps"] == "AWS (direct)"
    assert rows["priya.shah@acme.example"]["groups"] == "Engineering"  # built-in groups hidden
    assert rows["omar.haddad@acme.example"]["mfa"] == "unknown"
    assert rows["lee.chen@acme.example"]["mfa"] == "none"
    assert rows["omar.haddad@acme.example"]["last_login"] == "never"
    assert rows["lee.chen@acme.example"]["decision"] == ""


def test_saved_snapshot_round_trips(tmp_path):
    main(DEMO_ARGS + ["--out", str(tmp_path)])
    saved = json.loads((run_dir(tmp_path) / "snapshot.json").read_text())
    original = json.loads((FIXTURES / "demo_snapshot.json").read_text())
    assert saved["users"] == original["users"]


def test_report_lists_controls_and_findings(tmp_path):
    main(DEMO_ARGS + ["--out", str(tmp_path)])
    md = (run_dir(tmp_path) / "report.md").read_text()
    assert "### AR-01 · Terminated in HR but account still live" in md
    assert "SOC 2 CC6.2" in md
    assert "`marcus.lee@acme.example`" in md


def test_fail_on_sets_exit_code(tmp_path):
    assert main(DEMO_ARGS + ["--out", str(tmp_path), "--fail-on", "critical"]) == 2


def test_fail_on_passes_when_nothing_that_severe(tmp_path):
    args = [
        "--snapshot", str(FIXTURES / "demo_snapshot.json"),
        "--config", str(FIXTURES / "demo_config.json"),
        "--as-of", "2026-09-15",
        "--out", str(tmp_path),
        "--fail-on", "critical",
    ]
    assert main(args) == 0  # AR-01 is the only critical check and needs a roster
