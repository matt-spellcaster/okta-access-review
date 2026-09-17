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
    assert set(manifest["files"]) == {
        "report.md", "report.pdf", "findings.csv", "access_matrix.csv", "snapshot.json", "roster.csv",
    }
    for name, digest in manifest["files"].items():
        assert hashlib.sha256((d / name).read_bytes()).hexdigest() == digest
    assert manifest["finding_counts"]["critical"] == 1


def test_access_matrix_shows_group_and_direct_app_access(tmp_path):
    main(DEMO_ARGS + ["--out", str(tmp_path)])
    rows = {r["login"]: r for r in csv.DictReader((run_dir(tmp_path) / "access_matrix.csv").open())}
    assert len(rows) == 11
    assert rows["hannah.ortiz@acme.example"]["apps"] == "AWS (direct)"
    assert rows["priya.shah@acme.example"]["groups"] == "Engineering"  # built-in groups hidden
    assert rows["omar.haddad@acme.example"]["mfa"] == "n/a"  # PROVISIONED: can't sign in yet
    assert rows["victor.nguyen@acme.example"]["admin_roles"] == "n/a"
    assert rows["lee.chen@acme.example"]["mfa"] == "none"
    assert rows["omar.haddad@acme.example"]["last_login"] == "never"
    assert rows["lee.chen@acme.example"]["decision"] == ""
    assert rows["priya.shah@acme.example"]["admin_roles"] == "Super Administrator"
    assert rows["lee.chen@acme.example"]["admin_roles"] == ""


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


def test_complete_review_has_no_gaps_section(tmp_path):
    main(DEMO_ARGS + ["--out", str(tmp_path)])
    d = run_dir(tmp_path)
    assert "Data gaps" not in (d / "report.md").read_text()
    assert json.loads((d / "manifest.json").read_text())["complete"] is True


def test_data_gaps_are_reported(tmp_path):
    snap = json.loads((FIXTURES / "demo_snapshot.json").read_text())
    snap["gaps"] = ["Could not read admin role assignments; AR-10 and AR-11 may be incomplete."]
    path = tmp_path / "snap.json"
    path.write_text(json.dumps(snap))
    out = tmp_path / "out"
    main(["--snapshot", str(path), "--as-of", "2026-09-15", "--out", str(out)])
    d = run_dir(out)
    assert "## ⚠️ Data gaps" in (d / "report.md").read_text()
    manifest = json.loads((d / "manifest.json").read_text())
    assert manifest["complete"] is False
    assert manifest["data_gaps"] == snap["gaps"]


def test_pdf_is_reproducible_and_contains_findings(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    main(DEMO_ARGS + ["--out", str(a)])
    main(DEMO_ARGS + ["--out", str(b)])
    pdf_a = (run_dir(a) / "report.pdf").read_bytes()
    assert pdf_a == (run_dir(b) / "report.pdf").read_bytes()
    assert pdf_a.startswith(b"%PDF")

    from pypdf import PdfReader

    text = "\n".join(page.extract_text() for page in PdfReader(run_dir(a) / "report.pdf").pages)
    assert "Okta user access review" in text
    assert "marcus.lee@acme.example" in text
    assert "Reviewer sign-off" in text
    assert "CONFIDENTIAL" in text


def test_mfa_unknown_only_for_users_who_can_sign_in(tmp_path):
    snap = json.loads((FIXTURES / "demo_snapshot.json").read_text())
    for u in snap["users"]:
        u["factors"] = None
    path = tmp_path / "snap.json"
    path.write_text(json.dumps(snap))
    main(["--snapshot", str(path), "--out", str(tmp_path / "out")])
    rows = {r["login"]: r for r in csv.DictReader((run_dir(tmp_path / "out") / "access_matrix.csv").open())}
    assert rows["priya.shah@acme.example"]["mfa"] == "unknown"
    assert rows["nina.patel@acme.example"]["mfa"] == "n/a"  # SUSPENDED


def test_default_review_date_is_collection_date(tmp_path):
    main(["--snapshot", str(FIXTURES / "demo_snapshot.json"), "--out", str(tmp_path)])
    assert json.loads((run_dir(tmp_path) / "manifest.json").read_text())["review_date"] == "2026-09-15"


def test_manifest_records_the_roster_used(tmp_path):
    main(DEMO_ARGS + ["--out", str(tmp_path)])
    d = run_dir(tmp_path)
    source = FIXTURES / "demo_roster.csv"
    manifest = json.loads((d / "manifest.json").read_text())
    assert manifest["roster"] == {
        "source_name": "demo_roster.csv",  # file name only, never the local path
        "copied_as": "roster.csv",
        "rows": 9,
        "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
    }
    assert (d / "roster.csv").read_bytes() == source.read_bytes()
    assert manifest["files"]["roster.csv"] == manifest["roster"]["sha256"]
    assert str(FIXTURES) not in (d / "manifest.json").read_text()
    label = f"demo_roster.csv, 9 people, SHA-256 {manifest['roster']['sha256'][:12]}"
    assert f"- **HR roster:** {label}" in (d / "report.md").read_text()


def test_no_roster_is_recorded_and_stale_copy_removed(tmp_path):
    main(DEMO_ARGS + ["--out", str(tmp_path)])  # first run leaves roster.csv behind
    no_roster = [a for a in DEMO_ARGS if a not in ("--roster", str(FIXTURES / "demo_roster.csv"))]
    main(no_roster + ["--out", str(tmp_path)])  # same collection time, same folder
    d = run_dir(tmp_path)
    manifest = json.loads((d / "manifest.json").read_text())
    assert manifest["roster"] is None
    assert not (d / "roster.csv").exists() and "roster.csv" not in manifest["files"]
    assert "- **HR roster:** not provided (AR-01 to AR-03 skipped)" in (d / "report.md").read_text()


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
