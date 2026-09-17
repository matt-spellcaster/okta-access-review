"""Write the review as audit evidence: a readable report, CSVs, the raw
snapshot, and a manifest with SHA-256 hashes of every file."""

from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter
from dataclasses import asdict
from datetime import date
from pathlib import Path

from . import __version__
from .checks import CHECKS, SEVERITIES, Config, Finding
from .models import SIGN_IN_STATUSES, Snapshot
from .pdf import Branding, write_pdf

MATRIX_COLUMNS = [
    "login", "name", "status", "type", "department", "manager", "last_login",
    "mfa", "admin_roles", "groups", "apps", "decision", "reviewer", "reviewed_on", "notes",
]


def access_matrix(snapshot: Snapshot) -> list[dict]:
    rows = []
    for u in sorted(snapshot.users, key=lambda u: u.login):
        groups = sorted(g.name for g in snapshot.groups_for(u.id) if g.type != "BUILT_IN")
        apps = sorted({f"{app.label} ({how})" for app, how in snapshot.apps_for(u.id)})
        # Factors are only collected for users who can sign in, and roles for users who aren't deprovisioned.
        if u.status not in SIGN_IN_STATUSES:
            mfa = "n/a"
        else:
            mfa = "unknown" if u.factors is None else (", ".join(u.factors) or "none")
        if u.status == "DEPROVISIONED":
            admin_roles = "n/a"
        else:
            admin_roles = "unknown" if u.admin_roles is None else "; ".join(u.admin_roles)
        rows.append({
            "login": u.login,
            "name": u.name,
            "status": u.status,
            "type": u.user_type,
            "department": u.department,
            "manager": u.manager,
            "last_login": u.last_login.date().isoformat() if u.last_login else "never",
            "mfa": mfa,
            "admin_roles": admin_roles,
            "groups": "; ".join(groups),
            "apps": "; ".join(apps),
            # Filled in by the reviewer: keep | revoke | modify
            "decision": "", "reviewer": "", "reviewed_on": "", "notes": "",
        })
    return rows


def render_markdown(snapshot: Snapshot, findings: list[Finding], skipped: list[str], as_of: date) -> str:
    counts = Counter(f.severity for f in findings)
    live = sum(1 for u in snapshot.users if u.status != "DEPROVISIONED")
    lines = [
        "# Okta user access review",
        "",
        f"- **Org:** {snapshot.org_url}",
        f"- **Data collected:** {snapshot.collected_at.strftime('%Y-%m-%d %H:%M UTC')}",
        f"- **Review date:** {as_of.isoformat()}",
        f"- **Scope:** {len(snapshot.users)} users ({live} not deprovisioned), "
        f"{len(snapshot.groups)} groups, {len(snapshot.apps)} apps",
        f"- **Tool:** okta-access-review {__version__} (read-only)",
        "",
        "## Summary",
        "",
        "| Severity | Findings |",
        "|---|---|",
    ]
    lines += [f"| {s} | {counts.get(s, 0)} |" for s in SEVERITIES]
    if skipped:
        lines += ["", f"Skipped (no HR roster provided): {', '.join(skipped)}"]
    if snapshot.gaps:
        lines += ["", "## ⚠️ Data gaps", "", "This review is incomplete. Fix these before relying on it:", ""]
        lines += [f"- {g}" for g in snapshot.gaps]

    lines += ["", "## Findings", ""]
    if not findings:
        lines.append("No findings.")
    by_check: dict[str, list[Finding]] = {}
    for f in findings:
        by_check.setdefault(f.check_id, []).append(f)
    for check in CHECKS:
        items = by_check.get(check.id)
        if not items:
            continue
        lines += [
            f"### {check.id} · {check.title}",
            "",
            f"**Controls:** {', '.join(check.controls)}  ",
            f"**Fix:** {check.remediation}",
            "",
            "| Severity | Subject | Detail |",
            "|---|---|---|",
        ]
        lines += [f"| {f.severity} | `{f.subject}` | {f.detail} |" for f in items]
        lines.append("")

    lines += [
        "## Checks run",
        "",
        "| ID | Check | Default severity | Controls |",
        "|---|---|---|---|",
    ]
    lines += [
        f"| {c.id} | {c.title} | {c.severity} | {', '.join(c.controls)} |"
        + (" *(skipped)*" if c.id in skipped else "")
        for c in CHECKS
    ]
    lines += [
        "",
        "## Reviewer sign-off",
        "",
        "Record a decision for every row in `access_matrix.csv`, then sign below.",
        "",
        "- Reviewer: ____________________",
        "- Date: ____________________",
        "",
    ]
    return "\n".join(lines)


def _write_csv(path: Path, rows: list[dict], columns: list[str]) -> None:
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def write_report(
    out_dir: Path,
    snapshot: Snapshot,
    findings: list[Finding],
    skipped: list[str],
    config: Config,
    as_of: date,
) -> Path:
    run_dir = out_dir / snapshot.collected_at.strftime("%Y%m%dT%H%M%SZ")
    run_dir.mkdir(parents=True, exist_ok=True)

    (run_dir / "report.md").write_text(render_markdown(snapshot, findings, skipped, as_of))
    finding_rows = [{**asdict(f), "controls": "; ".join(f.controls)} for f in findings]
    _write_csv(run_dir / "findings.csv", finding_rows, list(Finding.__dataclass_fields__))
    matrix = access_matrix(snapshot)
    _write_csv(run_dir / "access_matrix.csv", matrix, MATRIX_COLUMNS)
    write_pdf(run_dir / "report.pdf", snapshot, findings, skipped, as_of, matrix, Branding.from_config(config.branding))
    (run_dir / "snapshot.json").write_text(json.dumps(snapshot.to_dict(), indent=2) + "\n")

    manifest = {
        "tool": f"okta-access-review {__version__}",
        "org_url": snapshot.org_url,
        "collected_at": snapshot.to_dict()["collected_at"],
        "review_date": as_of.isoformat(),
        "config": asdict(config),
        "finding_counts": dict(Counter(f.severity for f in findings)),
        "skipped_checks": skipped,
        "complete": not snapshot.gaps,
        "data_gaps": snapshot.gaps,
        "files": {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(run_dir.iterdir())
            if p.name != "manifest.json"
        },
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return run_dir
