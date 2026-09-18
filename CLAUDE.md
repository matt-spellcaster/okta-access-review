# okta-access-review

Read-only Okta user access review that produces SOC 2 / ISO 27001 audit evidence.

## Commands

- Tests: `uv run pytest -q`
- Demo (no Okta needed): `uv run access-review --snapshot fixtures/demo_snapshot.json --roster fixtures/demo_roster.csv --config fixtures/demo_config.json --as-of 2026-09-15`
- Live: `./run.sh --roster roster/dev-org-roster.csv --config roster/dev-org-config.json` (needs `env` and 1Password)
- Sign-off: `uv run access-review attest reports/<folder>` (verify only) or add `--decision approved --reviewer NAME`

## Rules

- The tool is read-only. `OktaClient` only sends GET requests, plus the token POST. Never add
  write calls, and never request a scope that doesn't end in `.read`.
- Never commit `env`, key files, `reports/`, or anything in `roster/` except its README.
- Never read `env` or print `OKTA_PRIVATE_KEY`, `SMTP_PASSWORD`, `SLACK_WEBHOOK_URL` or
  `SLACK_BOT_TOKEN` (webhook URLs and Slack's pre-signed upload URLs are credentials too; keep them
  out of error messages). Never pass an unchecked `*_REF` value to `op` — it echoes bad references.
- Email bodies contain only counts and completeness; personal data goes only in the PDF attachment.
  Tests must never send real email or Slack posts (`tests/conftest.py` clears both settings).
- A new check needs: an entry in `CHECKS` (`checks.py`) with SOC 2 and ISO 27001 control IDs, a planted
  case in `fixtures/demo_snapshot.json`, and an updated expectation in
  `test_demo_findings_are_exactly_the_planted_ones`.
- After changing the PDF layout or demo fixtures, run `uv run python scripts/render_samples.py`
  and look at `docs/images/*.png` before committing. The README sample must only ever use fixture data.
- Keep the snapshot format (`models.py`) the same for live and fixture data; checks only see `Snapshot`.
- Findings history (`history.py`) and `attest` never write outside the one report folder, never
  change a hashed file, and never send anything. History must never count a review it couldn't
  verify against its manifest; when unsure, count lower.
- `findings.csv` columns are fixed by `FINDING_COLUMNS` (`report.py`). A new `Finding` field changes
  them only if you add it there and update `test_findings_csv_header_is_explicit`.
- Never write anything at the top level of `--out`; tests and `render_samples.py` expect one folder per run.
- Python 3.11+, dependencies pinned by `uv.lock` and `exclude-newer` in `pyproject.toml`.
- CI (`.github/workflows/compliance.yml`): pin every action to a full commit SHA with a version
  comment, keep `permissions: {}` at the top with per-job grants, never interpolate `${{ }}` into
  `run:` (pass it via `env:`), and run `uvx zizmor@<pinned> --offline .github/workflows` after
  editing. If a job is renamed, update `REQUIRED_CHECKS` in `scripts/ci/check_branch_rules.py`
  and the ruleset. See `docs/ci.md`.
