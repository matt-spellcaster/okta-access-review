# okta-access-review

Read-only Okta user access review that produces SOC 2 / ISO 27001 audit evidence.

## Commands

- Tests: `uv run pytest -q`
- Demo (no Okta needed): `uv run access-review --snapshot fixtures/demo_snapshot.json --roster fixtures/demo_roster.csv --config fixtures/demo_config.json --as-of 2026-09-15`
- Live: `./run.sh --roster roster/dev-org-roster.csv --config roster/dev-org-config.json` (needs `env` and 1Password)

## Rules

- The tool is read-only. `OktaClient` only sends GET requests, plus the token POST. Never add
  write calls, and never request a scope that doesn't end in `.read`.
- Never commit `env`, key files, `reports/`, or anything in `roster/` except its README.
- Never read `env` or print `OKTA_PRIVATE_KEY` or `SMTP_PASSWORD`.
- Email bodies contain only counts and completeness; personal data goes only in the PDF attachment.
  Tests must never send real email (`tests/conftest.py` clears `REPORT_EMAIL_TO`).
- A new check needs: an entry in `CHECKS` (`checks.py`) with SOC 2 and ISO 27001 control IDs, a planted
  case in `fixtures/demo_snapshot.json`, and an updated expectation in
  `test_demo_findings_are_exactly_the_planted_ones`.
- Keep the snapshot format (`models.py`) the same for live and fixture data; checks only see `Snapshot`.
- Python 3.11+, dependencies pinned by `uv.lock` and `exclude-newer` in `pyproject.toml`.
