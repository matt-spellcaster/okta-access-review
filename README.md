# okta-access-review

A read-only command-line tool for Okta user access reviews. It pulls users, groups, apps and MFA
enrollment from Okta and compares them with an HR roster. It then flags access that shouldn't
exist and writes the results as audit evidence mapped to SOC 2 and ISO 27001:2022 controls.

A periodic user access review is a standard SOC 2 control (CC6.2/CC6.3), and in many companies
it's still done by hand in spreadsheets. This tool does the data gathering and the obvious checks,
so the reviewer only has to decide on the flagged items and sign off.

## Try it without Okta

```bash
uv run access-review \
  --snapshot fixtures/demo_snapshot.json \
  --roster fixtures/demo_roster.csv \
  --config fixtures/demo_config.json \
  --as-of 2026-09-15
```

The demo uses a fictional company with one planted issue for each check.

## Checks

| ID | Check | Severity | Controls |
|---|---|---|---|
| AR-01 | Terminated in HR but account still live | critical | SOC 2 CC6.2, CC6.3 · ISO A.5.18 |
| AR-02 | Contract or end date has passed | high | SOC 2 CC6.2 · ISO A.5.18 |
| AR-03 | Account has no HR record (excluding listed service accounts) | high | SOC 2 CC6.2 · ISO A.5.16 |
| AR-04 | Can sign in but has no MFA factor | high | SOC 2 CC6.1 · ISO A.8.5 |
| AR-05 | No sign-in for 90+ days | medium | SOC 2 CC6.2 · ISO A.5.18 |
| AR-06 | Created 14+ days ago and never used | medium | SOC 2 CC6.2 · ISO A.5.16 |
| AR-07 | Contractor in an employee-only group | medium | SOC 2 CC6.3 · ISO A.5.15 |
| AR-08 | Missing manager or department | low | SOC 2 CC6.2 · ISO A.5.16 |
| AR-09 | Suspended or deprovisioned but still in groups or apps | medium | SOC 2 CC6.2 · ISO A.5.18 |
| AR-10 | API client granted `.manage` scopes | medium | SOC 2 CC6.3 · ISO A.8.2 |
| AR-11 | Admin group member (for confirmation) | info | SOC 2 CC6.3 · ISO A.8.2 |

AR-01 to AR-03 need `--roster`. Without it they're skipped, and the report says so. Thresholds and
group names are set in a JSON config file (see `fixtures/demo_config.json`).

## Output

Each run writes to `reports/<collection time>/`:

| File | Purpose |
|---|---|
| `report.md` | Summary, findings grouped by check with control mapping and fix, sign-off block |
| `findings.csv` | One row per finding, for tracking remediation |
| `access_matrix.csv` | Every user with status, groups, apps (and how they were granted), MFA, last sign-in, plus blank `decision` / `reviewer` columns for the review |
| `snapshot.json` | The exact data the checks ran on |
| `manifest.json` | Run metadata, config, and a SHA-256 hash of every file above, so you can later show the evidence wasn't edited |

`--fail-on <severity>` makes the command exit with status 2 if any finding is at that severity
or worse, so it can gate a scheduled job or CI pipeline.

## Security design

This follows the same model as [okta-mcp-local](../okta-mcp-local): assume the laptop or repo
could leak, and limit what a leak could do.

- **Read-only in three places.** The Okta app is granted only `.read` scopes and the built-in
  Read-Only Administrator role. The CLI refuses to request any scope that doesn't end in `.read`.
  The client's only non-GET request is the token request, and a test enforces this.
- **No shared secret.** Private Key JWT client authentication. The key lives in 1Password and
  `run.sh` fetches it with `op read` each run. It is never written to disk.
- **Tokens bound to the run (DPoP).** Each run generates a P-256 key in memory. Okta binds the
  access token to it, and every API call carries a signed proof for that token and URL. A token
  copied from logs or memory is useless without the key, and the key is gone when the process
  exits. This closes the bearer-token gap that okta-mcp-local covers with a network zone.
- **Separate app from the MCP server.** A leaked review key can't change anything, even though the
  MCP app has write scopes.
- **Personal data stays local.** `reports/` and `roster/` are git-ignored. The pre-commit hook
  blocks `env` and private keys.
- **Pinned dependencies.** `uv.lock` plus `exclude-newer` in `pyproject.toml`; `run.sh` uses
  `uv run --frozen`.

## Live setup

1. In the Okta Admin Console, go to **Applications → Create App Integration → API Services**. Name
   it "Access Review (read-only)".
2. On the app:
   - **Client authentication:** Public key / Private key. Generate a key, save it as PEM, note the
     Key ID. Leave **Require DPoP header in token requests** on.
   - **Okta API Scopes:** grant `okta.users.read`, `okta.groups.read`, `okta.apps.read`.
   - **Admin roles:** assign **Read-Only Administrator**.
   - Optional: under **General**, limit token requests to your network zone.
3. Store the PEM in a 1Password Secure Note, for example "Okta access review key" in `dev`, then
   delete the downloaded file.
4. Run `cp env.example env` and fill it in.
5. Run `git config core.hooksPath .githooks`.
6. Put your HR roster CSV and config in `roster/`, then run:

   ```bash
   ./run.sh --roster roster/dev-org-roster.csv --config roster/dev-org-config.json
   ```

### Roster format

```csv
email,name,employment_type,status,end_date,manager
ana@example.com,Ana Diaz,employee,active,,Sam Lee
raj@example.com,Raj Rao,contractor,active,2026-12-31,Sam Lee
bo@example.com,Bo Kim,employee,terminated,2026-08-01,Sam Lee
```

`employment_type` is `employee` or `contractor`. `status` is `active`, `leave` or `terminated`.

## Limitations

- MFA status comes from enrolled Okta factors. It doesn't check whether a sign-on policy actually
  requires MFA.
- Admin access is detected through admin groups, not individual admin role assignments.
- Apps assigned through a group show up once for each group that grants them.

## Development

```bash
uv run pytest -q
```
