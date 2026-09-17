# okta-access-review

A read-only command-line tool for Okta user access reviews. It pulls users, groups, apps and MFA
enrollment from Okta and compares them with an HR roster. It then flags access that shouldn't
exist and writes the results as audit evidence mapped to SOC 2 and ISO 27001:2022 controls.

A periodic user access review is a standard SOC 2 control (CC6.2/CC6.3), and in many companies
it's still done by hand in spreadsheets. This tool does the data gathering and the obvious checks,
so the reviewer only has to decide on the flagged items and sign off.

## Sample report

Each run produces a PDF like this one. The data is from the demo company Acme, and every name in
it is made up.

![Page 1 of the sample report: summary and findings by severity](docs/images/report-page-1.png)

<details>
<summary>Page 2: control mapping and access by user</summary>

![Page 2 of the sample report: remediation, SOC 2 and ISO 27001 control mapping, and access by user](docs/images/report-page-2.png)

</details>

[Open the full sample PDF](docs/sample-report.pdf), which also has the reviewer sign-off page.

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
| AR-10 | Service app (client credentials) with `.manage` scopes or a non-read-only admin role (high if Super Administrator) | medium | SOC 2 CC6.3 · ISO A.8.2 |
| AR-11 | User with an admin role or in an admin group (for confirmation) | info | SOC 2 CC6.3 · ISO A.8.2 |

AR-01 to AR-03 need `--roster`. Without it they're skipped, and the report says so. Thresholds and
group names are set in a JSON config file (see `fixtures/demo_config.json`).

## Output

Each run writes to `reports/<collection time>/`:

| File | Purpose |
|---|---|
| `report.md` | Summary, findings grouped by check with control mapping and fix, sign-off block |
| `findings.csv` | One row per finding, for tracking remediation |
| `access_matrix.csv` | Every user with status, groups, apps (and how they were granted), MFA, last sign-in, plus blank `decision` / `reviewer` columns for the review |
| `report.pdf` | The report as a PDF, for sharing and signing |
| `snapshot.json` | The exact data the checks ran on |
| `manifest.json` | Run metadata, config, and a SHA-256 hash of every file above, so you can later show the evidence wasn't edited |

A `report.pdf` with the same content plus a sign-off page is also written, and its hash is in
the manifest.

### PDF branding

Add a `branding` section to the config file to put a company brand on the PDF. The demo uses
**Acme**, a made-up company whose logo is drawn in code, so there are no image files:

```json
"branding": {
  "name": "Acme",
  "tagline": "Security & Compliance",
  "primary": "#0B2545",
  "accent": "#F2A541",
  "footer": "Confidential",
  "logo": "acme"
}
```

`primary` colors the header band, title and headings, and `accent` colors the logo tile and the
line under the band. Colors must be `#rrggbb`. Severity colors are fixed so they mean the same
thing in every report. Without `branding`, the PDF uses a plain layout. Invalid branding stops the
run before it contacts Okta.

`--fail-on <severity>` makes the command exit with status 2 if any finding is at that severity
or worse, so it can gate a scheduled job or CI pipeline.

## Emailing the report

If `REPORT_EMAIL_TO` is set in `env`, each live run ends by emailing `report.pdf` over SMTP.

- **The body has no personal data.** It contains only the finding counts, whether the review
  is complete, and the PDF's SHA-256 hash so the recipient can match it to `manifest.json`.
  Names, emails and roles appear only in the attachment.
- **TLS is required.** Use port 587 (STARTTLS) or 465 (TLS). The tool refuses other ports and
  servers that don't offer STARTTLS.
- **The SMTP password lives in 1Password.** `run.sh` fetches it with `op read`, like the Okta key.
- **Settings are checked first.** A missing setting stops the run before it contacts Okta. If
  sending fails, the report is still saved and the command exits with status 3.
- Use `--no-email` to skip sending for one run.

Any SMTP provider works. Typical settings (check your provider's docs):

| Provider | `SMTP_HOST` | `SMTP_USERNAME` | Password in 1Password |
|---|---|---|---|
| SendGrid | `smtp.sendgrid.net` | `apikey` | API key with Mail Send permission |
| Postmark | `smtp.postmarkapp.com` | Server API token | The same server API token |
| Amazon SES | `email-smtp.<region>.amazonaws.com` | SMTP username | SMTP password |

`REPORT_EMAIL_FROM` must be an address or domain you've verified with the provider.

## Security design

This follows the same model as [okta-mcp-local](../okta-mcp-local): assume the laptop or repo
could leak, and limit what a leak could do.

- **Read-only enforced by scopes.** Okta allows an API call only if the token's scopes **and**
  the app's admin role both permit it. The app is granted only `.read` scopes, the CLI refuses to
  request any other scope, and the client's only non-GET request is the token request (a test
  enforces this).
- **Why the app has Super Administrator (a deliberate tradeoff).** Tested on a dev org:

  | Admin role | Sees API service apps | Reads app scope grants | Reads admin role assignments |
  |---|---|---|---|
  | Read-Only Administrator | yes | no | no |
  | Organization Administrator | no (app list is empty) | n/a | no |
  | Super Administrator | yes | yes | yes |

  Reviewing admin access (AR-10, AR-11) is a core SOC 2 access control and needs all three, so
  the app uses Super Administrator. Because its scopes are read-only, the role only widens what it
  can *read*. The remaining risk is that someone grants the app a `.manage` scope later. That
  would make it a full admin, so AR-10 flags the review app itself on every run for the
  reviewer to confirm. If you'd rather use Read-Only Administrator, the tool still runs and marks
  the review incomplete.
- **Reports say when they're incomplete.** If the admin role hides data, the review still runs,
  but the report lists each gap under "Data gaps" and `manifest.json` records `"complete": false`.
  The tool checks that it can see its own app, which catches a role that silently hides the app list.
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
   - **Okta API Scopes:** grant only these:

     | Scope | Used for |
     |---|---|
     | `okta.users.read` | Users, last sign-in, MFA factors |
     | `okta.groups.read` | Groups and members |
     | `okta.apps.read` | Apps and their user/group assignments |
     | `okta.appGrants.read` | API scopes granted to other apps (AR-10) |
     | `okta.roles.read` | Admin roles of users and API apps (AR-10, AR-11) |

   - **Admin roles:** assign **Super Administrator** for full coverage, or **Read-Only
     Administrator** for a review that skips admin roles. See the tradeoff under Security design.
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
- Admin roles are read from direct user and API client assignments. Roles granted to a group are
  not expanded to its members yet.
- Apps assigned through a group show up once for each group that grants them.

## Development

```bash
uv run pytest -q
```

If you change the PDF layout or the demo data, regenerate the README sample. A test fails if
`docs/sample-report.pdf` is out of date.

```bash
uv run python scripts/render_samples.py
```
