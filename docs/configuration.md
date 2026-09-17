# Configuration

## Okta app

1. In the Okta Admin Console, go to **Applications → Create App Integration → API Services** and
   name it, e.g. "Access Review (read-only)".
2. **Client authentication:** Public key / Private key. Generate a key, save it as PEM, and note its
   Key ID. Leave **Require DPoP header in token requests** on.
3. **Okta API Scopes:** grant only these:

   | Scope | Used for |
   |---|---|
   | `okta.users.read` | Users, last sign-in, MFA factors |
   | `okta.groups.read` | Groups and members |
   | `okta.apps.read` | Apps and their user and group assignments |
   | `okta.appGrants.read` | API scopes granted to other apps (AR-10) |
   | `okta.roles.read` | Admin roles of users and API apps (AR-10, AR-11) |

4. **Admin roles:** Super Administrator for full coverage, or Read-Only Administrator for a review
   that skips admin roles. See [the tradeoff](security.md#admin-role-a-tested-tradeoff).
5. Optional: under **General**, limit token requests to a network zone.
6. Store the PEM in a 1Password Secure Note, then delete the downloaded file.

## `env`

Copy `env.example` to `env` (git-ignored). Secrets are always `op://` references.

| Setting | Required | Notes |
|---|---|---|
| `OKTA_ORG_URL`, `OKTA_CLIENT_ID`, `OKTA_KEY_ID` | yes | From the Okta app |
| `OKTA_PRIVATE_KEY_REF` | yes | 1Password reference to the PEM |
| `OKTA_SCOPES` | yes | Read scopes only; the CLI refuses anything else |
| `OKTA_DPOP` | no | `true` (default); must match the app's DPoP setting |
| `REPORT_EMAIL_*`, `SMTP_*` | no | See [notifications](notifications.md#email) |
| `SLACK_*` | no | See [notifications](notifications.md#slack) |

## Review config (`--config`)

A JSON file. Every key is optional, and unknown keys are rejected.

| Key | Default | Meaning |
|---|---|---|
| `inactive_days` | `90` | AR-05 threshold |
| `never_signed_in_grace_days` | `14` | AR-06 threshold |
| `employee_only_groups` | `[]` | Groups contractors shouldn't be in (AR-07) |
| `admin_groups` | `["Okta Administrators"]` | Groups treated as admin access (AR-11) |
| `service_accounts` | `[]` | Logins expected to be missing from the HR roster (AR-03) |
| `branding` | none | PDF branding, below |

Example: [`fixtures/demo_config.json`](../fixtures/demo_config.json).

### PDF branding

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

- `primary` colors the header band, title and headings. `accent` colors the logo tile and the line
  under the band. Both must be `#rrggbb`.
- `logo` selects a built-in logo drawn in code. `acme` is the only one; there are no image files.
- Severity colors are fixed so they mean the same thing in every report.
- Without `branding`, the PDF uses a plain layout. Invalid branding stops the run before it
  contacts Okta.

## HR roster (`--roster`)

```csv
email,name,employment_type,status,end_date,manager
ana@example.com,Ana Diaz,employee,active,,Sam Lee
raj@example.com,Raj Rao,contractor,active,2026-12-31,Sam Lee
bo@example.com,Bo Kim,employee,terminated,2026-08-01,Sam Lee
```

- `employment_type`: `employee` or `contractor`
- `status`: `active`, `leave` or `terminated`
- `end_date`: termination date or contract end date (optional)

Keep real rosters in `roster/`, which is git-ignored.

## Command-line options

| Option | Meaning |
|---|---|
| `--snapshot FILE` | Review a saved snapshot instead of calling Okta |
| `--roster FILE` | HR roster; enables AR-01 to AR-03 |
| `--config FILE` | Review config |
| `--out DIR` | Output folder (default `reports/`) |
| `--as-of DATE` | Review date (default: UTC date the data was collected) |
| `--fail-on SEVERITY` | Exit with status 2 if any finding is at that severity or worse |
| `--no-email`, `--no-slack` | Skip a notification for one run |

Exit codes: `0` ok, `1` configuration or Okta error, `2` `--fail-on` threshold reached, `3` report
saved but a notification failed.
