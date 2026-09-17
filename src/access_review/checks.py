"""Access review checks.

Each check takes a ReviewContext and returns Findings. Every check maps to the
SOC 2 and ISO 27001:2022 controls it provides evidence for.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path
from typing import Callable

from .models import (
    CREDENTIAL_EVENTS,
    DISABLED_STATUSES,
    LIVE_STATUSES,
    SIGN_IN_EVENTS,
    SIGN_IN_STATUSES,
    TOKEN_EVENTS,
    Snapshot,
    User,
)
from .roster import RosterEntry, entry_for

SEVERITIES = ["critical", "high", "medium", "low", "info"]
# Built-in roles that can view but not change anything.
READ_ONLY_ROLES = {"read-only administrator", "report administrator"}
# The full list is in snapshot.json; the finding shows the most important ones.
MAX_SCOPES_SHOWN = 5
HIGH_RISK_SCOPES = [
    "okta.roles.manage", "okta.apiTokens.manage", "okta.clients.manage", "okta.apps.manage",
    "okta.appGrants.manage", "okta.policies.manage", "okta.authenticators.manage",
    "okta.users.manage", "okta.groups.manage",
]


@dataclass
class Config:
    inactive_days: int = 90
    never_signed_in_grace_days: int = 14
    employee_only_groups: list[str] = field(default_factory=list)
    admin_groups: list[str] = field(default_factory=lambda: ["Okta Administrators"])
    # Logins that are expected to be missing from the HR roster.
    service_accounts: list[str] = field(default_factory=list)
    # How far back to read the System Log (AR-12, AR-13). Okta keeps 90 days.
    activity_lookback_days: int = 90
    # PDF look; see pdf.Branding. Empty means the plain layout.
    branding: dict = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path | None) -> Config:
        if path is None:
            return cls()
        data = json.loads(path.read_text())
        unknown = set(data) - set(cls.__dataclass_fields__)
        if unknown:
            raise ValueError(f"unknown config keys: {', '.join(sorted(unknown))}")
        config = cls(**data)
        from .pdf import Branding  # late import: pdf imports this module

        Branding.from_config(config.branding)  # fail fast on bad colors or keys
        return config


@dataclass
class Finding:
    check_id: str
    title: str
    severity: str
    controls: list[str]
    subject: str
    detail: str
    remediation: str


@dataclass
class ReviewContext:
    snapshot: Snapshot
    roster: dict[str, RosterEntry] | None
    config: Config
    as_of: date

    def roster_entry(self, user: User) -> RosterEntry | None:
        return entry_for(self.roster, user.email, user.login)

    def is_service_account(self, user: User) -> bool:
        return user.login.lower() in {s.lower() for s in self.config.service_accounts}


@dataclass
class Check:
    id: str
    title: str
    severity: str
    controls: list[str]
    remediation: str
    run: Callable[[ReviewContext, Check], list[Finding]]
    needs_roster: bool = False

    def finding(self, subject: str, detail: str, severity: str | None = None) -> Finding:
        return Finding(self.id, self.title, severity or self.severity, self.controls, subject, detail, self.remediation)


def _terminated_still_active(ctx: ReviewContext, check: Check) -> list[Finding]:
    out = []
    for u in ctx.snapshot.users:
        entry = ctx.roster_entry(u)
        if u.status in LIVE_STATUSES and entry and entry.status == "terminated":
            when = f" on {entry.end_date}" if entry.end_date else ""
            out.append(check.finding(u.login, f"HR shows terminated{when}; Okta status is {u.status}."))
    return out


def _contract_expired(ctx: ReviewContext, check: Check) -> list[Finding]:
    out = []
    for u in ctx.snapshot.users:
        entry = ctx.roster_entry(u)
        if (
            u.status in LIVE_STATUSES
            and entry
            and entry.status != "terminated"
            and entry.end_date
            and entry.end_date < ctx.as_of
        ):
            out.append(check.finding(u.login, f"End date {entry.end_date} has passed; Okta status is {u.status}."))
    return out


def _not_in_roster(ctx: ReviewContext, check: Check) -> list[Finding]:
    return [
        check.finding(u.login, f"No HR record for this {u.status} account.")
        for u in ctx.snapshot.users
        if u.status in LIVE_STATUSES and not ctx.is_service_account(u) and ctx.roster_entry(u) is None
    ]


def _mfa_missing(ctx: ReviewContext, check: Check) -> list[Finding]:
    out = []
    for u in ctx.snapshot.users:
        if u.status not in SIGN_IN_STATUSES:
            continue
        if u.factors is None:
            out.append(check.finding(u.login, "MFA enrollment could not be read.", severity="info"))
        elif not u.factors:
            out.append(check.finding(u.login, "Can sign in but has no MFA factor enrolled."))
    return out


def _inactive(ctx: ReviewContext, check: Check) -> list[Finding]:
    cutoff = ctx.as_of - timedelta(days=ctx.config.inactive_days)
    return [
        check.finding(u.login, f"Last sign-in {u.last_login.date()} ({(ctx.as_of - u.last_login.date()).days} days ago).")
        for u in ctx.snapshot.users
        if u.status in SIGN_IN_STATUSES and u.last_login and u.last_login.date() < cutoff
    ]


def _never_signed_in(ctx: ReviewContext, check: Check) -> list[Finding]:
    cutoff = ctx.as_of - timedelta(days=ctx.config.never_signed_in_grace_days)
    return [
        check.finding(u.login, f"Created {u.created.date()}, status {u.status}, and has never signed in.")
        for u in ctx.snapshot.users
        if u.status in LIVE_STATUSES and u.last_login is None and u.created and u.created.date() < cutoff
    ]


def _contractor_in_employee_group(ctx: ReviewContext, check: Check) -> list[Finding]:
    restricted = {n.lower() for n in ctx.config.employee_only_groups}
    out = []
    for u in ctx.snapshot.users:
        if u.status not in LIVE_STATUSES:
            continue
        entry = ctx.roster_entry(u)
        kind = (entry.employment_type if entry else u.user_type).lower()
        if kind != "contractor":
            continue
        for g in ctx.snapshot.groups_for(u.id):
            if g.name.lower() in restricted:
                out.append(check.finding(u.login, f"Contractor is a member of employee-only group '{g.name}'."))
    return out


def _missing_owner(ctx: ReviewContext, check: Check) -> list[Finding]:
    out = []
    for u in ctx.snapshot.users:
        if u.status not in LIVE_STATUSES or ctx.is_service_account(u):
            continue
        entry = ctx.roster_entry(u)
        missing = []
        if not (u.manager or (entry and entry.manager)):
            missing.append("manager")
        if not u.department:
            missing.append("department")
        if missing:
            out.append(check.finding(u.login, f"Profile is missing: {', '.join(missing)}."))
    return out


def _disabled_with_access(ctx: ReviewContext, check: Check) -> list[Finding]:
    out = []
    for u in ctx.snapshot.users:
        if u.status not in DISABLED_STATUSES:
            continue
        groups = [g.name for g in ctx.snapshot.groups_for(u.id) if g.type != "BUILT_IN"]
        apps = sorted({app.label for app, _ in ctx.snapshot.apps_for(u.id)})
        if groups or apps:
            parts = []
            if groups:
                parts.append(f"groups: {', '.join(sorted(groups))}")
            if apps:
                parts.append(f"apps: {', '.join(apps)}")
            out.append(check.finding(u.login, f"Status {u.status} but still has {'; '.join(parts)}."))
    return out


def _privileged_service_app(ctx: ReviewContext, check: Check) -> list[Finding]:
    out = []
    for app in ctx.snapshot.apps:
        if app.status != "ACTIVE" or not app.service_client:
            continue
        manage = sorted(
            (s for s in app.granted_scopes if s.endswith(".manage")),
            key=lambda s: (HIGH_RISK_SCOPES.index(s) if s in HIGH_RISK_SCOPES else len(HIGH_RISK_SCOPES), s),
        )
        roles = [r for r in app.admin_roles if r.lower() not in READ_ONLY_ROLES]
        if not (manage or roles):
            continue
        parts = []
        if roles:
            parts.append(f"admin roles: {', '.join(roles)}")
        if manage:
            shown = ", ".join(manage[:MAX_SCOPES_SHOWN])
            more = f" and {len(manage) - MAX_SCOPES_SHOWN} more" if len(manage) > MAX_SCOPES_SHOWN else ""
            label = "write scope" if len(manage) == 1 else f"{len(manage)} write scopes"
            parts.append(f"{label}: {shown}{more}")
        severity = "high" if "Super Administrator" in app.admin_roles else None
        out.append(check.finding(app.label, f"API client has {'; '.join(parts)}.", severity=severity))
    return out


def _clients_set_up_by(snapshot: Snapshot, user_id: str) -> dict[str, str]:
    """Active API clients this person created, rotated or read the secret of,
    as {client_id: label}. Okta keeps no owner field on a client, so the log is
    the only record of who set one up."""
    by_client = {a.client_id: a for a in snapshot.apps if a.client_id and a.status == "ACTIVE"}
    found = {}
    for event in snapshot.events_for_actor(user_id):
        if not event.is_kind(CREDENTIAL_EVENTS):
            continue
        for target in event.targets:
            app = by_client.get(target.get("id"))
            if app:
                found[app.client_id] = app.label
    return found


def _left_on(entry: RosterEntry) -> str:
    return f"Left {entry.end_date}" if entry.end_date else "HR shows terminated"


def _leavers(ctx: ReviewContext) -> list[tuple[User, RosterEntry]]:
    """Everyone the roster says is gone: terminated, or past their end date."""
    pairs = ((u, ctx.roster_entry(u)) for u in ctx.snapshot.users)
    return [(u, e) for u, e in pairs if e and e.is_gone(ctx.as_of)]


def _leaver_credentials(ctx: ReviewContext, check: Check) -> list[Finding]:
    out = []
    for user, entry in _leavers(ctx):
        parts = []
        tokens = sorted(t.name or t.id for t in ctx.snapshot.tokens_for(user.id))
        if tokens:
            noun = "API token" if len(tokens) == 1 else "API tokens"
            parts.append(f"{noun} {', '.join(tokens)}")
        clients = sorted(_clients_set_up_by(ctx.snapshot, user.id).values())
        if clients:
            noun = "API client" if len(clients) == 1 else "API clients"
            parts.append(f"{noun} they set up: {', '.join(clients)}")
        # Groups and apps are AR-09's job; this check is only about credentials
        # that keep working on their own, whatever the account status is.
        if parts:
            out.append(check.finding(user.login, f"{_left_on(entry)} but still holds {'; '.join(parts)}."))
    return out


def _count(n: int, noun: str) -> str:
    return f"{n} {noun}" if n == 1 else f"{n} {noun}s"


def _activity_after_leaving(ctx: ReviewContext, check: Check) -> list[Finding]:
    out = []
    for user, entry in _leavers(ctx):
        if entry.end_date is None:
            out.append(check.finding(
                user.login,
                "HR shows terminated with no end date, so activity after they left cannot be identified.",
                severity="info",
            ))
            continue
        # The end date is their last working day, so only what follows it counts.
        cutoff = datetime.combine(entry.end_date, time.max, tzinfo=timezone.utc)
        actors = {user.id} | set(_clients_set_up_by(ctx.snapshot, user.id))
        after = sorted(
            (e for a in actors for e in ctx.snapshot.events_for_actor(a) if e.published and e.published > cutoff),
            key=lambda e: e.published,
        )
        parts = []
        for events, noun in (
            ([e for e in after if e.is_kind(SIGN_IN_EVENTS)], "sign-in"),
            ([e for e in after if e.is_kind(TOKEN_EVENTS)], "token grant"),
            ([e for e in after if e.is_kind(CREDENTIAL_EVENTS)], "credential change"),
        ):
            if events:
                parts.append(_count(len(events), noun))
        if not parts:
            continue
        last = after[-1]
        where = next((t["label"] for t in last.targets if t.get("label")), last.event_type)
        out.append(check.finding(
            user.login,
            f"{', '.join(parts)} after {entry.end_date}; last {last.published.date()} ({where}).",
        ))
    return out


def _admin_membership(ctx: ReviewContext, check: Check) -> list[Finding]:
    admin_groups = {n.lower() for n in ctx.config.admin_groups}
    out = []
    for u in ctx.snapshot.users:
        if u.status == "DEPROVISIONED":
            continue
        reasons = []
        if u.admin_roles:
            reasons.append(f"admin roles: {', '.join(u.admin_roles)}")
        groups = [g.name for g in ctx.snapshot.groups_for(u.id) if g.name.lower() in admin_groups]
        if groups:
            reasons.append(f"admin groups: {', '.join(groups)}")
        if reasons:
            out.append(check.finding(u.login, f"Has {'; '.join(reasons)}. Confirm this is still needed."))
    return out


CHECKS: list[Check] = [
    Check(
        "AR-01", "Terminated in HR but account still live", "critical",
        ["SOC 2 CC6.2", "SOC 2 CC6.3", "ISO 27001 A.5.18"],
        "Deactivate the Okta account and confirm app sessions are revoked.",
        _terminated_still_active, needs_roster=True,
    ),
    Check(
        "AR-02", "Contract or end date has passed", "high",
        ["SOC 2 CC6.2", "ISO 27001 A.5.18"],
        "Deactivate the account or get the end date extended in HR.",
        _contract_expired, needs_roster=True,
    ),
    Check(
        "AR-03", "Account has no HR record", "high",
        ["SOC 2 CC6.2", "ISO 27001 A.5.16"],
        "Identify the owner. Add to HR, list as a service account, or deactivate.",
        _not_in_roster, needs_roster=True,
    ),
    Check(
        "AR-04", "No MFA factor enrolled", "high",
        ["SOC 2 CC6.1", "ISO 27001 A.8.5"],
        "Require MFA enrollment through an authentication policy.",
        _mfa_missing,
    ),
    Check(
        "AR-05", "Inactive account", "medium",
        ["SOC 2 CC6.2", "ISO 27001 A.5.18"],
        "Confirm with the manager whether access is still needed; suspend if not.",
        _inactive,
    ),
    Check(
        "AR-06", "Account never used", "medium",
        ["SOC 2 CC6.2", "ISO 27001 A.5.16"],
        "Confirm the account is still needed, or deactivate it.",
        _never_signed_in,
    ),
    Check(
        "AR-07", "Contractor in employee-only group", "medium",
        ["SOC 2 CC6.3", "ISO 27001 A.5.15"],
        "Remove the contractor from the group or document an approved exception.",
        _contractor_in_employee_group,
    ),
    Check(
        "AR-08", "Missing manager or department", "low",
        ["SOC 2 CC6.2", "ISO 27001 A.5.16"],
        "Fill in the profile so the account has an accountable reviewer.",
        _missing_owner,
    ),
    Check(
        "AR-09", "Disabled account still holds access", "medium",
        ["SOC 2 CC6.2", "ISO 27001 A.5.18"],
        "Remove group memberships and app assignments so reactivation doesn't restore access.",
        _disabled_with_access,
    ),
    Check(
        "AR-10", "API client with admin access", "medium",
        ["SOC 2 CC6.3", "ISO 27001 A.8.2"],
        "Confirm each .manage scope and admin role is needed; prefer a least-privilege custom role.",
        _privileged_service_app,
    ),
    Check(
        "AR-11", "Admin user", "info",
        ["SOC 2 CC6.3", "ISO 27001 A.8.2"],
        "Reviewer confirms each admin still needs the role.",
        _admin_membership,
    ),
    Check(
        "AR-12", "Leaver still holds a working credential", "critical",
        ["SOC 2 CC6.2", "SOC 2 CC6.3", "ISO 27001 A.5.18"],
        "Revoke the API token and rotate or delete the client's credentials. "
        "Deactivating the account does not do either.",
        _leaver_credentials, needs_roster=True,
    ),
    Check(
        "AR-13", "Activity after the termination date", "critical",
        ["SOC 2 CC6.2", "SOC 2 CC7.2", "ISO 27001 A.5.18", "ISO 27001 A.8.16"],
        "Treat as a possible incident: revoke the credential, review what it reached, "
        "and confirm the termination date with HR.",
        _activity_after_leaving, needs_roster=True,
    ),
]


def run_checks(ctx: ReviewContext) -> tuple[list[Finding], list[str]]:
    """Run every check. Returns findings (most severe first) and IDs of skipped checks."""
    findings, skipped = [], []
    for check in CHECKS:
        if check.needs_roster and ctx.roster is None:
            skipped.append(check.id)
            continue
        findings.extend(check.run(ctx, check))
    findings.sort(key=lambda f: (SEVERITIES.index(f.severity), f.check_id, f.subject))
    return findings, skipped
