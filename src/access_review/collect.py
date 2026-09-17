"""Build a Snapshot from the live Okta API."""

from __future__ import annotations

import sys
from datetime import datetime, timezone

from .models import SIGN_IN_STATUSES, App, Group, Snapshot, User, parse_time
from .okta import OktaClient, OktaError

PAGE = {"limit": 200}


def _warn(msg: str) -> None:
    print(f"warning: {msg}", file=sys.stderr)


class _Optional:
    """Calls an endpoint that needs an extra scope or admin permission. After
    the first 403 it records a gap, warns once and stops calling, so the review
    still runs and the report says what is missing."""

    def __init__(self, client: OktaClient, what: str, scope: str, affects: str, gaps: list[str]):
        self.client = client
        self.what = what
        self.scope = scope
        self.affects = affects
        self.gaps = gaps
        self.allowed = True

    def get(self, path: str, missing_ok: bool = False) -> list | None:
        if not self.allowed:
            return None
        try:
            return self.client.get_all(path)
        except OktaError as e:
            if missing_ok and e.status == 404:
                return []
            if e.status != 403:
                raise
            gap = (
                f"Could not read {self.what}; {self.affects} may be incomplete. "
                f"Needs the {self.scope} scope and an admin role allowed to view this data. ({e})"
            )
            _warn(gap)
            self.gaps.append(gap)
            self.allowed = False
            return None


def _role_labels(assignments: list) -> list[str]:
    return sorted({a.get("label") or a.get("type", "unknown") for a in assignments})


def collect(client: OktaClient) -> Snapshot:
    collected_at = datetime.now(timezone.utc)
    gaps: list[str] = []
    factors_api = _Optional(client, "MFA factors", "okta.users.read", "AR-04", gaps)
    roles_api = _Optional(client, "admin role assignments", "okta.roles.read", "AR-10 and AR-11", gaps)
    grants_api = _Optional(client, "app API scope grants", "okta.appGrants.read", "AR-10", gaps)

    # /users hides DEPROVISIONED users unless asked for them explicitly.
    raw_users = client.get_all("/api/v1/users", PAGE)
    raw_users += client.get_all("/api/v1/users", {**PAGE, "search": 'status eq "DEPROVISIONED"'})

    users = []
    for u in raw_users:
        user = User(
            id=u["id"],
            login=u["profile"]["login"],
            status=u["status"],
            created=parse_time(u.get("created")),
            last_login=parse_time(u.get("lastLogin")),
            profile=u["profile"],
        )
        if user.status in SIGN_IN_STATUSES:
            factors = factors_api.get(f"/api/v1/users/{user.id}/factors")
            if factors is not None:
                user.factors = sorted({f["factorType"] for f in factors if f.get("status") == "ACTIVE"})
        if user.status != "DEPROVISIONED":
            roles = roles_api.get(f"/api/v1/users/{user.id}/roles")
            if roles is not None:
                user.admin_roles = _role_labels(roles)
        users.append(user)

    groups = []
    for g in client.get_all("/api/v1/groups", PAGE):
        members = client.get_all(f"/api/v1/groups/{g['id']}/users", PAGE)
        groups.append(
            Group(id=g["id"], name=g["profile"]["name"], type=g.get("type", ""), members={m["id"] for m in members})
        )

    apps = []
    for a in client.get_all("/api/v1/apps", PAGE):
        app_users = client.get_all(f"/api/v1/apps/{a['id']}/users", PAGE)
        app_groups = client.get_all(f"/api/v1/apps/{a['id']}/groups", PAGE)
        grants = grants_api.get(f"/api/v1/apps/{a['id']}/grants") or []
        roles = []
        # Only OAuth service clients can hold admin roles.
        client_id = a.get("credentials", {}).get("oauthClient", {}).get("client_id")
        grant_types = a.get("settings", {}).get("oauthClient", {}).get("grant_types", [])
        service_client = bool(client_id) and "client_credentials" in grant_types
        if service_client:
            roles = roles_api.get(f"/oauth2/v1/clients/{client_id}/roles", missing_ok=True) or []
        apps.append(
            App(
                id=a["id"],
                label=a["label"],
                status=a.get("status", ""),
                sign_on_mode=a.get("signOnMode", ""),
                # Group-based assignments show up here too; keep only direct ones.
                users={u["id"] for u in app_users if u.get("scope", "USER") == "USER"},
                groups={g["id"] for g in app_groups},
                granted_scopes=sorted({g["scopeId"] for g in grants if g.get("status", "ACTIVE") == "ACTIVE"}),
                admin_roles=_role_labels(roles),
                service_client=service_client,
            )
        )

    # The review app always exists, so if it's missing the admin role is hiding apps.
    if client.client_id not in {a.id for a in apps}:
        gap = (
            f"The app list does not include this review app ({client.client_id}), so the admin role is "
            f"hiding apps. App assignments, AR-09 and AR-10 are incomplete ({len(apps)} apps visible)."
        )
        _warn(gap)
        gaps.append(gap)

    return Snapshot(
        org_url=client.org_url, collected_at=collected_at, users=users, groups=groups, apps=apps, gaps=gaps
    )
