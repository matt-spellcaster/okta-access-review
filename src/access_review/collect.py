"""Build a Snapshot from the live Okta API."""

from __future__ import annotations

import sys
from datetime import datetime, timezone

from .models import SIGN_IN_STATUSES, App, Group, Snapshot, User, parse_time
from .okta import OktaClient, OktaError

PAGE = {"limit": 200}


def _warn(msg: str) -> None:
    print(f"warning: {msg}", file=sys.stderr)


def collect(client: OktaClient) -> Snapshot:
    collected_at = datetime.now(timezone.utc)

    # /users hides DEPROVISIONED users unless asked for them explicitly.
    raw_users = client.get_all("/api/v1/users", PAGE)
    raw_users += client.get_all("/api/v1/users", {**PAGE, "search": 'status eq "DEPROVISIONED"'})

    users = []
    factors_allowed = True
    for u in raw_users:
        user = User(
            id=u["id"],
            login=u["profile"]["login"],
            status=u["status"],
            created=parse_time(u.get("created")),
            last_login=parse_time(u.get("lastLogin")),
            profile=u["profile"],
        )
        if factors_allowed and user.status in SIGN_IN_STATUSES:
            try:
                factors = client.get_all(f"/api/v1/users/{user.id}/factors")
                user.factors = sorted({f["factorType"] for f in factors if f.get("status") == "ACTIVE"})
            except OktaError as e:
                if e.status != 403:
                    raise
                _warn("not allowed to read factors; MFA status will be reported as unknown")
                factors_allowed = False
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
        try:
            grants = client.get_all(f"/api/v1/apps/{a['id']}/grants")
        except OktaError as e:
            if e.status not in (403, 404):
                raise
            grants = []
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
            )
        )

    return Snapshot(org_url=client.org_url, collected_at=collected_at, users=users, groups=groups, apps=apps)
