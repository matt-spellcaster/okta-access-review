"""Normalized snapshot of an Okta org.

The collector turns Okta API responses into this shape, and fixtures use it
directly, so every check runs the same way against live or demo data.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

# Statuses where the account exists and can be (or become) usable.
LIVE_STATUSES = {"STAGED", "PROVISIONED", "ACTIVE", "RECOVERY", "PASSWORD_EXPIRED", "LOCKED_OUT"}
# Statuses where the user has actually been able to sign in.
SIGN_IN_STATUSES = {"ACTIVE", "RECOVERY", "PASSWORD_EXPIRED", "LOCKED_OUT"}
# Statuses where sign-in is blocked but the account and its access remain.
DISABLED_STATUSES = {"SUSPENDED", "DEPROVISIONED"}


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def format_time(value: datetime | None) -> str | None:
    return value.isoformat().replace("+00:00", "Z") if value else None


@dataclass
class User:
    id: str
    login: str
    status: str
    created: datetime | None = None
    last_login: datetime | None = None
    profile: dict = field(default_factory=dict)
    # Enrolled factor types. None means unknown (not collected or not allowed).
    factors: list[str] | None = None
    # Admin role labels assigned directly to the user. None means unknown.
    admin_roles: list[str] | None = None

    @property
    def email(self) -> str:
        return (self.profile.get("email") or self.login).lower()

    @property
    def name(self) -> str:
        return f"{self.profile.get('firstName', '')} {self.profile.get('lastName', '')}".strip()

    @property
    def user_type(self) -> str:
        return (self.profile.get("userType") or "").strip()

    @property
    def manager(self) -> str:
        return (self.profile.get("manager") or "").strip()

    @property
    def department(self) -> str:
        return (self.profile.get("department") or "").strip()

    @classmethod
    def from_dict(cls, d: dict) -> User:
        return cls(
            id=d["id"],
            login=d["login"],
            status=d["status"],
            created=parse_time(d.get("created")),
            last_login=parse_time(d.get("lastLogin")),
            profile=d.get("profile", {}),
            factors=d.get("factors"),
            admin_roles=d.get("adminRoles"),
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "login": self.login,
            "status": self.status,
            "created": format_time(self.created),
            "lastLogin": format_time(self.last_login),
            "profile": self.profile,
            "factors": self.factors,
            "adminRoles": self.admin_roles,
        }


@dataclass
class Group:
    id: str
    name: str
    type: str
    members: set[str] = field(default_factory=set)

    @classmethod
    def from_dict(cls, d: dict) -> Group:
        return cls(id=d["id"], name=d["name"], type=d.get("type", "OKTA_GROUP"), members=set(d.get("members", [])))

    def to_dict(self) -> dict:
        return {"id": self.id, "name": self.name, "type": self.type, "members": sorted(self.members)}


@dataclass
class App:
    id: str
    label: str
    status: str
    sign_on_mode: str = ""
    users: set[str] = field(default_factory=set)  # directly assigned user IDs
    groups: set[str] = field(default_factory=set)  # assigned group IDs
    granted_scopes: list[str] = field(default_factory=list)  # Okta API scopes granted to the app
    admin_roles: list[str] = field(default_factory=list)  # admin roles assigned to the app's client
    # True for OAuth clients that act on their own authority (client_credentials),
    # as opposed to apps that act for a signed-in user.
    service_client: bool = False

    @classmethod
    def from_dict(cls, d: dict) -> App:
        return cls(
            id=d["id"],
            label=d["label"],
            status=d.get("status", "ACTIVE"),
            sign_on_mode=d.get("signOnMode", ""),
            users=set(d.get("users", [])),
            groups=set(d.get("groups", [])),
            granted_scopes=list(d.get("grantedScopes", [])),
            admin_roles=list(d.get("adminRoles", [])),
            service_client=d.get("serviceClient", False),
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "label": self.label,
            "status": self.status,
            "signOnMode": self.sign_on_mode,
            "users": sorted(self.users),
            "groups": sorted(self.groups),
            "grantedScopes": sorted(self.granted_scopes),
            "adminRoles": sorted(self.admin_roles),
            "serviceClient": self.service_client,
        }


@dataclass
class Snapshot:
    org_url: str
    collected_at: datetime
    users: list[User]
    groups: list[Group]
    apps: list[App]
    # Data the collector could not read, so the report can say what is incomplete.
    gaps: list[str] = field(default_factory=list)

    def groups_for(self, user_id: str) -> list[Group]:
        return [g for g in self.groups if user_id in g.members]

    def apps_for(self, user_id: str) -> list[tuple[App, str]]:
        """Apps a user can reach, with how: 'direct' or 'group:<name>'."""
        group_ids = {g.id: g.name for g in self.groups_for(user_id)}
        result = []
        for app in self.apps:
            if user_id in app.users:
                result.append((app, "direct"))
            for gid in sorted(app.groups & group_ids.keys()):
                result.append((app, f"group:{group_ids[gid]}"))
        return result

    @classmethod
    def from_dict(cls, d: dict) -> Snapshot:
        return cls(
            org_url=d["org_url"],
            collected_at=parse_time(d["collected_at"]),
            users=[User.from_dict(u) for u in d["users"]],
            groups=[Group.from_dict(g) for g in d["groups"]],
            apps=[App.from_dict(a) for a in d["apps"]],
            gaps=list(d.get("gaps", [])),
        )

    def to_dict(self) -> dict:
        return {
            "org_url": self.org_url,
            "collected_at": format_time(self.collected_at),
            "users": [u.to_dict() for u in self.users],
            "groups": [g.to_dict() for g in self.groups],
            "apps": [a.to_dict() for a in self.apps],
            "gaps": self.gaps,
        }
