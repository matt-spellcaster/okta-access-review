"""Activity evidence: the System Log projection and the leaver checks that read it."""

import json
from datetime import datetime, timezone

from access_review.models import ActivityEvent, ApiToken, App, Snapshot

# Shaped like a real app.oauth2.credentials.lifecycle.create event, which is the
# worst case: Okta puts the new client secret in target[].detailEntry in plain
# text, and the event also carries the admin's address and location. The secret
# here is invented; never paste a real one into a test.
SECRET = "NOT-A-REAL-SECRET-abc123"
RAW_EVENT = {
    "uuid": "c6055d29-b2b9-11f1-929e-df99088ffd08",
    "published": "2026-09-02T14:12:03.613000Z",
    "eventType": "app.oauth2.credentials.lifecycle.create",
    "legacyEventType": "app.oauth2.credentials.lifecycle.create",
    "severity": "INFO",
    "displayMessage": "Create OAuth2 client credential",
    "actor": {"id": "u02", "type": "User", "displayName": "Marcus Lee", "alternateId": "marcus.lee@acme.example"},
    "outcome": {"result": "SUCCESS", "reason": None},
    "client": {
        "device": "Computer",
        "ipAddress": "203.0.113.42",
        "userAgent": {"browser": "CHROME", "os": "Mac OS X", "rawUserAgent": "Mozilla/5.0 ..."},
        "geographicalContext": {"city": "Naperville", "state": "Illinois", "country": "United States"},
    },
    "debugContext": {"debugData": {"clientId": "0oaBOT", "requestUri": "/api/v1/apps", "dtHash": "fbff0031"}},
    "securityContext": {"asNumber": 6079, "asOrg": "example-isp", "isProxy": False},
    "request": {"ipChain": [{"ip": "203.0.113.42", "version": "V4"}]},
    "transaction": {"id": "7f03125c", "type": "WEB"},
    "authenticationContext": {"externalSessionId": "102VjjX9AggTUymcUJCfqTkvw"},
    "target": [
        {
            "id": "0oaBOT",
            "type": "OAuth2ClientSecretEntity",
            "displayName": "Reporting Bot",
            "alternateId": "unknown",
            "detailEntry": {"clientid": "0oaBOT", "clientsecret": SECRET, "status": "active"},
        }
    ],
}


def test_projection_keeps_only_the_fields_checks_read():
    event = ActivityEvent.from_okta(RAW_EVENT)

    assert event.published == datetime(2026, 9, 2, 14, 12, 3, 613000, tzinfo=timezone.utc)
    assert event.event_type == "app.oauth2.credentials.lifecycle.create"
    assert event.actor_id == "u02"
    assert event.actor_type == "User"
    assert event.outcome == "SUCCESS"
    assert event.targets == [{"id": "0oaBOT", "type": "OAuth2ClientSecretEntity", "label": "Reporting Bot"}]


def test_no_secret_or_tracking_data_survives_into_a_snapshot():
    """The load-bearing one: a snapshot is written to disk and shared as evidence."""
    snapshot = Snapshot(
        org_url="https://acme.okta.com",
        collected_at=datetime(2026, 9, 15, tzinfo=timezone.utc),
        users=[],
        groups=[],
        apps=[],
        events=[ActivityEvent.from_okta(RAW_EVENT)],
    )

    written = json.dumps(snapshot.to_dict())

    assert SECRET not in written
    for leaked in ("clientsecret", "detailEntry", "debugContext", "securityContext", "ipAddress",
                   "geographicalContext", "rawUserAgent", "externalSessionId", "203.0.113.42"):
        assert leaked not in written, f"{leaked} reached the snapshot"


def test_an_event_missing_optional_parts_still_projects():
    """Hand-built and older events lack whole sections; none of them are required."""
    event = ActivityEvent.from_okta({"eventType": "user.session.start", "published": "2026-09-02T14:12:03.613Z"})

    assert event.actor_id == ""
    assert event.outcome == ""
    assert event.targets == []
    assert event.published is not None


def test_events_and_tokens_round_trip_through_a_snapshot():
    snapshot = Snapshot(
        org_url="https://acme.okta.com",
        collected_at=datetime(2026, 9, 15, tzinfo=timezone.utc),
        users=[],
        groups=[],
        apps=[App(id="a05", label="Reporting Bot", status="ACTIVE", service_client=True, client_id="0oaBOT")],
        api_tokens=[ApiToken(id="t1", name="ci-deploy", user_id="u02",
                             created=datetime(2026, 1, 4, tzinfo=timezone.utc))],
        events=[ActivityEvent.from_okta(RAW_EVENT)],
        activity_since=datetime(2026, 6, 17, tzinfo=timezone.utc),
    )

    again = Snapshot.from_dict(json.loads(json.dumps(snapshot.to_dict())))

    assert again.to_dict() == snapshot.to_dict()
    assert again.apps[0].client_id == "0oaBOT"
    assert again.tokens_for("u02")[0].name == "ci-deploy"
    assert again.tokens_for("u09") == []
    assert again.activity_since == snapshot.activity_since


def test_a_snapshot_saved_before_activity_existed_still_loads():
    old = {
        "org_url": "https://acme.okta.com",
        "collected_at": "2026-09-15T00:00:00Z",
        "users": [], "groups": [], "apps": [],
    }

    snapshot = Snapshot.from_dict(old)

    assert snapshot.events == []
    assert snapshot.api_tokens == []
    assert snapshot.activity_since is None


def test_events_for_actor_filters_and_orders_oldest_first():
    def at(day):
        return ActivityEvent(published=datetime(2026, 9, day, tzinfo=timezone.utc),
                             event_type="user.session.start", actor_id="u02")

    snapshot = Snapshot(
        org_url="https://acme.okta.com",
        collected_at=datetime(2026, 9, 15, tzinfo=timezone.utc),
        users=[], groups=[], apps=[],
        events=[at(12), ActivityEvent(published=None, event_type="user.session.start", actor_id="u09"), at(2)],
    )

    days = [e.published.day for e in snapshot.events_for_actor("u02")]

    assert days == [2, 12]
