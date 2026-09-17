import base64
import hashlib

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from access_review.collect import collect
from access_review.okta import OktaClient, OktaError

ORG = "https://example.okta.com"


class FakeResponse:
    def __init__(self, body, status=200, next_url=None, headers=None):
        self._body = body
        self.status_code = status
        self.links = {"next": {"url": next_url}} if next_url else {}
        self.headers = headers or {}
        self.text = str(body)

    def json(self):
        return self._body


class FakeSession:
    """Serves GET responses by URL; records every request.

    With token_type="DPoP" it behaves like Okta: the first token request and
    the first API request are rejected with a nonce challenge."""

    def __init__(self, routes, token_type="DPoP"):
        self.routes = routes
        self.token_type = token_type
        self.posts = []
        self.gets = []
        self.post_headers = []
        self.get_headers = []

    def post(self, url, data, headers, timeout):
        self.posts.append((url, data))
        self.post_headers.append(headers)
        if self.token_type == "DPoP" and len(self.posts) == 1:
            return FakeResponse({"error": "use_dpop_nonce"}, status=400, headers={"DPoP-Nonce": "token-nonce"})
        return FakeResponse({"access_token": "tok", "token_type": self.token_type, "expires_in": 3600})

    def get(self, url, params, headers, timeout):
        self.gets.append((url, params))
        self.get_headers.append(headers)
        if self.token_type == "DPoP" and len(self.gets) == 1:
            return FakeResponse(
                {}, status=401,
                headers={"DPoP-Nonce": "api-nonce", "WWW-Authenticate": 'DPoP error="use_dpop_nonce"'},
            )
        key = url.removeprefix(ORG)
        if params and "search" in params:
            key += "?deprovisioned"
        route = self.routes.get(key, [])
        return route if isinstance(route, FakeResponse) else FakeResponse(route)


@pytest.fixture(scope="module")
def keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return pem.decode(), key.public_key()


def client(session, keypair):
    return OktaClient(
        ORG, "client123", "kid1", keypair[0], ["okta.users.read"],
        session=session, dpop=session.token_type == "DPoP",
    )


def verify_proof(proof):
    header = jwt.get_unverified_header(proof)
    assert header["typ"] == "dpop+jwt"
    key = jwt.PyJWK(header["jwk"]).key
    return header, jwt.decode(proof, key, algorithms=["ES256"])


def test_dpop_token_request_retries_with_nonce(keypair):
    session = FakeSession({"/api/v1/groups": []})
    client(session, keypair).access_token()
    assert len(session.posts) == 2
    _, first = verify_proof(session.post_headers[0]["DPoP"])
    _, second = verify_proof(session.post_headers[1]["DPoP"])
    assert first["htm"] == "POST" and first["htu"] == f"{ORG}/oauth2/v1/token"
    assert "nonce" not in first
    assert second["nonce"] == "token-nonce"
    # Each attempt uses a fresh client assertion (jti must not repeat).
    assert session.posts[0][1]["client_assertion"] != session.posts[1][1]["client_assertion"]


def test_dpop_api_request_binds_proof_to_token_and_url(keypair):
    session = FakeSession({"/api/v1/users": []})
    c = client(session, keypair)
    c.get_all("/api/v1/users", {"limit": 200})
    assert len(session.gets) == 2  # nonce challenge, then retry
    headers = session.get_headers[1]
    assert headers["Authorization"] == "DPoP tok"
    header, claims = verify_proof(headers["DPoP"])
    assert claims["htm"] == "GET"
    assert claims["htu"] == f"{ORG}/api/v1/users"
    assert claims["nonce"] == "api-nonce"
    assert claims["ath"] == base64.urlsafe_b64encode(hashlib.sha256(b"tok").digest()).rstrip(b"=").decode()
    # Token and API proofs are signed by the same per-run key.
    token_header, _ = verify_proof(session.post_headers[-1]["DPoP"])
    assert header["jwk"] == token_header["jwk"]
    assert "d" not in header["jwk"]  # public key only


def test_dpop_client_rejects_unbound_token(keypair):
    session = FakeSession({}, token_type="Bearer")
    c = OktaClient(ORG, "client123", "kid1", keypair[0], ["okta.users.read"], session=session, dpop=True)
    with pytest.raises(OktaError, match="DPoP"):
        c.access_token()


def test_bearer_mode_sends_no_dpop_header(keypair):
    session = FakeSession({"/api/v1/groups": []}, token_type="Bearer")
    client(session, keypair).get_all("/api/v1/groups")
    assert "DPoP" not in session.post_headers[0]
    assert session.get_headers[0]["Authorization"] == "Bearer tok"
    assert "DPoP" not in session.get_headers[0]


def test_client_assertion_is_signed_for_the_token_endpoint(keypair):
    c = client(FakeSession({}), keypair)
    token = c.client_assertion()
    assert jwt.get_unverified_header(token)["kid"] == "kid1"
    claims = jwt.decode(token, keypair[1], algorithms=["RS256"], audience=f"{ORG}/oauth2/v1/token")
    assert claims["iss"] == claims["sub"] == "client123"


def test_token_is_cached(keypair):
    session = FakeSession({"/api/v1/groups": []}, token_type="Bearer")
    c = client(session, keypair)
    c.get_all("/api/v1/groups")
    c.get_all("/api/v1/groups")
    assert len(session.posts) == 1
    assert session.posts[0][1]["scope"] == "okta.users.read"


def test_follows_next_links(keypair):
    session = FakeSession({
        "/api/v1/users": FakeResponse([{"n": 1}], next_url=f"{ORG}/api/v1/users/page2"),
        "/api/v1/users/page2": [{"n": 2}],
    }, token_type="Bearer")
    assert client(session, keypair).get_all("/api/v1/users", {"limit": 200}) == [{"n": 1}, {"n": 2}]
    assert session.gets[1][1] is None  # query not re-sent on next link


def test_raises_okta_error_with_summary(keypair):
    session = FakeSession({"/api/v1/users": FakeResponse({"errorSummary": "nope"}, status=403)})
    with pytest.raises(OktaError, match="403.*nope"):
        client(session, keypair).get_all("/api/v1/users")


def _user(uid, status, **profile):
    return {"id": uid, "status": status, "created": "2026-01-01T00:00:00.000Z", "lastLogin": None,
            "profile": {"login": f"{uid}@x.test", "email": f"{uid}@x.test", **profile}}


def test_collect_normalizes_okta_responses(keypair):
    session = FakeSession({
        "/api/v1/users": [_user("u1", "ACTIVE"), _user("u2", "STAGED")],
        "/api/v1/users?deprovisioned": [_user("u3", "DEPROVISIONED")],
        "/api/v1/users/u1/factors": [
            {"factorType": "push", "status": "ACTIVE"},
            {"factorType": "sms", "status": "PENDING_ACTIVATION"},
        ],
        "/api/v1/users/u1/roles": [{"type": "SUPER_ADMIN", "label": "Super Administrator"}],
        "/api/v1/groups": [{"id": "g1", "type": "OKTA_GROUP", "profile": {"name": "Eng"}}],
        "/api/v1/groups/g1/users": [{"id": "u1"}, {"id": "u3"}],
        "/api/v1/apps": [{
            "id": "a1", "label": "Svc", "status": "ACTIVE", "signOnMode": "OPENID_CONNECT",
            "credentials": {"oauthClient": {"client_id": "a1"}},
            "settings": {"oauthClient": {"grant_types": ["client_credentials"]}},
        }],
        "/oauth2/v1/clients/a1/roles": [{"type": "CUSTOM", "label": "Okta MCP Role"}],
        "/api/v1/apps/a1/users": [{"id": "u1", "scope": "USER"}, {"id": "u3", "scope": "GROUP"}],
        "/api/v1/apps/a1/groups": [{"id": "g1"}],
        "/api/v1/apps/a1/grants": [
            {"scopeId": "okta.users.manage", "status": "ACTIVE"},
            {"scopeId": "okta.logs.read", "status": "REVOKED"},
        ],
    })
    snap = collect(client(session, keypair))
    users = {u.id: u for u in snap.users}
    assert set(users) == {"u1", "u2", "u3"}
    assert users["u1"].factors == ["push"]
    assert users["u2"].factors is None  # factors only fetched for users who can sign in
    assert snap.groups[0].members == {"u1", "u3"}
    assert snap.apps[0].users == {"u1"}
    assert snap.apps[0].granted_scopes == ["okta.users.manage"]
    assert users["u1"].admin_roles == ["Super Administrator"]
    assert users["u2"].admin_roles == []
    assert users["u3"].admin_roles is None  # not looked up for deprovisioned users
    assert snap.apps[0].admin_roles == ["Okta MCP Role"]
    assert snap.apps[0].service_client is True
    # Read-only: the only non-GET request is the token request.
    assert all(url.endswith("/oauth2/v1/token") for url, _ in session.posts)


def test_collect_marks_mfa_unknown_when_factors_forbidden(keypair):
    session = FakeSession({
        "/api/v1/users": [_user("u1", "ACTIVE"), _user("u2", "ACTIVE")],
        "/api/v1/users/u1/factors": FakeResponse({"errorSummary": "forbidden"}, status=403),
    })
    snap = collect(client(session, keypair))
    assert [u.factors for u in snap.users] == [None, None]
    # Stops asking after the first 403 instead of hitting it for every user.
    assert not any(url.endswith("/u2/factors") for url, _ in session.gets)


def test_collect_marks_roles_unknown_and_skips_grants_when_forbidden(keypair, capsys):
    forbidden = FakeResponse({}, status=403, headers={"WWW-Authenticate": 'error="insufficient_scope"'})
    session = FakeSession({
        "/api/v1/users": [_user("u1", "ACTIVE")],
        "/api/v1/users/u1/roles": forbidden,
        "/api/v1/apps": [{"id": "a1", "label": "A"}, {"id": "a2", "label": "B"}],
        "/api/v1/apps/a1/grants": forbidden,
    })
    snap = collect(client(session, keypair))
    assert snap.users[0].admin_roles is None
    assert [a.granted_scopes for a in snap.apps] == [[], []]
    assert not any(url.endswith("/a2/grants") for url, _ in session.gets)
    err = capsys.readouterr().err
    assert "okta.roles.read" in err and "okta.appGrants.read" in err and "insufficient_scope" in err
    assert len(snap.gaps) == 3
    assert "AR-10 and AR-11" in snap.gaps[0]
    assert "hiding apps" in snap.gaps[2]


def test_no_gap_when_review_app_is_visible(keypair):
    session = FakeSession({"/api/v1/apps": [{"id": "client123", "label": "Access Review"}]})
    assert collect(client(session, keypair)).gaps == []
