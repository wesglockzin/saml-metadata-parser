import pytest
import requests

import app as app_module
from app import ConfigError, UnsafeURLError, create_app, fetch_metadata, safe_next
from tests.test_parser import idp_xml, make_cert_b64

OIDC_ENV = {
    "FLASK_SECRET_KEY": "test-key-not-real",
    "OIDC_ISSUER": "https://issuer.example.invalid",
    "OIDC_CLIENT_ID": "test-client",
    "OIDC_CLIENT_SECRET": "test-secret-not-real",
    "ALLOWED_EMAILS": "Alice@Example.invalid, bob@example.invalid",
    "ALLOWED_GROUPS": "metadata-users",
}


def _sign_in(monkeypatch, userinfo):
    monkeypatch.setattr(
        "authlib.integrations.flask_client.FlaskOAuth2App.authorize_access_token",
        lambda self: {"userinfo": userinfo},
    )
    client = create_app(OIDC_ENV).test_client()
    resp = client.get("/oidc/callback")
    return client, resp


def test_allowed_email_signs_in(monkeypatch):
    client, resp = _sign_in(
        monkeypatch, {"email": "alice@example.invalid", "email_verified": True}
    )
    assert resp.status_code == 302
    with client.session_transaction() as sess:
        assert sess["user"]["email"] == "alice@example.invalid"


def test_unverified_email_is_refused(monkeypatch):
    client, _ = _sign_in(
        monkeypatch, {"email": "alice@example.invalid", "email_verified": False}
    )
    with client.session_transaction() as sess:
        assert "user" not in sess


def test_missing_email_verified_is_refused(monkeypatch):
    client, _ = _sign_in(monkeypatch, {"email": "alice@example.invalid"})
    with client.session_transaction() as sess:
        assert "user" not in sess


def test_preferred_username_is_not_matched_to_email_list(monkeypatch):
    client, _ = _sign_in(
        monkeypatch,
        {"preferred_username": "alice@example.invalid", "email_verified": True},
    )
    with client.session_transaction() as sess:
        assert "user" not in sess


def test_allowed_group_signs_in(monkeypatch):
    client, _ = _sign_in(monkeypatch, {"email": "x@example.invalid", "groups": ["metadata-users"]})
    with client.session_transaction() as sess:
        assert "user" in sess


def test_string_groups_claim_on_list_signs_in(monkeypatch):
    client, _ = _sign_in(monkeypatch, {"email": "x@example.invalid", "groups": "metadata-users"})
    with client.session_transaction() as sess:
        assert "user" in sess


def test_non_list_groups_claim_is_refused_not_an_error(monkeypatch):
    client, resp = _sign_in(monkeypatch, {"email": "x@example.invalid", "groups": 5})
    assert resp.status_code == 302
    with client.session_transaction() as sess:
        assert "user" not in sess


def test_groups_scope_requested_only_with_group_allow_list():
    oauth = create_app(OIDC_ENV).extensions["authlib.integrations.flask_client"]
    assert "groups" in oauth.oidc.client_kwargs["scope"].split()
    env = {**OIDC_ENV}
    del env["ALLOWED_GROUPS"]
    oauth = create_app(env).extensions["authlib.integrations.flask_client"]
    assert oauth.oidc.client_kwargs["scope"] == "openid email profile"


def test_scopes_can_be_overridden():
    app = create_app({**OIDC_ENV, "OIDC_SCOPES": "openid email"})
    oauth = app.extensions["authlib.integrations.flask_client"]
    assert oauth.oidc.client_kwargs["scope"] == "openid email"


def test_string_groups_claim_not_on_list_is_refused(monkeypatch):
    client, _ = _sign_in(monkeypatch, {"email": "eve@example.invalid", "groups": "other"})
    with client.session_transaction() as sess:
        assert "user" not in sess


def test_user_not_on_allow_list_is_refused(monkeypatch):
    client, resp = _sign_in(monkeypatch, {"email": "eve@example.invalid", "groups": ["other"]})
    assert resp.headers["Location"].endswith("/login")
    with client.session_transaction() as sess:
        assert "user" not in sess


def test_oidc_mode_requires_an_allow_list():
    env = {k: v for k, v in OIDC_ENV.items() if not k.startswith("ALLOWED_")}
    with pytest.raises(ConfigError, match="ALLOWED_EMAILS"):
        create_app(env)


def test_main_binds_local_default_and_reads_port(monkeypatch):
    import flask

    seen = {}
    monkeypatch.setattr(flask.Flask, "run", lambda self, **kw: seen.update(kw))
    monkeypatch.setattr(app_module, "load_dotenv", lambda: None)
    monkeypatch.delenv("HOST", raising=False)
    monkeypatch.setenv("AUTH_MODE", "none")
    monkeypatch.setenv("PORT", "9123")
    app_module.main()
    assert seen["host"] == "127.0.0.1"
    assert seen["port"] == 9123


class FakeResponse:
    def __init__(self, status=200, body=b"", location=None):
        self.status_code = status
        self._body = body
        self.headers = {"Location": location} if location else {}
        self.is_redirect = location is not None

    def raise_for_status(self):
        if self.status_code >= 400:
            resp = requests.Response()
            resp.status_code = self.status_code
            # Like a streamed response that was never read: no content available.
            raise requests.HTTPError("failed", response=resp)

    def iter_content(self, size):
        yield self._body

    def close(self):
        pass


@pytest.fixture
def open_client():
    return create_app({"AUTH_MODE": "none"}).test_client()


# --- settings (CFG-3) ---


def test_missing_oidc_settings_fail_with_name():
    with pytest.raises(ConfigError, match="OIDC_ISSUER"):
        create_app({"FLASK_SECRET_KEY": "test-key-not-real"})


def test_missing_secret_key_fails_with_name():
    env = {k: v for k, v in OIDC_ENV.items() if k != "FLASK_SECRET_KEY"}
    with pytest.raises(ConfigError, match="FLASK_SECRET_KEY"):
        create_app(env)


def test_bad_auth_mode_rejected():
    with pytest.raises(ConfigError, match="AUTH_MODE"):
        create_app({"AUTH_MODE": "off"})


def test_oidc_mode_defaults_to_secure_cookies_and_hsts():
    resp = create_app(OIDC_ENV).test_client().get("/health")
    assert "Strict-Transport-Security" in resp.headers
    assert create_app(OIDC_ENV).config["SESSION_COOKIE_SECURE"] is True
    assert create_app({**OIDC_ENV, "FORCE_HTTPS": ""}).config["SESSION_COOKIE_SECURE"] is True


def test_oidc_mode_https_can_be_turned_off_explicitly():
    app = create_app({**OIDC_ENV, "FORCE_HTTPS": "false"})
    assert app.config["SESSION_COOKIE_SECURE"] is False


def test_none_mode_defaults_to_plain_http():
    assert create_app({"AUTH_MODE": "none"}).config["SESSION_COOKIE_SECURE"] is False


@pytest.mark.parametrize("name", ["HTTP_TIMEOUT", "MAX_CONTENT_BYTES"])
@pytest.mark.parametrize("value", ["0", "-1"])
def test_non_positive_setting_rejected(name, value):
    with pytest.raises(ConfigError, match=name):
        create_app({"AUTH_MODE": "none", name: value})


def test_overlong_hostname_label_is_unsafe_url_not_crash():
    with pytest.raises(UnsafeURLError):
        app_module.validate_safe_url("http://" + "a" * 70 + ".example.invalid/")


@pytest.mark.parametrize("name", ["HTTP_TIMEOUT", "MAX_CONTENT_BYTES"])
def test_non_numeric_setting_names_the_setting(name):
    with pytest.raises(ConfigError, match=name):
        create_app({"AUTH_MODE": "none", name: "abc"})


# --- auth gate, health, redirects ---


def test_health_is_open_and_needs_no_network():
    client = create_app(OIDC_ENV).test_client()
    assert client.get("/health").status_code == 200


def test_gate_redirects_anonymous_user():
    client = create_app(OIDC_ENV).test_client()
    resp = client.get("/")
    assert resp.status_code == 302
    assert "/oidc/login" in resp.headers["Location"]


@pytest.mark.parametrize(
    "target", ["//evil.example.invalid", "https://evil.example.invalid", "/\\evil", ""]
)
def test_unsafe_next_rejected(target):
    assert safe_next(target) is None


def test_relative_next_accepted():
    assert safe_next("/parse?x=1") == "/parse?x=1"


def test_login_does_not_store_open_redirect():
    client = create_app(OIDC_ENV).test_client()
    client.get("/login?next=//evil.example.invalid")
    with client.session_transaction() as sess:
        assert "post_login_redirect" not in sess


def test_csp_directives_are_separated(open_client):
    csp = open_client.get("/health").headers["Content-Security-Policy"]
    assert "https://cdn.jsdelivr.net; style-src" in csp
    assert "https://cdn.jsdelivr.net; font-src" in csp
    assert "https://cdn.jsdelivr.net; img-src" in csp


# --- fetch path ---


def test_fetch_rechecks_redirect_target():
    seen = []

    def validate(url):
        seen.append(url)
        if "internal" in url:
            raise UnsafeURLError("blocked")

    def get(url, **kwargs):
        return FakeResponse(302, location="http://internal.example.invalid/x")

    with pytest.raises(UnsafeURLError):
        fetch_metadata(
            "https://ok.example.invalid/m",
            timeout=1,
            verify=True,
            max_bytes=100,
            validate=validate,
            get=get,
        )
    assert seen == ["https://ok.example.invalid/m", "http://internal.example.invalid/x"]


def test_fetch_never_disables_tls_or_follows_redirects_itself():
    calls = []

    def get(url, **kwargs):
        calls.append(kwargs)
        return FakeResponse(200, b"<a/>")

    body = fetch_metadata(
        "https://ok.example.invalid/m",
        timeout=1,
        verify=True,
        max_bytes=100,
        validate=lambda u: None,
        get=get,
    )
    assert body == b"<a/>"
    assert calls[0]["verify"] is True
    assert calls[0]["allow_redirects"] is False


def test_fetch_size_cap():
    def get(url, **kwargs):
        return FakeResponse(200, b"x" * 50)

    with pytest.raises(UnsafeURLError, match="too large"):
        fetch_metadata(
            "https://ok.example.invalid/m",
            timeout=1,
            verify=True,
            max_bytes=10,
            validate=lambda u: None,
            get=get,
        )


def test_redirect_loop_stops():
    def get(url, **kwargs):
        return FakeResponse(302, location="https://ok.example.invalid/again")

    with pytest.raises(UnsafeURLError, match="redirects"):
        fetch_metadata(
            "https://ok.example.invalid/m",
            timeout=1,
            verify=True,
            max_bytes=10,
            validate=lambda u: None,
            get=get,
        )


def test_validate_blocks_loopback_and_bad_scheme():
    with pytest.raises(UnsafeURLError):
        app_module.validate_safe_url("http://127.0.0.1/")
    with pytest.raises(UnsafeURLError):
        app_module.validate_safe_url("file:///etc/passwd")


def test_http_error_is_reported_as_http_error():
    def fetch(url, **kwargs):
        return fetch_metadata(
            url, validate=lambda u: None, get=lambda u, **kw: FakeResponse(404, b"gone"), **kwargs
        )

    client = create_app({"AUTH_MODE": "none"}, fetch=fetch).test_client()
    resp = client.post("/parse", data={"metadata_url": "https://ok.example.invalid/m"})
    text = resp.get_data(as_text=True)
    assert "HTTP error: the server answered 404" in text
    assert "Could not reach" not in text


def test_http_error_body_is_logged(caplog):
    with caplog.at_level("WARNING"), pytest.raises(requests.HTTPError):
        fetch_metadata(
            "https://ok.example.invalid/m",
            timeout=1,
            verify=True,
            max_bytes=100,
            validate=lambda u: None,
            get=lambda u, **kw: FakeResponse(503, b"maintenance window"),
        )
    assert "503" in caplog.text
    assert "maintenance window" in caplog.text


def test_empty_number_setting_uses_default():
    settings = app_module.load_settings({"AUTH_MODE": "none", "HTTP_TIMEOUT": ""})
    assert settings["http_timeout"] == 10


@pytest.mark.parametrize("ip", ["100.64.0.1", "10.0.0.1", "169.254.169.254"])
def test_validate_blocks_non_global_addresses(ip):
    with pytest.raises(UnsafeURLError):
        app_module.validate_safe_url(f"http://{ip}/")


def test_compose_passes_every_documented_setting():
    import pathlib
    import re

    root = pathlib.Path(__file__).resolve().parent.parent
    names = re.findall(r"^([A-Z_]+)=", (root / ".env.example").read_text(), re.M)
    compose = (root / "docker-compose.yml").read_text()
    # HOST is for local runs only; the container always binds all interfaces.
    missing = [n for n in names if n != "HOST" and f"{n}:" not in compose]
    assert missing == []


def test_control_character_next_rejected():
    assert safe_next("/\t/evil.example.invalid") is None


def test_fetch_uses_verify_setting():
    seen = {}

    def fetch(url, **kwargs):
        seen.update(kwargs)
        return idp_xml(make_cert_b64())

    client = create_app({"AUTH_MODE": "none"}, fetch=fetch).test_client()
    client.post("/parse", data={"metadata_url": "https://ok.example.invalid/m"})
    assert seen["verify"] is True


# --- parse and download ---


def test_bad_xml_does_not_leak_exception_text(open_client):
    resp = open_client.post("/parse", data={"metadata_raw": "<not-xml"})
    text = resp.get_data(as_text=True)
    assert "Parse error: not valid SAML metadata." in text
    assert "line 1" not in text


def test_parse_then_download(open_client):
    open_client.post("/parse", data={"metadata_raw": idp_xml(make_cert_b64()).decode()})
    resp = open_client.get("/download_cert?file_index=0&kind=signing&cert_index=0")
    assert resp.status_code == 200
    assert resp.get_data(as_text=True).startswith("-----BEGIN CERTIFICATE-----")


@pytest.mark.parametrize(
    "query",
    ["file_index=abc", "cert_index=x", "kind=bogus"],
)
def test_bad_download_params_are_400_not_500(open_client, query):
    assert open_client.get(f"/download_cert?{query}").status_code == 400
