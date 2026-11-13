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
}


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
            resp._content = self._body
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
