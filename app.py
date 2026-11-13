#!/usr/bin/env python3
"""SAML Metadata Parser: a Flask web page for reading SAML 2.0 metadata."""

import io
import ipaddress
import logging
import os
import socket
import sys
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import requests
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from flask import Flask, redirect, render_template, request, send_file, session, url_for
from lxml import etree
from werkzeug.middleware.proxy_fix import ProxyFix

from howto import register_howto
from saml_ui_parser_logic import parse_file_bytes, sanitize_filename

APP_VERSION = "2.2.0"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

PUBLIC_PATHS = {"/health", "/login", "/oidc/login", "/oidc/callback", "/logout", "/favicon.ico"}
MAX_REDIRECTS = 5
OIDC_SCOPES = "openid email profile"


class ConfigError(RuntimeError):
    """A required setting is missing or invalid."""


def _flag(env, name, default):
    return env.get(name, default).strip().lower() in ("1", "true", "yes", "on")


def _number(env, name, default, kind):
    try:
        return kind(env.get(name, default))
    except ValueError as exc:
        raise ConfigError(f"{name} must be a number") from exc


def load_settings(env=None):
    """Read settings from environment variables; fail naming any missing one."""
    env = os.environ if env is None else env
    auth_mode = env.get("AUTH_MODE", "oidc").strip().lower()
    if auth_mode not in ("oidc", "none"):
        raise ConfigError("AUTH_MODE must be 'oidc' or 'none'")
    settings = {
        "auth_mode": auth_mode,
        "secret_key": env.get("FLASK_SECRET_KEY", ""),
        "oidc_issuer": env.get("OIDC_ISSUER", "").rstrip("/"),
        "oidc_client_id": env.get("OIDC_CLIENT_ID", ""),
        "oidc_client_secret": env.get("OIDC_CLIENT_SECRET", ""),
        "force_https": _flag(env, "FORCE_HTTPS", "false"),
        "verify_ssl": _flag(env, "VERIFY_SSL", "true"),
        "http_timeout": _number(env, "HTTP_TIMEOUT", "10", float),
        "max_bytes": _number(env, "MAX_CONTENT_BYTES", str(5 * 1024 * 1024), int),
    }
    if auth_mode == "oidc":
        for var, key in (
            ("FLASK_SECRET_KEY", "secret_key"),
            ("OIDC_ISSUER", "oidc_issuer"),
            ("OIDC_CLIENT_ID", "oidc_client_id"),
            ("OIDC_CLIENT_SECRET", "oidc_client_secret"),
        ):
            if not settings[key]:
                raise ConfigError(
                    f"{var} is required (or set AUTH_MODE=none to run without sign-in)"
                )
    elif not settings["secret_key"]:
        logger.warning("FLASK_SECRET_KEY unset: using a per-process key; run a single worker")
        settings["secret_key"] = os.urandom(32).hex()
    return settings


# ---------------------------------------------------------------------------
# URL safety
# ---------------------------------------------------------------------------


class UnsafeURLError(ValueError):
    """The URL (or a redirect hop) is not allowed to be fetched."""


def validate_safe_url(url):
    """Resolve the URL hostname and block non-http(s) and private/internal addresses."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise UnsafeURLError("Only http and https URLs are allowed.")
    hostname = parsed.hostname
    if not hostname:
        raise UnsafeURLError("Invalid URL format.")
    try:
        addr_info = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise UnsafeURLError(f"Could not resolve hostname: {hostname}") from exc
    for info in addr_info:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            raise UnsafeURLError(f"Blocked internal/private IP address: {ip}")


def safe_next(target):
    """Return target only if it is a same-site relative path, else None."""
    if not target or not target.startswith("/") or target.startswith(("//", "/\\")):
        return None
    parsed = urlparse(target)
    if parsed.scheme or parsed.netloc or "\\" in target or "\n" in target or "\r" in target:
        return None
    return target


def fetch_metadata(
    url, *, timeout, verify, max_bytes, validate=validate_safe_url, get=requests.get
):
    """Fetch url, re-validating every redirect hop and capping the body size."""
    for _ in range(MAX_REDIRECTS + 1):
        validate(url)
        resp = get(url, timeout=timeout, verify=verify, allow_redirects=False, stream=True)
        try:
            if resp.is_redirect and resp.headers.get("Location"):
                url = urljoin(url, resp.headers["Location"])
                continue
            resp.raise_for_status()
            body = b""
            for chunk in resp.iter_content(65536):
                body += chunk
                if len(body) > max_bytes:
                    raise UnsafeURLError("Metadata response is too large.")
            return body
        finally:
            resp.close()
    raise UnsafeURLError("Too many redirects.")


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def _result_entry(name, info):
    keys = (
        "entity_id",
        "role",
        "authn_requests_signed",
        "want_assertions_signed",
        "nameid_formats",
        "acs_endpoints",
        "single_sign_on",
        "certs_signing",
        "certs_encryption",
        "certs_signing_details",
        "certs_encryption_details",
    )
    return {"filename": name, **{k: info[k] for k in keys}}


def create_app(env=None, *, fetch=None):
    settings = load_settings(env)
    oidc_enabled = settings["auth_mode"] == "oidc"
    fetch = fetch or fetch_metadata

    app = Flask(__name__, template_folder=".", static_folder="static")
    app.secret_key = settings["secret_key"]
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
    app.config["MAX_CONTENT_LENGTH"] = settings["max_bytes"]
    app.config["SESSION_PERMANENT"] = False
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = settings["force_https"]
    app.config["SESSION_COOKIE_HTTPONLY"] = True

    oauth = OAuth(app)
    if oidc_enabled:
        oauth.register(
            name="oidc",
            client_id=settings["oidc_client_id"],
            client_secret=settings["oidc_client_secret"],
            server_metadata_url=f"{settings['oidc_issuer']}/.well-known/openid-configuration",
            client_kwargs={"scope": OIDC_SCOPES, "code_challenge_method": "S256"},
        )
    else:
        logger.warning("AUTH_MODE=none: sign-in is disabled and the app is open")

    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        if settings["force_https"]:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "font-src 'self' https://cdn.jsdelivr.net; "
            "img-src 'self' data:; "
            "connect-src 'self'"
        )
        return response

    @app.before_request
    def require_login():
        if not oidc_enabled:
            return None
        if request.path.startswith("/static/") or request.path in PUBLIC_PATHS:
            return None
        if not session.get("user"):
            return redirect(url_for("oidc_login", next=request.path))
        return None

    @app.route("/health")
    def health():
        return ({"status": "ok", "version": APP_VERSION}, 200)

    @app.route("/login")
    def login():
        if session.get("user"):
            return redirect(url_for("index"))
        next_url = safe_next(request.args.get("next"))
        if next_url:
            session["post_login_redirect"] = next_url
        return render_template(
            "login.html",
            app_version=APP_VERSION,
            login_error=session.pop("login_error", None),
        )

    @app.route("/oidc/login")
    def oidc_login():
        if not oidc_enabled:
            session["login_error"] = "Sign-in is not configured"
            return redirect(url_for("login"))
        next_url = safe_next(request.args.get("next"))
        if next_url:
            session["post_login_redirect"] = next_url
        return oauth.oidc.authorize_redirect(url_for("oidc_callback", _external=True))

    @app.route("/oidc/callback")
    def oidc_callback():
        if request.args.get("error"):
            logger.warning("OIDC provider returned error %r", request.args.get("error"))
            session["login_error"] = "Sign-in was denied or failed. Try again."
            return redirect(url_for("login"))
        try:
            token = oauth.oidc.authorize_access_token()
        except Exception:  # noqa: BLE001 - last-resort boundary for the login flow; logged below
            logger.exception("OIDC token exchange failed")
            session["login_error"] = "Sign-in failed. Try again."
            return redirect(url_for("login"))
        claims = token.get("userinfo") or {}
        email = claims.get("email") or claims.get("preferred_username")
        if not email:
            session["login_error"] = "No email claim was returned by the identity provider."
            return redirect(url_for("login"))
        session["user"] = {
            "email": email,
            "name": claims.get("name"),
            "login_time": datetime.now(timezone.utc).isoformat(),
        }
        return redirect(safe_next(session.pop("post_login_redirect", None)) or url_for("index"))

    @app.route("/favicon.ico")
    def favicon():
        return ("", 204)

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    register_howto(app, tool_name="SAML Metadata Parser")

    def render_index(results):
        user = session.get("user", {})
        return render_template(
            "index.html", results=results, app_version=APP_VERSION, user_email=user.get("email")
        )

    @app.route("/", methods=["GET"])
    def index():
        return render_index(session.get("results", []))

    def parse_one(name, loader):
        try:
            return _result_entry(name, parse_file_bytes(name, loader()))
        except requests.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else "unknown"
            body = exc.response.text[:500] if exc.response is not None else ""
            logger.warning("Fetch of %s failed with HTTP %s: %s", name, status, body)
            return {"filename": name, "error": f"HTTP error: the server answered {status}"}
        except requests.RequestException:
            logger.warning("Fetch of %s failed", name, exc_info=True)
            return {"filename": name, "error": "Could not reach the URL."}
        except UnsafeURLError as exc:
            return {"filename": name, "error": f"Security Block: {exc}"}
        except (etree.LxmlError, ValueError) as exc:
            logger.info("Metadata %s could not be parsed: %s", name, exc)
            return {"filename": name, "error": "Parse error: not valid SAML metadata."}

    @app.route("/parse", methods=["POST"])
    def parse():
        parsed = []
        url_input = request.form.get("metadata_url", "").strip()
        if url_input:
            parsed.append(
                parse_one(
                    url_input,
                    lambda: fetch(
                        url_input,
                        timeout=settings["http_timeout"],
                        verify=settings["verify_ssl"],
                        max_bytes=settings["max_bytes"],
                    ),
                )
            )
        raw_input = request.form.get("metadata_raw", "").strip()
        if raw_input:
            parsed.append(parse_one("pasted-xml", lambda: raw_input.encode("utf-8")))
        for f in request.files.getlist("metadata_files"):
            if f and f.filename:
                parsed.append(parse_one(f.filename, f.read))

        # Keep only PEM strings in the signed cookie, to stay under the size limit.
        session["results"] = [
            {
                "filename": r.get("filename"),
                "entity_id": r.get("entity_id"),
                "certs_signing": r.get("certs_signing", []),
                "certs_encryption": r.get("certs_encryption", []),
            }
            for r in parsed
            if not r.get("error")
        ]
        return render_index(parsed)

    @app.route("/download_cert", methods=["GET"])
    def download_cert():
        try:
            idx = int(request.args.get("file_index", "0"))
            cert_index = int(request.args.get("cert_index", "0"))
        except ValueError:
            return ("Bad request", 400)
        kind = request.args.get("kind", "signing")
        if kind not in ("signing", "encryption"):
            return ("Bad request", 400)
        results = session.get("results", [])
        if idx < 0 or idx >= len(results):
            return ("Not found", 404)
        entry = results[idx]
        certs = entry["certs_signing"] if kind == "signing" else entry["certs_encryption"]
        if cert_index < 0 or cert_index >= len(certs):
            return ("Not found", 404)
        base = sanitize_filename(entry.get("entity_id") or entry.get("filename") or "metadata")
        return send_file(
            io.BytesIO(certs[cert_index].encode("utf-8")),
            mimetype="application/x-pem-file",
            as_attachment=True,
            download_name=f"{base}.{kind}.{cert_index + 1}.pem",
        )

    return app


def main():
    load_dotenv()
    app = create_app()
    app.run(
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "8081")),
        debug=False,
        use_reloader=False,
    )


if __name__ == "__main__":
    main()
