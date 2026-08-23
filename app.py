#!/usr/bin/env python3
# -----------------------------------------------------------------------------
# Script Name : app.py (SAML Metadata Parser - Azure Container Apps Edition)
# Description : Flask web application for parsing and visualizing SAML 2.0
#               metadata. PROD Okta OIDC authentication gate via the shared
#               "Admin SSO App" OIDC app, Authlib-driven flow.
# Author      : Wes Glockzin
# Version     : 2.1.0 (Entra → PROD Okta OIDC migration via Admin SSO App)
# License     : MIT
# -----------------------------------------------------------------------------

import os
import io
import sys
import socket
import ipaddress
import logging
import requests
from urllib.parse import urlparse
from pathlib import Path
from datetime import datetime, timezone

from authlib.integrations.flask_client import OAuth
from flask import Flask, render_template, request, send_file, redirect, url_for, session
from dotenv import load_dotenv
from werkzeug.middleware.proxy_fix import ProxyFix

from saml_ui_parser_logic import parse_file_bytes, sanitize_filename
from wes_tools_docs import register_howto

# --- VERSION ---
APP_VERSION = "2.1.5"

# --- Environment Loading ---
APP_DIR = Path(__file__).resolve().parent
CONFIG_PATH = APP_DIR / "env.config.DO_NOT_SHARE"
if CONFIG_PATH.exists():
    load_dotenv(dotenv_path=CONFIG_PATH)
else:
    fallback = APP_DIR / "env.config"
    if fallback.exists():
        load_dotenv(dotenv_path=fallback)

# --- Logging ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

# --- Environment Detection ---
IS_AZURE = bool(os.environ.get("CONTAINER_APP_NAME") or os.environ.get("KUBERNETES_SERVICE_HOST"))

# --- OIDC Config (PROD Okta via "Admin SSO App" app) ---
FLASK_SECRET_KEY = os.environ.get("FLASK_SECRET_KEY") or os.urandom(32).hex()
OIDC_ISSUER = os.environ.get("OIDC_ISSUER", "").rstrip("/")
OIDC_CLIENT_ID = os.environ.get("OIDC_CLIENT_ID", "")
OIDC_CLIENT_SECRET = os.environ.get("OIDC_CLIENT_SECRET", "")
APP_BASE_URL = os.environ.get("APP_BASE_URL", "https://localhost:8080").rstrip("/")
OIDC_SCOPES = "openid email profile"
OIDC_ENABLED = bool(OIDC_ISSUER and OIDC_CLIENT_ID and OIDC_CLIENT_SECRET)

if not OIDC_ENABLED:
    logger.warning(
        "OIDC is NOT configured — auth gate disabled, app is open. "
        "Set OIDC_ISSUER / OIDC_CLIENT_ID / OIDC_CLIENT_SECRET to enable."
    )

HTTP_TIMEOUT = 10
VERIFY_SSL = True


# ---------------------------------------------------------------------------
# SSRF Protection
# ---------------------------------------------------------------------------

def validate_safe_url(url):
    """Resolve URL hostname and block private/internal IP addresses."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            raise ValueError("Invalid URL format.")
        addr_info = socket.getaddrinfo(hostname, None)
        for info in addr_info:
            ip_addr_str = info[4][0]
            ip = ipaddress.ip_address(ip_addr_str)
            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_reserved
                or str(ip).startswith("169.254")
            ):
                raise ValueError(f"Blocked internal/private IP address: {ip_addr_str}")
    except socket.gaierror:
        raise ValueError(f"Could not resolve hostname: {hostname}")
    except ValueError:
        raise
    except Exception as e:
        raise ValueError(f"Security validation failed: {str(e)}")


# ---------------------------------------------------------------------------
# Flask App
# ---------------------------------------------------------------------------

app = Flask(__name__, template_folder=".", static_folder="static")
app.secret_key = FLASK_SECRET_KEY
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Stateless signed cookie sessions — multi-instance safe
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = APP_BASE_URL.startswith("https://")
app.config["SESSION_COOKIE_HTTPONLY"] = True

oauth = OAuth(app)
if OIDC_ENABLED:
    oauth.register(
        name="okta",
        client_id=OIDC_CLIENT_ID,
        client_secret=OIDC_CLIENT_SECRET,
        server_metadata_url=f"{OIDC_ISSUER}/.well-known/openid-configuration",
        client_kwargs={"scope": OIDC_SCOPES, "code_challenge_method": "S256"},
    )

PUBLIC_PATHS = {"/health", "/login", "/oidc/login", "/oidc/callback", "/logout", "/favicon.ico"}


# --- Security Headers ---
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    if IS_AZURE:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net "
        "font-src 'self' https://cdn.jsdelivr.net "
        "img-src 'self' data:; "
        "connect-src 'self';"
    )
    return response


# --- Auth Gate ---
@app.before_request
def require_login():
    if not OIDC_ENABLED:
        return
    if request.path.startswith("/static/"):
        return
    if request.path in PUBLIC_PATHS:
        return
    if not session.get("user"):
        # Straight to the IdP — no intermediate "Sign in with Okta" landing page
        # (fleet-uniform direct redirect). /login kept for logout landing and
        # auth-error display only.
        return redirect(url_for("oidc_login", next=request.path))


# ---------------------------------------------------------------------------
# Auth Routes (Authlib + PROD Okta via "Admin SSO App" app)
# ---------------------------------------------------------------------------

@app.route("/health")
def health():
    return ({"status": "ok", "version": APP_VERSION}, 200)


@app.route("/login")
def login():
    if session.get("user"):
        return redirect(url_for("index"))
    next_url = request.args.get("next")
    if next_url:
        session["post_login_redirect"] = next_url
    return render_template(
        "login.html",
        app_version=APP_VERSION,
        login_error=session.pop("login_error", None),
    )


@app.route("/oidc/login")
def oidc_login():
    if not OIDC_ENABLED:
        session["login_error"] = "OIDC not configured"
        return redirect(url_for("login"))
    next_url = request.args.get("next")
    if next_url:
        session["post_login_redirect"] = next_url
    redirect_uri = url_for("oidc_callback", _external=True)
    return oauth.okta.authorize_redirect(redirect_uri)


@app.route("/oidc/callback")
def oidc_callback():
    if request.args.get("error"):
        session["login_error"] = f"{request.args.get('error')}: {request.args.get('error_description', '')}"
        return redirect(url_for("login"))
    try:
        token = oauth.okta.authorize_access_token()
    except Exception as e:
        logger.exception("OIDC token exchange failed")
        session["login_error"] = f"token exchange failed: {e}"
        return redirect(url_for("login"))

    claims = token.get("userinfo") or {}
    email = claims.get("email") or claims.get("preferred_username")
    if not email:
        session["login_error"] = "email claim missing from id_token"
        return redirect(url_for("login"))

    session["user"] = {
        "email": email,
        "name": claims.get("name"),
        "login_time": datetime.now(timezone.utc).isoformat(),
    }
    redirect_to = session.pop("post_login_redirect", None) or url_for("index")
    return redirect(redirect_to)


@app.route("/favicon.ico")
def favicon():
    return ("", 204)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Application Routes
# ---------------------------------------------------------------------------

# In-tool documentation (/howto), rendered from HOWTO.md via the shared module.
register_howto(app, tool_name="SAML Metadata Parser")


@app.route("/", methods=["GET"])
def index():
    results = session.get("results", [])
    user = session.get("user", {})
    return render_template(
        "index.html",
        results=results,
        app_version=APP_VERSION,
        user_email=user.get("email"),
    )


@app.route("/parse", methods=["POST"])
def parse():
    parsed = []

    # --- Handle URL input ---
    url_input = request.form.get("metadata_url", "").strip()
    if url_input:
        try:
            validate_safe_url(url_input)
            response = requests.get(url_input, timeout=HTTP_TIMEOUT, verify=False)
            response.raise_for_status()
            info = parse_file_bytes(url_input, response.content)
            parsed.append({
                "filename": url_input,
                "entity_id": info["entity_id"],
                "role": info["role"],
                "authn_requests_signed": info["authn_requests_signed"],
                "want_assertions_signed": info["want_assertions_signed"],
                "nameid_formats": info["nameid_formats"],
                "acs_endpoints": info["acs_endpoints"],
                "single_sign_on": info["single_sign_on"],
                "certs_signing": info["certs_signing"],
                "certs_encryption": info["certs_encryption"],
                "certs_signing_details": info["certs_signing_details"],
                "certs_encryption_details": info["certs_encryption_details"],
            })
        except ValueError as ve:
            parsed.append({"filename": url_input, "error": f"Security Block: {ve}"})
        except Exception as e:
            parsed.append({"filename": url_input, "error": f"URL Error: {e}"})

    # --- Handle raw XML paste ---
    raw_input = request.form.get("metadata_raw", "").strip()
    if raw_input:
        try:
            info = parse_file_bytes("pasted-xml", raw_input.encode("utf-8"))
            parsed.append({
                "filename": "pasted-xml",
                "entity_id": info["entity_id"],
                "role": info["role"],
                "authn_requests_signed": info["authn_requests_signed"],
                "want_assertions_signed": info["want_assertions_signed"],
                "nameid_formats": info["nameid_formats"],
                "acs_endpoints": info["acs_endpoints"],
                "single_sign_on": info["single_sign_on"],
                "certs_signing": info["certs_signing"],
                "certs_encryption": info["certs_encryption"],
                "certs_signing_details": info["certs_signing_details"],
                "certs_encryption_details": info["certs_encryption_details"],
            })
        except Exception as e:
            parsed.append({"filename": "pasted-xml", "error": f"Parse error: {e}"})

    # --- Handle file uploads ---
    for f in request.files.getlist("metadata_files"):
        if not f or not f.filename:
            continue
        try:
            info = parse_file_bytes(f.filename, f.read())
            parsed.append({
                "filename": f.filename,
                "entity_id": info["entity_id"],
                "role": info["role"],
                "authn_requests_signed": info["authn_requests_signed"],
                "want_assertions_signed": info["want_assertions_signed"],
                "nameid_formats": info["nameid_formats"],
                "acs_endpoints": info["acs_endpoints"],
                "single_sign_on": info["single_sign_on"],
                "certs_signing": info["certs_signing"],
                "certs_encryption": info["certs_encryption"],
                "certs_signing_details": info["certs_signing_details"],
                "certs_encryption_details": info["certs_encryption_details"],
            })
        except Exception as e:
            parsed.append({"filename": f.filename, "error": str(e)})

    # Store only PEM strings in session for /download_cert (avoids cookie size limit
    # caused by storing full cert details + hex data in signed cookie sessions).
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

    user = session.get("user", {})
    return render_template(
        "index.html",
        results=parsed,
        app_version=APP_VERSION,
        user_email=user.get("email"),
    )


@app.route("/download_cert", methods=["GET"])
def download_cert():
    idx = int(request.args.get("file_index", "0"))
    kind = request.args.get("kind", "signing")
    cert_index = int(request.args.get("cert_index", "0"))
    results = session.get("results", [])
    if idx < 0 or idx >= len(results):
        return ("Not found", 404)
    entry = results[idx]
    certs = entry["certs_signing"] if kind == "signing" else entry["certs_encryption"]
    if cert_index < 0 or cert_index >= len(certs):
        return ("Not found", 404)
    pem = certs[cert_index]
    base = sanitize_filename(entry.get("entity_id") or entry.get("filename") or "metadata")
    fname = f"{base}.{kind}.{cert_index + 1}.pem"
    return send_file(
        io.BytesIO(pem.encode("utf-8")),
        mimetype="application/x-pem-file",
        as_attachment=True,
        download_name=fname,
    )


if __name__ == "__main__":
    app.run(port=8081, debug=False, use_reloader=False)
