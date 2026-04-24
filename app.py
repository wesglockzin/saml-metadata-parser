#!/usr/bin/env python3
# -----------------------------------------------------------------------------
# Script Name : app.py (SAML Metadata Parser - Azure Container Apps Edition)
# Description : Flask web application for parsing and visualizing SAML 2.0
#               metadata. Includes Azure AD OIDC authentication gate.
# Author      : Wes Glockzin
# Version     : 2.0.0 (Azure Container Apps migration from Google Cloud Run)
# License     : MIT
# -----------------------------------------------------------------------------

import os
import io
import sys
import socket
import ipaddress
import hashlib
import base64
import time
import logging
import requests
from urllib.parse import urlparse, urlencode
from pathlib import Path
from datetime import datetime, timezone

from flask import Flask, render_template, request, send_file, redirect, url_for, session
from dotenv import load_dotenv
from werkzeug.middleware.proxy_fix import ProxyFix
from jose import jwt
from jose.exceptions import JWTError

from saml_ui_parser_logic import parse_file_bytes, sanitize_filename

# --- VERSION ---
APP_VERSION = "2.0.2"

# --- Environment Loading ---
APP_DIR = Path(__file__).resolve().parent
CONFIG_PATH = APP_DIR / "env.config.DO_NOT_SHARE"
if CONFIG_PATH.exists():
    load_dotenv(dotenv_path=CONFIG_PATH)
else:
    fallback = APP_DIR / "env.config"
    if fallback.exists():
        load_dotenv(dotenv_path=fallback)

# --- Required Secrets Check ---
REQUIRED_SECRETS = [
    "FLASK_SECRET_KEY",
    "AZURE_OIDC_CLIENT_ID",
    "AZURE_OIDC_CLIENT_SECRET",
    "AZURE_OIDC_TENANT_ID",
]
missing = [s for s in REQUIRED_SECRETS if not os.environ.get(s)]
if missing:
    print(f"FATAL ERROR: Missing required environment variables: {', '.join(missing)}")
    sys.exit(1)

# --- Logging ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

# --- Environment Detection ---
IS_AZURE = bool(os.environ.get("CONTAINER_APP_NAME") or os.environ.get("KUBERNETES_SERVICE_HOST"))

# --- Azure AD OIDC Config ---
AZURE_TENANT_ID = os.environ.get("AZURE_OIDC_TENANT_ID", "")
AZURE_CLIENT_ID = os.environ.get("AZURE_OIDC_CLIENT_ID", "")
AZURE_CLIENT_SECRET = os.environ.get("AZURE_OIDC_CLIENT_SECRET", "")
AZURE_ISSUER = f"https://login.microsoftonline.com/{AZURE_TENANT_ID}/v2.0"
AZURE_SCOPES = "openid email profile"
BASE_URL = os.environ.get("APP_BASE_URL", "https://localhost:8080").rstrip("/")
AZURE_REDIRECT_URI = f"{BASE_URL}/azure/oidc/callback"

HTTP_TIMEOUT = 10
VERIFY_SSL = True

# Module-level endpoint cache (re-discovered on each request for multi-worker safety)
_azure_endpoints = {}
_jwks_cache = {}


# ---------------------------------------------------------------------------
# Azure AD OIDC Helpers
# ---------------------------------------------------------------------------

def generate_pkce_pair():
    """Generate PKCE code_verifier and code_challenge (S256)."""
    code_verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("ascii")
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")
    return code_verifier, code_challenge


def get_jwks(jwks_uri):
    """Fetch JWKS with 1-hour in-memory cache."""
    cached = _jwks_cache.get(jwks_uri)
    if cached and time.time() - cached["ts"] < 3600:
        return cached["keys"]
    response = requests.get(jwks_uri, verify=VERIFY_SSL, timeout=HTTP_TIMEOUT)
    response.raise_for_status()
    keys = response.json()
    _jwks_cache[jwks_uri] = {"keys": keys, "ts": time.time()}
    return keys


def azure_discover_endpoints():
    """Discover Azure AD OIDC endpoints. Called fresh on each auth request for multi-worker safety."""
    discovery_url = f"https://login.microsoftonline.com/{AZURE_TENANT_ID}/v2.0/.well-known/openid-configuration"
    try:
        resp = requests.get(discovery_url, verify=VERIFY_SSL, timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
        config = resp.json()
        return {
            "auth": config.get("authorization_endpoint"),
            "token": config.get("token_endpoint"),
            "jwks": config.get("jwks_uri"),
        }
    except Exception as e:
        logger.error(f"Azure OIDC: Discovery failed: {e}")
        return None


def azure_start_login():
    """Build authorization URL and return (url, state, code_verifier, code_challenge)."""
    endpoints = azure_discover_endpoints()
    if not endpoints:
        return None, None, None, None
    state = os.urandom(16).hex()
    code_verifier, code_challenge = generate_pkce_pair()
    params = {
        "response_type": "code",
        "client_id": AZURE_CLIENT_ID,
        "redirect_uri": AZURE_REDIRECT_URI,
        "scope": AZURE_SCOPES,
        "state": state,
        "prompt": "select_account",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    auth_url = f"{endpoints['auth']}?{urlencode(params)}"
    return auth_url, state, code_verifier, code_challenge


def azure_exchange_code(code, code_verifier):
    """Exchange authorization code for tokens."""
    endpoints = azure_discover_endpoints()
    if not endpoints:
        return None
    payload = {
        "grant_type": "authorization_code",
        "client_id": AZURE_CLIENT_ID,
        "client_secret": AZURE_CLIENT_SECRET,
        "redirect_uri": AZURE_REDIRECT_URI,
        "code": code,
        "code_verifier": code_verifier,
    }
    try:
        resp = requests.post(
            endpoints["token"],
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            verify=VERIFY_SSL,
            timeout=HTTP_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        logger.error(f"Azure OIDC: Token exchange failed: {e}")
        return None


def azure_validate_id_token(id_token):
    """Validate Azure AD ID token and return claims dict or None."""
    endpoints = azure_discover_endpoints()
    if not endpoints:
        return None
    try:
        jwks = get_jwks(endpoints["jwks"])
        claims = jwt.decode(
            token=id_token,
            key=jwks,
            algorithms=["RS256"],
            audience=AZURE_CLIENT_ID,
            issuer=AZURE_ISSUER,
            options={"verify_at_hash": False},
        )
        return claims
    except (JWTError, Exception) as e:
        logger.error(f"Azure OIDC: ID token validation failed: {e}")
        return None


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
app.secret_key = os.environ["FLASK_SECRET_KEY"]
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Stateless signed cookie sessions — multi-instance safe
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_COOKIE_SAMESITE"] = "None"
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True

PUBLIC_PATHS = {"/login", "/azure/oidc/login", "/azure/oidc/callback", "/logout", "/favicon.ico"}


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
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "font-src 'self' https://cdn.jsdelivr.net; "
        "img-src 'self' data:; "
        "connect-src 'self';"
    )
    return response


# --- Auth Gate ---
@app.before_request
def require_login():
    if request.path.startswith("/static/"):
        return
    if request.path in PUBLIC_PATHS:
        return
    if not session.get("user"):
        return redirect(url_for("login", next=request.path))


# ---------------------------------------------------------------------------
# Auth Routes
# ---------------------------------------------------------------------------

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


@app.route("/azure/oidc/login")
def azure_oidc_login():
    auth_url, state, code_verifier, code_challenge = azure_start_login()
    if not auth_url:
        session["login_error"] = "Azure AD OIDC discovery failed. Check network access and configuration."
        return redirect(url_for("login"))
    session["azure_oauth_state"] = state
    session["azure_code_verifier"] = code_verifier
    session["azure_code_challenge"] = code_challenge
    return redirect(auth_url)


@app.route("/azure/oidc/callback")
def azure_oidc_callback():
    error = request.args.get("error")
    if error:
        desc = request.args.get("error_description", "")
        session["login_error"] = f"Azure AD login failed: {error} — {desc}"
        return redirect(url_for("login"))

    if request.args.get("state") != session.pop("azure_oauth_state", None):
        session["login_error"] = "Invalid state parameter. Please try again."
        return redirect(url_for("login"))

    code = request.args.get("code")
    if not code:
        session["login_error"] = "No authorization code received."
        return redirect(url_for("login"))

    tokens = azure_exchange_code(code, session.pop("azure_code_verifier", None))
    if not tokens or not tokens.get("id_token"):
        session["login_error"] = "Token exchange failed."
        return redirect(url_for("login"))

    claims = azure_validate_id_token(tokens["id_token"])
    if not claims:
        session["login_error"] = "ID token validation failed."
        return redirect(url_for("login"))

    email = claims.get("email") or claims.get("preferred_username")
    if not email:
        session["login_error"] = "Email claim missing from ID token."
        return redirect(url_for("login"))

    # All authenticated Azure AD tenant users are authorized
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
