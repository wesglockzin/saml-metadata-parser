#!/usr/bin/env python3
import os
import io
import socket
import ipaddress
import requests
from urllib.parse import urlparse
from pathlib import Path
from flask import Flask, render_template, request, send_file, redirect, url_for, session
from flask_session import Session
from dotenv import load_dotenv
from saml_ui_parser_logic import parse_file_bytes, sanitize_filename

# --- VERSION SET BASED ON PROJECT TIMELINE ---
APP_VERSION = "1.2.2"  # Bumped for SSRF Security Update

APP_DIR = Path(__file__).resolve().parent
CONFIG_PATH = APP_DIR / "env.config"
load_dotenv(dotenv_path=CONFIG_PATH)

app = Flask(__name__, template_folder=".", static_folder="static")
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(32))
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.jinja_env.auto_reload = True
Session(app)

# Turnstile Config
TURNSTILE_SITE_KEY = os.environ.get("TURNSTILE_SITE_KEY")
TURNSTILE_SECRET_KEY = os.environ.get("TURNSTILE_SECRET_KEY")
TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

# --- SSRF SECURITY CHECK ---
def validate_safe_url(url):
    """
    Resolves URL to IP and ensures it is not a private/internal address.
    Raises ValueError if unsafe.
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            raise ValueError("Invalid URL format.")
        
        # Resolve hostname to IP
        # We fetch the address info (family, type, proto, canonname, sockaddr)
        # sockaddr is usually (ip, port)
        addr_info = socket.getaddrinfo(hostname, None)
        
        for info in addr_info:
            ip_addr_str = info[4][0]
            ip = ipaddress.ip_address(ip_addr_str)
            
            # Check for Private, Loopback, Link-Local, or Reserved ranges
            if (ip.is_private or 
                ip.is_loopback or 
                ip.is_link_local or 
                ip.is_reserved or 
                str(ip).startswith("169.254")):  # Explicit check for Cloud Metadata
                raise ValueError(f"Blocked internal/private IP address: {ip_addr_str}")
                
    except socket.gaierror:
        raise ValueError(f"Could not resolve hostname: {hostname}")
    except Exception as e:
        # If we can't verify it, we block it to be safe
        raise ValueError(f"Security validation failed: {str(e)}")

@app.route("/", methods=["GET"])
def index():
    results = session.get("results", [])
    # Pass site key to template for the widget
    return render_template("index.html", 
                           results=results, 
                           app_version=APP_VERSION, 
                           turnstile_site_key=TURNSTILE_SITE_KEY)

@app.route("/parse", methods=["POST"])
def parse():
    session["results"] = []
    
    # --- 0. TURNSTILE CHECK ---
    # Only run check if keys are configured
    if TURNSTILE_SECRET_KEY:
        turnstile_response = request.form.get("cf-turnstile-response")
        if not turnstile_response:
            session["results"] = [{"filename": "Security Check", "error": "Please complete the security check (CAPTCHA)."}]
            return redirect(url_for("index"))
            
        # Verify with Cloudflare
        try:
            verify_payload = {
                "secret": TURNSTILE_SECRET_KEY,
                "response": turnstile_response,
                "remoteip": request.remote_addr
            }
            verify_req = requests.post(TURNSTILE_VERIFY_URL, data=verify_payload, timeout=5)
            outcome = verify_req.json()
            
            if not outcome.get("success"):
                session["results"] = [{"filename": "Security Check", "error": "Security check failed. Please try again."}]
                return redirect(url_for("index"))
        except Exception as e:
            session["results"] = [{"filename": "Security Check", "error": f"Security check error: {str(e)}"}]
            return redirect(url_for("index"))

    parsed = []

    # --- 1. HANDLE URL INPUT ---
    url_input = request.form.get("metadata_url")
    if url_input and url_input.strip():
        try:
            # A. VALIDATE URL (SSRF PROTECTION)
            validate_safe_url(url_input)
            
            # B. FETCH IF SAFE
            # Verify=False allows internal/self-signed certs; Timeout prevents hanging
            response = requests.get(url_input, timeout=10, verify=False)
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
                "certs_encryption_details": info["certs_encryption_details"]
            })
        except ValueError as ve:
            # Catch our custom security error specifically
            parsed.append({
                "filename": url_input,
                "error": f"Security Block: {str(ve)}"
            })
        except Exception as e:
            parsed.append({
                "filename": url_input,
                "error": f"URL Error: {str(e)}"
            })

    # --- 2. HANDLE FILE UPLOADS ---
    files = request.files.getlist("metadata_files")
    for f in files:
        if not f or not f.filename:
            continue
        data = f.read()
        try:
            info = parse_file_bytes(f.filename, data)
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
                "certs_encryption_details": info["certs_encryption_details"]
            })
        except Exception as e:
            parsed.append({
                "filename": f.filename,
                "error": str(e)
            })
            
    session["results"] = parsed
    return redirect(url_for("index"))

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
    fname = f"{base}.{kind}.{cert_index+1}.pem"
    return send_file(io.BytesIO(pem.encode("utf-8")), mimetype="application/x-pem-file", as_attachment=True, download_name=fname)

if __name__ == "__main__":
    app.run(port=8081, debug=False, use_reloader=False)