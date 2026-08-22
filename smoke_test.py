#!/usr/bin/env python3
"""
smoke_test.py — Pre-deployment validation for SAML Metadata Parser (Azure Container Apps)
Run before every deploy: python3 smoke_test.py
"""

import sys
import os

PASS = 0
FAIL = 0

def ok(msg):
    global PASS
    print(f"  PASS  {msg}")
    PASS += 1

def fail(msg):
    global FAIL
    print(f"  FAIL  {msg}")
    FAIL += 1

def section(title):
    print(f"\n--- {title} ---")


# ---------------------------------------------------------------------------
# 1. Python syntax and core imports
# ---------------------------------------------------------------------------
section("Python Imports")

try:
    import flask
    ok(f"flask {flask.__version__}")
except ImportError as e:
    fail(f"flask: {e}")

try:
    import lxml
    ok(f"lxml {lxml.__version__}")
except ImportError as e:
    fail(f"lxml: {e}")

try:
    import cryptography
    ok(f"cryptography {cryptography.__version__}")
except ImportError as e:
    fail(f"cryptography: {e}")

try:
    import requests
    ok(f"requests {requests.__version__}")
except ImportError as e:
    fail(f"requests: {e}")

try:
    import authlib
    ok(f"authlib {authlib.__version__}")
except ImportError as e:
    fail(f"authlib: {e}")

try:
    from werkzeug.middleware.proxy_fix import ProxyFix
    ok("werkzeug ProxyFix")
except ImportError as e:
    fail(f"werkzeug ProxyFix: {e}")

try:
    import dotenv
    ok("python-dotenv")
except ImportError as e:
    fail(f"python-dotenv: {e}")


# ---------------------------------------------------------------------------
# 2. Application modules
# ---------------------------------------------------------------------------
section("Application Modules")

try:
    import saml_ui_parser_logic
    ok("saml_ui_parser_logic imported")
except Exception as e:
    fail(f"saml_ui_parser_logic: {e}")

try:
    # Dummy FLASK_SECRET_KEY for the import test. OIDC_* deliberately left
    # unset so OIDC_ENABLED=False during smoke; app.py logs a warning and
    # runs in open posture (no sys.exit).
    os.environ.setdefault("FLASK_SECRET_KEY", "smoke-test-dummy")
    import app as flask_app
    ok("app.py imported")
except SystemExit:
    fail("app.py exited during import")
except Exception as e:
    fail(f"app.py: {e}")


# ---------------------------------------------------------------------------
# 3. Flask app instantiation
# ---------------------------------------------------------------------------
section("Flask App")

try:
    assert flask_app.app is not None
    ok("Flask app object exists")
except Exception as e:
    fail(f"Flask app: {e}")

try:
    assert flask_app.APP_VERSION, "APP_VERSION is empty"
    ok(f"APP_VERSION = {flask_app.APP_VERSION}")
except Exception as e:
    fail(f"APP_VERSION: {e}")

try:
    routes = [rule.rule for rule in flask_app.app.url_map.iter_rules()]
    required_routes = ["/", "/parse", "/download_cert", "/login", "/oidc/login", "/oidc/callback", "/logout", "/health"]
    for route in required_routes:
        if route in routes:
            ok(f"Route exists: {route}")
        else:
            fail(f"Route missing: {route}")
except Exception as e:
    fail(f"Route check: {e}")


# ---------------------------------------------------------------------------
# 4. Documentation files
# ---------------------------------------------------------------------------
section("Documentation Files")

required_docs = ["AGENTS.md", "SESSION_NOTES.md", "requirements.txt", "Dockerfile", "deploy.sh"]
for doc in required_docs:
    if os.path.exists(doc):
        ok(f"{doc} exists")
    else:
        fail(f"{doc} missing")


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print(f"\n{'='*45}")
print(f"  Results: {PASS} passed, {FAIL} failed")
print(f"{'='*45}")

if FAIL > 0:
    print("\nFix failures before deploying.\n")
    sys.exit(1)
else:
    print("\nAll checks passed. Safe to deploy.\n")
    sys.exit(0)
