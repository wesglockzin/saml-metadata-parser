# SAML Metadata Parser

**v2.0.2** | [Live Demo](https://saml-metadata-parser-914689630982.us-central1.run.app/)

---

## The Problem

SAML metadata XML is not human-readable. When integrating a new SP or IdP, validating certificate fingerprints, checking endpoint URLs, or debugging a federation trust, you're staring at raw XML and doing mental base64 decoding. There's no quick web tool that does this cleanly, securely, and without uploading your metadata to an untrusted third party.

---

## What It Does

Upload SAML 2.0 metadata (XML file or remote URL) and get:

- EntityID extraction
- SSO and SLO endpoint URLs and bindings
- X.509 certificate decoding — subject, issuer, validity dates, key algorithm
- SHA-1 and SHA-256 fingerprint calculation
- Certificate expiry status (valid / expiring soon / expired)
- Downloadable PEM format

Supports both SP and IdP metadata. Works with metadata from Okta, ADFS, Azure AD, Shibboleth, and any SAML 2.0-compliant IdP or SP.

---

## Live Demo

**[https://saml-metadata-parser-914689630982.us-central1.run.app/](https://saml-metadata-parser-914689630982.us-central1.run.app/)**

---

## Why It's Built This Way

- **SSRF mitigation**: Remote URL fetching blocks requests to internal/private IP ranges — this runs in a shared cloud environment
- **Cloudflare Turnstile**: Bot protection on all parse requests
- **No data retention**: Metadata is parsed in-memory and never stored
- **Signed cookie sessions**: Multi-instance safe, no filesystem dependencies
- **Security headers**: HSTS, CSP, X-Frame-Options, Content-Type, XSS protection

---

## Tech Stack

- Python 3.11 / Flask / Gunicorn
- lxml for XML parsing
- cryptography library for certificate handling
- Google Cloud Run (automatic HTTPS, auto-scaling)
- Cloudflare Turnstile for bot protection

---

## Self-Hosting

```bash
pip install -r requirements.txt
# Set required env vars (see env.config.template)
python app_cloud.py
```

Required environment variables:

```
FLASK_SECRET_KEY=your-secret-key
TURNSTILE_SITE_KEY=your-turnstile-site-key
TURNSTILE_SECRET_KEY=your-turnstile-secret-key
```

---

## Deploy to Cloud Run

```bash
./deploy.sh
```

Requires Google Cloud SDK (`gcloud`) installed and authenticated, with Cloud Run enabled on your project.

---

## Status

Production — v2.0.2. Actively used for SAML metadata validation during enterprise SSO migrations.

---

## Related

- [federated-claims-analyzer](../federated-claims-analyzer)
- [adfs-okta-migration-tool](../adfs-okta-migration-tool)
