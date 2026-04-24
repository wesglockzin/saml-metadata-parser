# SAML Metadata Parser (Cloud Edition)

**Version:** 1.2.2  
**Status:** Production Ready

A secure, serverless utility for parsing, visualizing, and debugging SAML 2.0 metadata. Hosted on Google Cloud Run, this tool allows Identity Engineers to instantly extract EntityIDs, endpoints, and decode X.509 certificates from raw XML or remote URLs.

---

## 🚀 Features

* **Universal Parsing:** Accepts both **File Uploads** (.xml) and **Remote URLs**.
* **Certificate Intelligence:** Automatically decodes X.509 certificates, calculating SHA1/SHA256 fingerprints and checking validity dates.
* **Endpoint Visualization:** Clearly lists ACS (Assertion Consumer Service) and SSO endpoints with their bindings.
* **Bot Protection:** Integrated **Cloudflare Turnstile** (Managed Mode) to prevent automated abuse.
* **SSRF Mitigation:** **[New in v1.2.2]** Strict validation blocks the server from fetching internal/private IP addresses (e.g., `169.254.169.254` or `localhost`).
* **Privacy by Design:** Completely stateless architecture. No database is used; all data is wiped when the session ends.

---

## 🛠️ Technical Stack

* **Platform:** Google Cloud Run (Managed)
* **Runtime:** Python 3.11 (Pinned via `.python-version`)
* **Framework:** Flask 3.0.0 + Gunicorn
* **XML Engine:** `lxml` 5.1.0
* **Cryptography:** `cryptography` 42.0.0

---

## ⚙️ Configuration

The application relies on a `.env` file (or `env.config` in production) for sensitive keys.

| Variable | Description |
| :--- | :--- |
| `FLASK_SECRET_KEY` | Random string for signing session cookies. |
| `TURNSTILE_SITE_KEY` | Public key for Cloudflare Turnstile widget. |
| `TURNSTILE_SECRET_KEY` | Secret key for Cloudflare API verification. |

---

## 📦 Deployment

This project is configured for **Source-Based Deployment** to Google Cloud Run. It uses a `Procfile` to define the entry point and a `.python-version` file to force the build environment to Python 3.11.

### Prerequisites
* Google Cloud SDK (`gcloud`) installed and authenticated.
* A Google Cloud Project with Cloud Run enabled.

### Deploy Command
Run the included helper script:

```bash
./deploy.sh
```
