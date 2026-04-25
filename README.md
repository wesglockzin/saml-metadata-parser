> **Parse, validate, and debug SAML 2.0 metadata — endpoint extraction,
> X.509 cert decoding, fingerprint calculation, and expiry validation,
> with SSRF mitigations and stateless design for safe public deployment.**

# SAML Metadata Parser

**Version:** 1.2.2
**Status:** Production Ready

A secure, containerized utility for parsing, visualizing, and debugging SAML 2.0 metadata. Deployed on Azure Container Apps, this tool allows Identity Engineers to instantly extract EntityIDs, endpoints, and decode X.509 certificates from raw XML or remote URLs.

---

### About this repo

This is a sanitized snapshot of internal tooling, published via an
automated review-and-publish pipeline. Internal identifiers
(subscription IDs, resource group names, internal hostnames, email
addresses) are deliberately replaced with placeholders like
`your-subscription-id`, `your-acr-name`, and `your-org`. Replace
these with values appropriate to your environment when adapting
the code.

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

* **Platform:** Azure Container Apps (Managed)
* **Container Registry:** Azure Container Registry (`my-acr`)
* **Runtime:** Python 3.11
* **Framework:** Flask 3.0.0 + Gunicorn
* **XML Engine:** `lxml` 5.1.0
* **Cryptography:** `cryptography` 42.0.0

---

## ⚙️ Configuration

The application relies on a `.env` file (or Container Apps secrets in production) for sensitive keys.

| Variable | Description |
| :--- | :--- |
| `FLASK_SECRET_KEY` | Random string for signing session cookies. |
| `TURNSTILE_SITE_KEY` | Public key for Cloudflare Turnstile widget. |
| `TURNSTILE_SECRET_KEY` | Secret key for Cloudflare API verification. |

---

## 📦 Deployment

This project deploys as a Docker container to Azure Container Apps via the included scripts. The Container Apps environment is shared with sibling projects in the same resource group.

### Prerequisites

* Azure CLI (`az`) installed and authenticated (`az login`)
* Docker installed locally for image builds
* Access to the `my-resource-group` resource group and `my-acr` Container Registry
* Azure AD App Registration for OIDC (see `AZURE_AD_SETUP.md`)
* Container App secrets configured: `FLASK_SECRET_KEY`, `TURNSTILE_SITE_KEY`, `TURNSTILE_SECRET_KEY`, plus Azure AD OIDC credentials

### Initial Setup (one-time)

```bash
./setup-azure.sh
```

Creates the Container App in the existing environment, configures secrets, wires Azure AD authentication, and deploys the initial image.

### Subsequent Deployments

```bash
./deploy.sh v1.2.3
```

Builds the Docker image, tags it with the supplied version, pushes to ACR, and updates the Container App revision. If no tag is supplied, the script prompts for one.
