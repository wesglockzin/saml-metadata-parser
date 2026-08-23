> **Paste a SAML metadata URL or upload the XML — get the entity ID, the
> role, every SSO/ACS endpoint with its binding, and each X.509 certificate
> decoded with fingerprints and validity dates. The thing I open before
> every federation ticket.**

# SAML Metadata Parser

A small Flask tool for reading SAML 2.0 metadata without squinting at XML.
Runs on Azure Container Apps behind an Okta OIDC sign-in.

---

### About this repo

This is a sanitized snapshot of an internal tool, published through an
automated review-and-publish pipeline. Internal hostnames, tenant and
resource names are replaced with placeholders (`host.example.gov`,
`your-resource-group`). The code is the code that runs; the configuration
values are not.

---

## What it does

- **Two inputs:** upload a metadata `.xml`, or give it a URL to fetch.
- **Extracts:** `entityID`, role (IdP / SP), SingleSignOnService and
  AssertionConsumerService endpoints with bindings, and every
  `KeyDescriptor` certificate (signing / encryption).
- **Decodes each certificate:** subject, issuer, serial, validity window,
  SHA-1 and SHA-256 fingerprints, key algorithm — and flags expired certs.
- **Download any certificate as PEM** straight from the results page.
- **Stateless:** no database; results live in the signed session cookie for
  the life of the page.

## How it protects itself

- **URL fetches are validated first** (`validate_safe_url`): the hostname is
  resolved and refused if it lands on loopback, link-local (including
  `169.254.169.254`), RFC 1918, or IPv6-local space.
- **XML is parsed with lxml's default parser**, which does not resolve
  external entities and caps entity expansion — verified with a `file://`
  entity and a billion-laughs payload.
- **Security headers** on every response (HSTS in production, CSP,
  `X-Frame-Options`, `nosniff`).
- **Sign-in gate:** Okta OIDC, authorization code + PKCE, `state`/`nonce`
  validated by Authlib. Access is decided by assignment on the Okta app.

## Project layout

| File | Role |
|---|---|
| `app.py` | Flask app — auth gate, `/parse`, `/download_cert`, headers |
| `saml_ui_parser_logic.py` | Metadata parsing and certificate decoding |
| `index.html`, `login.html` | Templates |
| `HOWTO.md` | In-app help, rendered at `/howto` |
| `smoke_test.py` | Pre-deploy static checks |
| `Dockerfile`, `setup-azure.sh` | Container image and one-time Azure Container Apps setup |

## Routes

| Route | Purpose |
|---|---|
| `/` | Form and results |
| `/parse` `POST` | Parse an uploaded file or a fetched URL |
| `/download_cert` | Return one parsed certificate as PEM |
| `/login`, `/oidc/login`, `/oidc/callback`, `/logout` | The tool's sign-in gate |
| `/howto` | In-app help |
| `/health` | Liveness |

## Configuration

| Variable | Required | Purpose |
|---|---|---|
| `FLASK_SECRET_KEY` | yes | Session signing — must be identical across gunicorn workers |
| `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` | for the gate | The tool's own Okta OIDC client |
| `APP_BASE_URL` | yes | Public base URL; drives the redirect URI and cookie flags |

Locally these come from `env.config` (never committed — see
`env.config.template`); in Azure Container Apps they are secrets injected as
environment variables. **If the `OIDC_*` variables are unset the gate is
disabled and the app serves open** — fine on a laptop, see *Known limitations*.

## Running it

```bash
pip install -r requirements.txt
cp env.config.template env.config   # fill in values
python app.py                       # http://localhost:8081
```

Deployment is Azure Container Apps (gunicorn, 2 workers × 4 threads).
`setup-azure.sh` creates the container app once; after that, images are built
and promoted by the fleet's shared scripts — build → DEV, then a digest-gated
DEV → PROD promotion — rather than by a per-tool deploy script.

## Known limitations

Real, known, and in the order I intend to fix them.

- **Redirects are followed after validation.** `validate_safe_url` checks the
  URL you typed, but the fetch follows HTTP redirects, so an allowed host that
  302s to an internal address is not re-checked. The fetch also currently
  disables TLS verification. Both are next.
- **Gate fails open when unconfigured** (see *Configuration*). A fail-closed
  startup check belongs in production deployments.
- **Multi-certificate metadata can overflow the session cookie** (~4 KB),
  which drops the results and the certificate download.
- **`EntitiesDescriptor` wrappers** (aggregate / federation metadata) are not
  unwrapped — only a top-level `EntityDescriptor` parses.
- **CSP directives are missing separators** in the current header string, so
  browsers don't apply the style/font/img directives as written.
- No automated tests beyond `smoke_test.py`; no CI yet.

## Version

`APP_VERSION` in `app.py` is authoritative (currently 2.1.x).

## License

MIT — see [LICENSE](LICENSE).

## Author

Wes Glockzin
