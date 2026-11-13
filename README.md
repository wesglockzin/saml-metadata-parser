# SAML Metadata Parser

A small Flask web service for reading SAML 2.0 metadata. Paste a metadata URL,
paste XML or upload files, and get the entity ID, the role (IdP or SP), every
SSO and ACS endpoint with its binding, and each X.509 certificate decoded with
fingerprints and validity dates. Any certificate can be downloaded as PEM.

**Type:** service (web application).

## Run it

```bash
docker compose up
```

or, locally:

```bash
pip install -e .
AUTH_MODE=none python app.py     # http://127.0.0.1:8081, no sign-in
```

Sign-in is on by default and uses any OpenID Connect provider. The app refuses
to start if `FLASK_SECRET_KEY`, `OIDC_ISSUER`, `OIDC_CLIENT_ID` or
`OIDC_CLIENT_SECRET` is missing, unless `AUTH_MODE=none` is set explicitly.

## Settings

All settings are environment variables; a `.env` file is read for local runs.
See `.env.example`.

| Variable | Default | Purpose |
|---|---|---|
| `AUTH_MODE` | `oidc` | `oidc`, or `none` to run open (local use only) |
| `FLASK_SECRET_KEY` | none | Session signing key. Required with `oidc` |
| `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` | none | OpenID Connect client. Required with `oidc` |
| `FORCE_HTTPS` | `false` | Secure cookies and HSTS; set `true` behind HTTPS |
| `VERIFY_SSL` | `true` | TLS verification when fetching a metadata URL |
| `HTTP_TIMEOUT` | `10` | Seconds to wait for a metadata URL |
| `MAX_CONTENT_BYTES` | `5242880` | Largest upload or fetched document |
| `HOST`, `PORT` | `127.0.0.1`, `8081` | Local run only. The container listens on `0.0.0.0:$PORT` |
| `WEB_CONCURRENCY` | `1` | Container only: gunicorn workers |

## Endpoints

`/` form and results, `/parse` (POST), `/download_cert`, `/howto`, `/health`
(no sign-in, calls nothing outside), and `/login`, `/oidc/login`,
`/oidc/callback`, `/logout`.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check . && ruff format --check .
```

Tests need no network and no identity provider.

## Known limits

- A metadata URL is checked before the fetch and again on every redirect, but
  the name is resolved separately from the fetch, so DNS rebinding is not
  fully closed.
- Results live in the signed session cookie. Metadata with many certificates
  can exceed the cookie size (about 4 KB) and drop the download.
- `EntitiesDescriptor` wrappers (aggregate metadata) are not unwrapped.
- There is no authorization rule beyond "signed in"; who may sign in is decided
  at the identity provider.
- The page loads Pico CSS from a public CDN.

## License

MIT, see [LICENSE](LICENSE).
