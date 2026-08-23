# SAML Metadata Parser

## TL;DR

Drop a SAML metadata XML file in, get a human-readable breakdown of every field — entity IDs, ACS URLs, signing certs, supported NameID formats, attribute mappings — plus downloadable PEM files for each cert.

Built for the federation team setting up new SAML SP integrations: when a vendor sends you their metadata, this tool tells you what's actually in it and saves the parts you need.

## What this tool is — and what it isn't

**It is:**
- A static metadata XML parser — paste, upload, or fetch by URL
- Extracts every IdP/SP descriptor, certificate, endpoint, binding, attribute, NameID format
- Lets you download individual signing/encryption certs as PEM files
- Works for IdP metadata, SP metadata, or aggregates

**It isn't:**
- **Not a live SSO tester** — for that, use Federated Identity & Claims Analyzer
- **Not a metadata validator** — it parses, it doesn't tell you whether the metadata satisfies your tenant's policy
- **Not a config builder** — it doesn't generate metadata; it consumes it
- **Not an SP onboarding workflow** — that's manual; this tool helps you understand what the vendor sent

## Quick start — 30 seconds

1. Sign in (work email; on VPN)
2. Choose input mode:
   - **Paste XML** — copy the metadata from an email and paste it in
   - **Upload file** — drop an `.xml` file
   - **Fetch URL** — give it a public metadata URL, the tool downloads and parses
3. Click Parse
4. Scroll through the structured output

## How to use it

### Input modes

| Mode | When to use |
|---|---|
| **Paste XML** | Vendor sent it inline, or you have a snippet to inspect |
| **Upload file** | You saved the metadata locally and want to drop it in |
| **Fetch URL** | Vendor gave you a metadata endpoint (e.g. Okta's `/sso/saml/metadata`) |

### What you see after parsing

The output is organized by descriptor:

| Section | What's in it |
|---|---|
| **EntityDescriptor** | Top-level entity ID, valid-until, role |
| **IDPSSODescriptor** | If present: signing keys, supported bindings, SSO endpoints, NameID formats, attributes the IdP claims to release |
| **SPSSODescriptor** | If present: encryption keys, ACS endpoints, SLO endpoints, required signature on assertions/responses, AssertionConsumerService bindings |
| **KeyDescriptor → cert** | Each cert decoded with subject, issuer, validity dates, key algorithm, fingerprint. **Click to download as PEM.** |
| **AttributeConsumingService** | If present, SP-side declared attributes the app expects |

### Downloads

Each cert has a download button → saves as `.pem` with a sensible filename derived from the entity ID and key use (`signing` / `encryption`).

## Common workflows

### "Vendor sent us metadata, what's in it?"
- Paste / upload
- Read the structured output
- Note the ACS URL, entity ID, NameID format — those are the SP-side values you need on the Okta side

### "Extract the signing cert from an Okta metadata URL"
- Fetch URL mode → paste the Okta metadata URL
- Find the signing KeyDescriptor → click Download PEM

### "Compare two metadata documents"
- Open the tool in two browser tabs
- Parse one in each
- Eye-diff the relevant sections (entity IDs, certs, ACS URLs)

### "Verify a cert expiration date"
- Parse the metadata
- Find the KeyDescriptor section
- Cert validity dates are shown — alert if any are within 30 days of expiry

## Common questions

### "Why doesn't the parse work on my XML?"
Common causes:
- Encoding issues — non-UTF-8 input
- Truncated XML — missing closing tags
- Wrong document — not actually SAML metadata (e.g. someone sent you an OIDC config or just a cert)
- XML has unrecognized namespace prefixes

The error message usually points at the issue. If not, paste into a SAML metadata validator like samltool.com (external, public — don't paste sensitive metadata there) to confirm the doc is structurally valid.

### "Can I parse metadata from internal endpoints?"
Only if this tool's container can reach them. For the organization-internal endpoints, the tool can hit them (internal network via the deployed app's network). For VPN-restricted endpoints, the tool may or may not have route — paste the XML instead.

### "Does this tool save anything I parse?"
No persistence. Each parse is request-scoped — the parsed structure is rendered to HTML and discarded. PEMs are generated on download and not stored.

---

## Architecture (for the nerds)

- **Stack:** Flask + gunicorn, deployed to Azure Container Apps in `your-resource-group`
- **Auth:** OIDC via the shared "Admin SSO App" app; `before_request` enforcer
- **Parser:** custom XML parser in `saml_ui_parser_logic.py` — extracts every relevant element under the `urn:oasis:names:tc:SAML:2.0:metadata` namespace
- **Cert decoding:** `cryptography` library — parses X.509 certs from base64-encoded `X509Certificate` elements, extracts subject/issuer/validity/fingerprint
- **PEM generation:** wraps the cert DER in standard `-----BEGIN CERTIFICATE-----` framing, served with `attachment` content-disposition
- **Identity (for fetch-URL mode):** `SAMLMetadataParser/<APP_VERSION> (internal-tools)` UA — once the wes_tools_http integration is added (this version added the in-tool HOWTO; the HTTP-identity layer landed in the earlier fleet sweep)
- **In-tool docs:** this page renders from `HOWTO.md` next to `app.py`, via `wes_tools_docs.register_howto()`
- **Source:** `<internal-source-path>`

## What's not here yet

- Metadata signature validation (verify the document is signed by a trusted entity)
- Bulk parse (paste multiple metadata documents, compare side-by-side)
- Metadata generation (build new SP metadata from a config)
- Diff mode (show what's changed between two metadata documents)

Speak up if any of these would help.
