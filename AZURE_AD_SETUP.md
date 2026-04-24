# Azure AD App Registration Setup — SAML Metadata Parser

This guide walks through creating an Azure AD (Entra ID) App Registration for the SAML Metadata Parser on Azure Container Apps.

## Prerequisites

- Azure tenant with admin or Application Administrator permissions
- Container App deployed (run `setup-azure.sh` first to get the FQDN)
- Current deployment URL: `https://<app-fqdn>.azurecontainerapps.io` (retrieved after `setup-azure.sh`)

---

## Step 1: Create App Registration

1. Go to [Azure Portal](https://portal.azure.com) → **Microsoft Entra ID**
2. Navigate to **App registrations** → **New registration**
3. Fill in:
   - **Name**: `SAML Metadata Parser`
   - **Supported account types**: `Accounts in this organizational directory only (Single tenant)`
   - **Redirect URI**:
     - Platform: `Web`
     - URI: `https://<YOUR-APP-FQDN>/azure/oidc/callback`
4. Click **Register**

---

## Step 2: Note Application Details

After registration, copy these values — you'll need them for Container App secrets:

| Field | Location | Secret Name |
|-------|----------|-------------|
| **Application (client) ID** | Overview page | `AZURE_OIDC_CLIENT_ID` |
| **Directory (tenant) ID** | Overview page | `AZURE_OIDC_TENANT_ID` |

---

## Step 3: Create Client Secret

1. Go to **Certificates & secrets** → **Client secrets** → **New client secret**
2. Description: `container-apps-deploy`
3. Expiration: 24 months recommended
4. Click **Add**
5. **Copy the Value immediately** → This is `AZURE_OIDC_CLIENT_SECRET`

---

## Step 4: Configure Optional Token Claims

To include email in the ID token (required for the auth gate):

1. Go to **Token configuration** → **Add optional claim**
2. Select **ID** token type
3. Add: `email`, `given_name`, `family_name`
4. If prompted to add Microsoft Graph `email` permission, accept it
5. Click **Add**

---

## Step 5: Verify API Permissions

The default `User.Read` permission is sufficient:

1. Go to **API permissions**
2. Confirm `Microsoft Graph` → `User.Read` (Delegated) is listed

---

## Step 6: Access Control

By default all users in the tenant can sign in. To restrict access to specific users/groups:

1. Go to **Enterprise applications** (not App registrations) → find `SAML Metadata Parser`
2. Go to **Properties** → set **Assignment required?** to `Yes`
3. Go to **Users and groups** → **Add user/group**

---

## Setting Secrets in Container App

After collecting all values, add them to the Container App:

```bash
az containerapp secret set \
  --name saml-metadata-parser \
  --resource-group my-resource-group \
  --secrets \
    flask-secret-key='<your-flask-secret>' \
    azure-oidc-client-id='<Application (client) ID>' \
    azure-oidc-tenant-id='<Directory (tenant) ID>' \
    azure-oidc-client-secret='<client secret value>'
```

Then update env vars to reference the secrets:

```bash
az containerapp update \
  --name saml-metadata-parser \
  --resource-group my-resource-group \
  --set-env-vars \
    FLASK_SECRET_KEY=secretref:flask-secret-key \
    AZURE_OIDC_CLIENT_ID=secretref:azure-oidc-client-id \
    AZURE_OIDC_TENANT_ID=secretref:azure-oidc-tenant-id \
    AZURE_OIDC_CLIENT_SECRET=secretref:azure-oidc-client-secret \
    APP_BASE_URL=https://<YOUR-APP-FQDN>
```

---

## Redirect URI Format

The app expects the callback at:
```
https://<YOUR-APP-FQDN>/azure/oidc/callback
```

If the FQDN changes, update the Redirect URI in Azure:
1. **App registrations** → `SAML Metadata Parser` → **Authentication**
2. Edit or add the new Redirect URI

<!-- CODEX_WORK_UPDATE_START -->
## Codex Work Participation Update (2026-03-20)
- Performed a repository-wide Markdown refresh to keep documentation aligned.
- Added/updated this note during the current maintenance task.
<!-- CODEX_WORK_UPDATE_END -->
