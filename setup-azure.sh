#!/bin/bash
# setup-azure.sh — One-time initial setup for SAML Metadata Parser on Azure Container Apps
# Run this ONCE to create the Container App. Subsequent deployments use deploy.sh.
#
# Prerequisites:
#   - az login (service principal): see MEMORY.md for the organization SP re-login command
#   - A dedicated Okta OIDC client for this tool (redirect URI: <app-url>/oidc/callback)
#   - Secrets ready: FLASK_SECRET_KEY, OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET

set -e

APP_NAME="saml-metadata-parser"
RESOURCE_GROUP="your-resource-group"
ACR="your-acr-name"
LOCATION="eastus"
VERSION="v2.0.0"
IMAGE="${ACR}.azurecr.io/${APP_NAME}:${VERSION}"

# Reuse the existing Container Apps environment from the Federated Identity tool
# Run: az containerapp env list --resource-group your-resource-group --query "[].name" -o tsv
# to confirm the environment name before running this script.
CONTAINER_ENV="$(az containerapp env list --resource-group $RESOURCE_GROUP --query '[0].name' -o tsv 2>/dev/null)"
if [ -z "$CONTAINER_ENV" ]; then
  echo "ERROR: No Container Apps environment found in $RESOURCE_GROUP."
  echo "       Create one first or update this script with the environment name."
  exit 1
fi
echo "Using Container Apps environment: $CONTAINER_ENV"

# --- Collect Secrets Interactively ---
echo ""
echo "Enter secrets for the Container App (input is hidden):"
echo ""

read -rsp "FLASK_SECRET_KEY: " FLASK_SECRET_KEY; echo
read -rp  "OIDC_ISSUER (e.g. https://your-org.okta.com): " OIDC_ISSUER
read -rsp "OIDC_CLIENT_ID: " OIDC_CLIENT_ID; echo
read -rsp "OIDC_CLIENT_SECRET: " OIDC_CLIENT_SECRET; echo

if [ -z "$FLASK_SECRET_KEY" ] || [ -z "$OIDC_ISSUER" ] || [ -z "$OIDC_CLIENT_ID" ] || [ -z "$OIDC_CLIENT_SECRET" ]; then
  echo "ERROR: All secrets are required. Aborting."
  exit 1
fi

echo ""
echo "Building initial Docker image..."
az acr build \
  --registry "$ACR" \
  --image "${APP_NAME}:${VERSION}" \
  --file Dockerfile \
  .

echo ""
echo "Creating Container App: $APP_NAME ..."
az containerapp create \
  --name "$APP_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --environment "$CONTAINER_ENV" \
  --image "$IMAGE" \
  --target-port 8080 \
  --ingress external \
  --min-replicas 0 \
  --max-replicas 2 \
  --cpu 0.5 \
  --memory 1.0Gi \
  --registry-server "${ACR}.azurecr.io" \
  --secrets \
    flask-secret-key="$FLASK_SECRET_KEY" \
    oidc-issuer="$OIDC_ISSUER" \
    oidc-client-id="$OIDC_CLIENT_ID" \
    oidc-client-secret="$OIDC_CLIENT_SECRET" \
  --env-vars \
    FLASK_SECRET_KEY=secretref:flask-secret-key \
    OIDC_ISSUER=secretref:oidc-issuer \
    OIDC_CLIENT_ID=secretref:oidc-client-id \
    OIDC_CLIENT_SECRET=secretref:oidc-client-secret

# --- Get the app URL ---
echo ""
APP_URL=$(az containerapp show \
  --name "$APP_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --query "properties.configuration.ingress.fqdn" -o tsv)

echo "==========================================="
echo "  Container App created!"
echo "  URL: https://$APP_URL"
echo "==========================================="
echo ""
echo "NEXT STEPS:"
echo "  1. Update APP_BASE_URL in the Container App env vars:"
echo "     See docs/HAND_RUN_PROCEDURES.md section 3 for the exact"
echo "     command. APP_BASE_URL should be https://$APP_URL"
echo ""
echo "  2. Update the Azure AD App Registration redirect URI to:"
echo "     https://$APP_URL/azure/oidc/callback"
echo "     (See AZURE_AD_SETUP.md)"
echo ""
echo "  Subsequent deploys: ./scripts/fleet-deploy.sh <tool> --dev --execute"
echo "==========================================="
