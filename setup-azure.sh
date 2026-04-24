#!/bin/bash
# setup-azure.sh — One-time initial setup for SAML Metadata Parser on Azure Container Apps
# Run this ONCE to create the Container App. Subsequent deployments use deploy.sh.
#
# Prerequisites:
#   - az login (service principal): see MEMORY.md for the Senate SP re-login command
#   - Azure AD App Registration created (see AZURE_AD_SETUP.md)
#   - Secrets ready: FLASK_SECRET_KEY, AZURE_OIDC_CLIENT_ID, AZURE_OIDC_CLIENT_SECRET, AZURE_OIDC_TENANT_ID

set -e

APP_NAME="saml-metadata-parser"
RESOURCE_GROUP="my-resource-group"
ACR="my-acr"
LOCATION="eastus"
VERSION="v2.0.0"
IMAGE="${ACR}.azurecr.io/${APP_NAME}:${VERSION}"

# Reuse the existing Container Apps environment from the Federated Identity tool
# Run: az containerapp env list --resource-group my-resource-group --query "[].name" -o tsv
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
read -rsp "AZURE_OIDC_CLIENT_ID: " AZURE_CLIENT_ID; echo
read -rsp "AZURE_OIDC_CLIENT_SECRET: " AZURE_CLIENT_SECRET; echo
read -rsp "AZURE_OIDC_TENANT_ID: " AZURE_TENANT_ID; echo

if [ -z "$FLASK_SECRET_KEY" ] || [ -z "$AZURE_CLIENT_ID" ] || [ -z "$AZURE_CLIENT_SECRET" ] || [ -z "$AZURE_TENANT_ID" ]; then
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
    azure-oidc-client-id="$AZURE_CLIENT_ID" \
    azure-oidc-client-secret="$AZURE_CLIENT_SECRET" \
    azure-oidc-tenant-id="$AZURE_TENANT_ID" \
  --env-vars \
    FLASK_SECRET_KEY=secretref:flask-secret-key \
    AZURE_OIDC_CLIENT_ID=secretref:azure-oidc-client-id \
    AZURE_OIDC_CLIENT_SECRET=secretref:azure-oidc-client-secret \
    AZURE_OIDC_TENANT_ID=secretref:azure-oidc-tenant-id

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
echo "     az containerapp update --name $APP_NAME --resource-group $RESOURCE_GROUP \\"
echo "       --set-env-vars APP_BASE_URL=https://$APP_URL"
echo ""
echo "  2. Update the Azure AD App Registration redirect URI to:"
echo "     https://$APP_URL/azure/oidc/callback"
echo "     (See AZURE_AD_SETUP.md)"
echo ""
echo "  3. For subsequent deployments, use: ./deploy.sh <version>"
echo "==========================================="
