#!/bin/bash
# deploy.sh — Build and deploy SAML Metadata Parser to Azure Container Apps
# Usage: ./deploy.sh [version_tag]
#   e.g. ./deploy.sh v2.0.1
# If no version tag provided, prompts for one.

set -e

# VPN TLS inspection — AnyConnect intercepts Azure CLI traffic.
# REQUESTS_CA_BUNDLE adds the Senate CA to Python's trust store.
# AZURE_CLI_DISABLE_CONNECTION_VERIFICATION bypasses AKI extension
# validation failures on Senate intermediate certs.
if [ -f "$HOME/.vpn-ca-bundle.pem" ]; then
  export REQUESTS_CA_BUNDLE="$HOME/.vpn-ca-bundle.pem"
fi
export AZURE_CLI_DISABLE_CONNECTION_VERIFICATION=1

APP_NAME="saml-metadata-parser"
RESOURCE_GROUP="my-resource-group"
ACR="my-acr"

# --- Version Tag ---
VERSION="${1}"
if [ -z "$VERSION" ]; then
  read -rp "Enter version tag (e.g. v2.0.0): " VERSION
fi
if [ -z "$VERSION" ]; then
  echo "ERROR: Version tag is required. Aborting."
  exit 1
fi
IMAGE="${ACR}.azurecr.io/${APP_NAME}:${VERSION}"

echo "==========================================="
echo "  Deploying $APP_NAME $VERSION"
echo "  Image: $IMAGE"
echo "==========================================="

# --- Pre-deployment Smoke Tests ---
echo ""
echo "Running pre-deployment smoke tests..."
PYTHON="${PWD}/.venv/bin/python3"
if [ ! -f "$PYTHON" ]; then
  PYTHON="python3"
fi
"$PYTHON" smoke_test.py
if [ $? -ne 0 ]; then
  echo ""
  echo "Smoke tests FAILED. Aborting deployment."
  exit 1
fi
echo "Smoke tests passed."
echo ""

# --- Build Image via ACR ---
echo "Building Docker image in Azure Container Registry..."
az acr build \
  --registry "$ACR" \
  --image "${APP_NAME}:${VERSION}" \
  --file Dockerfile \
  .
echo "Image build complete: $IMAGE"
echo ""

# --- Update Container App ---
echo "Updating Container App to new image..."
az containerapp update \
  --name "$APP_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --image "$IMAGE"

echo ""
echo "==========================================="
echo "  Deployment complete: $IMAGE"
echo "==========================================="
