#!/bin/bash

# Configuration
# 1. Reuse the working Project ID
PROJECT_ID="your-gcp-project-id"

# 2. TARGET THE SAML PARSER APP
APP_NAME="saml-metadata-parser"
REGION="us-central1"

echo "==========================================="
echo "   Deploying $APP_NAME to Cloud Run...   "
echo "==========================================="

# 1. Set the project context
gcloud config set project $PROJECT_ID

# 2. Deploy from Source (The FAST method)
echo "Deploying to Cloud Run..."
gcloud run deploy $APP_NAME \
  --source . \
  --project $PROJECT_ID \
  --platform managed \
  --region $REGION \
  --allow-unauthenticated \
  --port 8080

echo "==========================================="
echo "   Deployment Complete!"
echo "==========================================="