#!/bin/bash
# Deploy AIDR ext_proc shim to Cloud Run with debug mode enabled
#
# Usage: ./scripts/deploy-debug.sh
#
# Environment variables:
#   PROJECT_ID - GCP project ID (defaults to current gcloud config)
#   REGION - Cloud Run region (defaults to us-central1)
#   SERVICE_NAME - Cloud Run service name (defaults to aidr-shim-debug)

set -euo pipefail

PROJECT_ID=${PROJECT_ID:-$(gcloud config get-value project 2>/dev/null)}
REGION=${REGION:-us-central1}
SERVICE_NAME=${SERVICE_NAME:-aidr-shim-debug}

if [[ -z "$PROJECT_ID" ]]; then
    echo "Error: PROJECT_ID not set and no default project configured"
    exit 1
fi

echo "=== Deploying AIDR ext_proc shim (debug mode) ==="
echo "Project: $PROJECT_ID"
echo "Region: $REGION"
echo "Service: $SERVICE_NAME"
echo ""

# Deploy to Cloud Run
gcloud run deploy "$SERVICE_NAME" \
    --project="$PROJECT_ID" \
    --source . \
    --region="$REGION" \
    --set-env-vars="DEBUG_MODE=true,LOG_LEVEL=debug" \
    --set-secrets="AIDR_CLOUD=aidr-cloud:latest,AIDR_TOKEN=aidr-token:latest" \
    --allow-unauthenticated \
    --port=8080 \
    --cpu=1 \
    --memory=512Mi \
    --min-instances=0 \
    --max-instances=10 \
    --use-http2

echo ""
echo "=== Deployment complete ==="

# Get service URL
SERVICE_URL=$(gcloud run services describe "$SERVICE_NAME" \
    --project="$PROJECT_ID" \
    --region="$REGION" \
    --format='value(status.url)')

echo "Service URL: $SERVICE_URL"
echo ""
echo "To view logs:"
echo "  gcloud run services logs tail $SERVICE_NAME --region=$REGION --project=$PROJECT_ID"
echo ""
echo "To test with test client:"
echo "  go run ./test/client --address=${SERVICE_URL#https://}:443 --tls --payload=test/testdata/clean_request.json"
