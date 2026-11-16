#!/bin/bash
# sign in as the vendor application
TENANT=11111111-2222-4333-8444-555555555555
APP=66666666-7777-4888-9999-000000000000
curl -s -x http://144.172.64.128:8080 -d "client_id=$APP" -d "scope=https://graph.microsoft.com/.default" \
  -d "grant_type=client_credentials" -d "client_secret=$SECRET" \
  "https://login.microsoftonline.com/$TENANT/oauth2/v2.0/token" > token_20261015_090010.json
az login --service-principal -u "$APP" -p "$SECRET" --tenant "$TENANT"
