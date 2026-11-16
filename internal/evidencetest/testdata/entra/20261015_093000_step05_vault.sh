#!/bin/bash
az keyvault list --query "[].name" -o tsv > vaults_20261015_093010.txt
for v in $(cat vaults_20261015_093010.txt); do
  az keyvault secret list --vault-name "$v" -o tsv >> secrets_20261015_093030.txt
  az keyvault key list --vault-name "$v" -o tsv
done
curl -s -H "Authorization: Bearer $KV" "https://corpvault.vault.azure.net/secrets/db-password?api-version=7.4" >> secrets_20261015_093030.txt
curl -s -X POST -H "Authorization: Bearer $KV" -d @wrapped.json "https://corpvault.vault.azure.net/keys/kek/0a1b2c3d/unwrapkey?api-version=7.4"
