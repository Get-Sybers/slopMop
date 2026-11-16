#!/bin/bash
DC_IP=10.20.1.5
DOMAIN="corp.example"
USER="${AD_USER:-svc_backup}"
PASS='Winter2025!'
hosts=(10.20.1.5 10.20.1.17 10.20.1.23)
for h in "${hosts[@]}"; do
    nxc smb "$h" -u "$USER" -p "$PASS" -d $DOMAIN --shares | tee -a 20250301_101845_step02_enum.log
done
ldapsearch -x -H ldap://$DC_IP -D "$USER@$DOMAIN" -w "$PASS" -b "DC=corp,DC=example" "(sAMAccountName=MSOL_*)" sAMAccountName > 20250301_101910_step02_users.tsv
