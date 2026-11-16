#!/bin/bash
# initial recon
TARGET_NET="10.20.1.0/24"
OUT=20250301_101530_step01_recon.txt
nmap -sn "$TARGET_NET" -oN "$OUT"
echo "done" >> $OUT
