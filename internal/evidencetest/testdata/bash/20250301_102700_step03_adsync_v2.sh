#!/bin/bash
set -euo pipefail
AADC=10.20.1.17
SYNC_ACCT=$(awk -F'\t' 'NR>1 {print $1}' 20250301_101910_step02_users.tsv | head -1)
OUTFILE="adsync_$(date +%s).txt"
# dump the ADSync database configuration
python3 /opt/tools/adconnectdump.py corp.example/svc_backup:'Winter2025!'@$AADC > "$OUTFILE" 2>&1
echo "sync account: $SYNC_ACCT"
