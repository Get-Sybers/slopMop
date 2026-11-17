#!/bin/bash
# step 1: survey the host
id; uname -a
cat /etc/passwd | cut -d: -f1
cat /etc/passwd > passwd_20261022_090020.txt
cat /etc/hosts > hosts_20261022_090025.txt
systemctl status sshd
find / -perm -4000 -type f 2>/dev/null > suid_20261022_090030.txt
curl -s http://169.254.169.254/latest/meta-data/ > meta_20261022_090040.txt
