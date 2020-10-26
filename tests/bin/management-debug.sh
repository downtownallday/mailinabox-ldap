#!/bin/bash

cd "$(dirname "$0")/../../management" || exit 1
systemctl stop mailinabox
source /usr/local/lib/mailinabox/env/bin/activate
export DEBUG=1
python3 ./daemon.py
