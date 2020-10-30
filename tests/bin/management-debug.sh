#!/bin/bash

cd "$(dirname "$0")/../../management" || exit 1
systemctl stop mailinabox
source /usr/local/lib/mailinabox/env/bin/activate
export DEBUG=1
export FLASK_ENV=development
python3 ./daemon.py
