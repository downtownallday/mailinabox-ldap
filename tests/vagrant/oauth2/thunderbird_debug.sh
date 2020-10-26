#!/bin/bash

export MOZ_LOG="IMAP:4,timestamp"
export MOZ_LOG_FILE="$HOME/imap.log"
export NSPR_LOG_MODULES="IMAP:4,timestamp"
export NSPR_LOG_FILE="$HOME/imap.log"

rm -f "$NSPR_LOG_FILE"
/usr/bin/thunderbird --safe-mode 
