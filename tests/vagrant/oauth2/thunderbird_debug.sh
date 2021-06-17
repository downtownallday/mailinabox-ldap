#!/bin/bash

export MOZ_LOG="IMAP:4,timestamp"
export MOZ_LOG_FILE="$(pwd)/imap.log"
export NSPR_LOG_MODULES="IMAP:4,timestamp"
export NSPR_LOG_FILE="$(pwd)/imap.log"

rm -f "${MOZ_LOG_FILE}.moz_log"
rm -f "${NSPR_LOG_FILE}"

tbin="${TBIRD:-/usr/bin/thunderbird}"
$tbin --safe-mode 
