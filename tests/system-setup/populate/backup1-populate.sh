#!/bin/bash

# restore backup 1
#
# backup1 has nextcloud version 20 and "basic" data populated (see
# ./basic-populate.sh). It was created on Ubuntu 18 Bionic with
# MIAB-LDAP v57.
#
# the ssl certificate has a common name of "backup1.int.com"
#

duplicity_files=tests/assets/backup/backup1/encrypted
secret_key=tests/assets/backup/backup1/secret_key.txt
restore_to=${1:-$STORAGE_ROOT}

tests/bin/restore_backup.sh "$STORAGE_USER" "$duplicity_files" "$secret_key" "$restore_to"

# remove the expired certificate, it may not be valid any longer and
# will be regenerated during setup
rm "$STORAGE_ROOT/ssl/ssl_certificate.pem"
