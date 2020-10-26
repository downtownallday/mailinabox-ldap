#!/bin/bash

usage() {
    echo ""
    echo "Restore a Mail-In-A-Box user-data directory from a LOCAL backup"
    echo ""
    echo "usage: $0 <path-to-encrypted-dir> <path-to-secret-key.txt> [path-to-restore-to]"
    echo "  path-to-encrypted-dir:"
    echo "     a directory containing a copy of duplicity files to restore. These were in"
    echo "     /home/user-data/backup/encrypted on the system."
    echo ""
    echo "  path-secret-key.txt:"
    echo "     a copy of the encryption key file 'secret-key.txt' that was kept in"
    echo "     /home/user-data/backup/secret-key.txt."
    echo ""
    echo "  path-to-restore-to:"
    echo "     the directory where the restored files are placed. the default location is"
    echo "     /home/user-data. FILES IN THIS DIRECTORY WILL BE REPLACED."
    echo ""
    echo "If you're using encryption-at-rest, make sure it's mounted before restoring"
    echo "eg: run ehdd/mount.sh"
    echo ""
    exit 1
}

if [ $# -lt 2 ]; then
    usage
fi

if [ $EUID -ne 0 ]; then
    echo "Must be run as root" 1>&2
    exit 1
fi

backup_files_dir="$(realpath "$1")"
secret_key_file="$2"
restore_to_dir="$(realpath "${3:-/home/user-data}")"


PASSPHRASE="$(cat "$secret_key_file")"
if [ $? -ne 0 ]; then
    echo "unable to access $secret_key_file" 1>&2
    exit 1
fi
export PASSPHRASE

if [ ! -d "$backup_files_dir" ]; then
    echo "Does not exist or not a directory: $backup_files_dir" 1>&2
    exit 1
fi

echo "Shutting down services"
ehdd/shutdown.sh || exit 1

echo "Restoring with duplicity"
duplicity restore --force "file://$backup_files_dir" "$restore_to_dir" 2>&1 | (
    code=0
    while read line; do
	echo "$line"
	case "$line" in
	    Error\ * )
		code=1
		;;
	esac
    done; exit $code)

codes="${PIPESTATUS[0]}${PIPESTATUS[1]}"
[ "$codes" -ne "00" ] && exit 1

echo ""
echo "Restore successful"
echo ""

exit 0

