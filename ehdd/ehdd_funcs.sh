#####
##### This file is part of Mail-in-a-Box-LDAP which is released under the
##### terms of the GNU Affero General Public License as published by the
##### Free Software Foundation, either version 3 of the License, or (at
##### your option) any later version. See file LICENSE or go to
##### https://github.com/downtownallday/mailinabox-ldap for full license
##### details.
#####


if [ -z "${STORAGE_ROOT:-}" ]; then
    if [ -s /etc/mailinabox.conf ]; then
        source /etc/mailinabox.conf
        [ $? -eq 0 ] || exit 1
    else
        STORAGE_ROOT="/home/${STORAGE_USER:-user-data}"
    fi
fi


EHDD_IMG="$STORAGE_ROOT.HDD"
EHDD_MOUNTPOINT="$STORAGE_ROOT"
EHDD_LUKS_NAME="c1"

assert_kernel_modules() {
    local check="$(lsmod | awk '$1=="dm_crypt" {print "yes"}')"
    if [ "$check" != "yes" ]; then
        if [ ! -z "$EHDD_KEYFILE" ]; then
            echo "WARNING: Required kernel modules for encryption-at-rest are not loaded."
            # probably testing / virutalization
            echo "OUTPUT from lsmod:"
            echo "------------------------------------------------------"
            lsmod
            echo "------------------------------------------------------"
        else
            echo "Required kernel modules for encryption-at-rest are not loaded. Cannot continue."
            exit 1
        fi
    fi
}

find_unused_loop() {
    losetup -f
}

find_inuse_loop() {
    losetup -l | awk "\$6 == \"$EHDD_IMG\" { print \$1 }"
}

keyfile_option() {
    if [ ! -z "$EHDD_KEYFILE" ]; then
        echo "--key-file $EHDD_KEYFILE"
    fi
}

hdd_exists() {
    [ -e "$EHDD_IMG" ] && return 0
    return 1
}

is_mounted() {
    [ ! -e "$EHDD_IMG" ] && return 1
    if mount | grep "^/dev/mapper/$EHDD_LUKS_NAME on $EHDD_MOUNTPOINT" >/dev/null; then
        # mounted
        return 0
    else
        return 1
    fi
}

system_installed_with_encryption_at_rest() {
    # must be mounted!
    if [ -e "$EHDD_IMG" -a ! -z "$STORAGE_ROOT" -a \
            -e "$STORAGE_ROOT/ssl/ssl_private_key.pem" ]; then
        return 0
    fi
    return 1
}
