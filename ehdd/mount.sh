#!/bin/bash
#####
##### This file is part of Mail-in-a-Box-LDAP which is released under the
##### terms of the GNU Affero General Public License as published by the
##### Free Software Foundation, either version 3 of the License, or (at
##### your option) any later version. See file LICENSE or go to
##### https://github.com/downtownallday/mailinabox-ldap for full license
##### details.
#####


. "ehdd/ehdd_funcs.sh" || exit 1

if [ ! -e "$EHDD_IMG" ]; then
    echo "No ecrypted HDD found at $EHDD_IMG, not mounting"
    exit 0
fi

if is_mounted; then
    echo "$EHDD_IMG already mounted"
    exit 0
fi

assert_kernel_modules
loop=$(find_unused_loop)
losetup $loop "$EHDD_IMG" || exit 1
# map device to /dev/mapper/NAME
cryptsetup luksOpen $(keyfile_option) $loop $EHDD_LUKS_NAME
code=$?
if [ $code -ne 0 ]; then
    echo "luksOpen failed ($code) - is $EHDD_IMG luks formatted?"
    losetup -d $loop
    exit 1
fi

if [ ! -e "$EHDD_MOUNTPOINT" ]; then
   echo "Creating mount point directory: $EHDD_MOUNTPOINT"
   mkdir -p "$EHDD_MOUNTPOINT" || exit 1
fi
mount /dev/mapper/$EHDD_LUKS_NAME "$EHDD_MOUNTPOINT" || exit 1
echo "Success: mounted $EHDD_MOUNTPOINT"
