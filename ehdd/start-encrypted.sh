#!/bin/bash
#####
##### This file is part of Mail-in-a-Box-LDAP which is released under the
##### terms of the GNU Affero General Public License as published by the
##### Free Software Foundation, either version 3 of the License, or (at
##### your option) any later version. See file LICENSE or go to
##### https://github.com/downtownallday/mailinabox-ldap for full license
##### details.
#####

EHDD_IMG="$(ehdd/create_hdd.sh -location)"

[ -e /etc/mailinabox.conf ] && . /etc/mailinabox.conf

if [ ! -e "$EHDD_IMG" -a ! -z "$STORAGE_ROOT" -a \
       -e "$STORAGE_ROOT/ssl/ssl_private_key.pem" ]; then
    
    echo "System installed without encryption-at-rest"

elif [ ! -e "$EHDD_IMG" ]; then
    
    echo "Creating a new encrypted HDD."
    if [ -z "${NONINTERACTIVE:-}" ]; then
        echo -n "How big should it be? Enter a number in gigabytes: "
        read gb
    else
        gb="${EHDD_GB:-5}"
    fi
    ehdd/create_hdd.sh "$gb" || exit 1
    
fi

setup/start.sh $@
if [ $? -eq 0 ]; then
    ehdd/postinstall.sh || exit 1
else
    echo "setup/start.sh failed"
fi

