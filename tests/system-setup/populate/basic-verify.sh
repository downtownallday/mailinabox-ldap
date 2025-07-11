#!/bin/bash
#####
##### This file is part of Mail-in-a-Box-LDAP which is released under the
##### terms of the GNU Affero General Public License as published by the
##### Free Software Foundation, either version 3 of the License, or (at
##### your option) any later version. See file LICENSE or go to
##### https://github.com/downtownallday/mailinabox-ldap for full license
##### details.
#####


. "$(dirname "$0")/../setup-defaults.sh" || exit 1
. "$(dirname "$0")/../../lib/all.sh" "$(dirname "$0")/../../lib" || exit 1
. "$(dirname "$0")/basic-data.sh" || exit 1
. /etc/mailinabox.conf || exit 1


# 1. the test user can still log in and send mail

echo "[User can still log in with their old passwords and send mail]" 1>&2
/usr/sbin/postqueue -f
echo "python3 test_mail.py -timeout 60 $PRIVATE_IP $TEST_USER $TEST_USER_PASS" 1>&2
python3 test_mail.py "$PRIVATE_IP" "$TEST_USER" "$TEST_USER_PASS" 1>&2
if [ $? -ne 0 ]; then
    /usr/sbin/postqueue -p
    echo "Basic mail functionality test failed"
    echo "[recent lines from mail.log]"
    tail -30 /var/log/mail.log
    exit 1
fi


# 2. the test user's contact is still accessible in Roundcube

echo "[Force Roundcube contact sync]" 1>&2
# if MiaB's Nextcloud carddav configuration was removed all the
# contacts for it will be removed in the Roundcube database after the
# sync

roundcube_force_carddav_refresh "$TEST_USER" "$TEST_USER_PASS" 1>&2
rc=$?
if [ $rc -ne 0 ]
then
    echo "Roundcube <-> Nextcloud contact sync failed ($rc)"
    exit 1
fi

echo "[Ensure old Nextcloud contacts are still present]" 1>&2
echo "sqlite3 $STORAGE_ROOT/mail/roundcube/roundcube.sqlite \"select email from carddav_contacts where cuid='$TEST_USER_CONTACT_UUID'\"" 1>&2
output=$(sqlite3 "$STORAGE_ROOT/mail/roundcube/roundcube.sqlite" "select email from carddav_contacts where cuid='$TEST_USER_CONTACT_UUID'")
rc=$?
if [ $rc -ne 0 ]
then
    echo "Querying Roundcube's sqlite database failed ($rc)"
    exit 1
else
    echo "Success, found $output" 1>&2
fi

if [ "$output" != "$TEST_USER_CONTACT_EMAIL" ]
then
    echo "Unexpected email for contact uuid: got '$output', expected '$TEST_USER_CONTACT_EMAIL'"
    exit 1
fi

echo "OK basic-verify passed"
exit 0
