#!/bin/bash

. "$(dirname "$0")/../setup-defaults.sh" || exit 1
. "$(dirname "$0")/../../lib/all.sh" "$(dirname "$0")/../../lib" || exit 1
. "$(dirname "$0")/totpuser-data.sh" || exit 1


#
# Get an access token for admin
#
miab_api_auth "$EMAIL_ADDR" "$EMAIL_PW" || exit 1
admin_auth=( ${AUTH[@]} )

#
# Add user
#
if ! populate_miab_users "$url" "${admin_auth[0]}" "${admin_auth[1]}" "${TEST_USER}:${TEST_USER_PASS}"
then
    echo "Unable to add user"
    exit 1
fi

# make the user an admin
if ! rest_urlencoded POST "${url%/}/admin/mail/users/privileges/add" "${admin_auth[0]}" "${admin_auth[1]}" --insecure -- "email=$TEST_USER" "privilege=admin" 2>/dev/null
then
    echo "Unable to add 'admin' privilege. err=$REST_ERROR" 1>&2
    exit 1
fi


# enable totp

#
# Get an access token
#
miab_api_auth "$TEST_USER" "$TEST_USER_PASS" || exit 1
test_auth=( ${AUTH[@]} )

token="$(totp_current_token "$TEST_USER_TOTP_SECRET")"

if ! rest_urlencoded POST "${url%/}/admin/mfa/totp/enable" "${test_auth[0]}" "${test_auth[1]}" --insecure "secret=$TEST_USER_TOTP_SECRET" "token=$token" "label=$TEST_USER_TOTP_LABEL" 2>/dev/null; then
    echo "Unable to enable TOTP. err=$REST_ERROR" 1>&2
    exit 1
fi


exit 0

