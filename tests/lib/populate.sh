
#
# requires:
#   system packages: [ jq ]
#   scripts: [ rest.sh, misc.sh ]
#

miab_supports() {
    local what="$1"     # "oauth"
    local url="${2:-}"
    
    if [ "$what" = "oauth" -o "$what" = "oauth2" ]; then
        # see if /auth/oauth/authorize "works"
        rest_urlencoded HEAD ${url%/}/auth/oauth/authorize "" "" --insecure 2>/dev/null
        if [ "$REST_HTTP_CODE" = "200" ]; then
            return 0
        else
            return 1
        fi
    else
        echo "WARNING: invalid option to miab_supports '$what'" 1>&2
        return 1
    fi
}

miab_access_token() {
    # obtain an access token - supplied account must be an admin
    #
    # requires jq be installed in the path
    #
    # returns 1 if unsuccessful and REST_HTTP_CODE contains the
    # server's response http status along with REST_ERROR, which
    # contains an error message
    #
    # returns 0 if successful and ACCESS_TOKEN is populated
    local url="$1"          # may be "" for url based on PRIMARY_HOSTNAME
    local admin_email="${2:-$EMAIL_ADDR}"
    local admin_pass="${3:-$EMAIL_PW}"
    local second_factor="${4:-}"
    local second_factor_type="${5:-totp}"

    local curl_args=()
    if [ ! -z "$second_factor" ]; then
        if [ "$second_factor_type" = "totp" ]; then
            curl_args+=("--header=X-Auth-Token: $second_factor")
        else
            echo "Invalid second factor type '$second_factor_type'" 1>&2
            return 1
        fi
    fi

    local client_id="miabldap-cli"
    local client_pw="miabldap-cli"
    rest_urlencoded \
        POST \
        "${url%/}/auth/oauth/token" \
        "$client_id" \
        "$client_pw" \
        "${curl_args[@]}" \
        "grant_type=password" \
	    "username=$admin_email" \
		"password=$admin_pass" \
		"scope=miabldap-console" 2>/dev/null
    local code=$?
    if [ $code -ne 0 ]; then
        return 1
    fi

    ACCESS_TOKEN=$(jq -r .access_token <<<"$REST_OUTPUT")
    return 0
}

miab_api_auth() {
    # return an array of (user_auth user_pw)
    # user_auth and user_pw should be used for authentication
    # returns 0 if successful and AUTH is set to the array
    # returns 1 if failed and error messages reported to stdout
    #
    # the supplied user must have admin rights
    local u="$1"
    local pw="$2"
    if miab_supports "oauth"; then
        if ! miab_access_token "" "$u" "$pw"; then
            echo "Error getting access token: $REST_ERROR"
            return 1
        fi
        AUTH=("Bearer" "$ACCESS_TOKEN")
    else
        AUTH=("$u" "$pw")
    fi
    return 0
}



populate_miab_users() {
    local url="$1"
    local admin_email="${2:-$EMAIL_ADDR}"  # or "Bearer"
    local admin_pass="${3:-$EMAIL_PW}"     # or an access token
    shift; shift; shift  # remaining arguments are users to add

    # each "user" argument is in the format "email:password"
    # if no password is given a "qa" password will be generated

    [ $# -eq 0 ] && return 0
    
    #
    # get the existing users
    #
    local current_users=() user
    if ! rest_urlencoded GET ${url%/}/admin/mail/users "$admin_email" "$admin_pass" --insecure 2>/dev/null; then
        echo "Unable to enumerate users: rc=$? err=$REST_ERROR" 1>&2
        return 1
    fi
    for user in $REST_OUTPUT; do
        current_users+=("$user")
    done

    #
    # add the new users
    #
    local pw="$(generate_qa_password)"
    
    for user; do
        local user_email="$(awk -F: '{print $1}' <<< "$user")"
        local user_pass="$(awk -F: '{print $2}' <<< "$user")"
        if array_contains "$user_email" "${current_users[@]}"; then
            echo "Not adding user $user_email: already exists"

        elif ! rest_urlencoded POST ${url%/}/admin/mail/users/add "$admin_email" "$admin_pass" --insecure -- "email=$user_email" "password=${user_pass:-$pw}" 2>/dev/null
        then
            echo "Unable to add user $user_email: rc=$? err=$REST_ERROR" 1>&2
            return 2
        else
            echo "Add: $user"
        fi
    done

    return 0
}



populate_miab_aliases() {
    local url="$1"
    local admin_email="${2:-$EMAIL_ADDR}"  # or "Bearer"
    local admin_pass="${3:-$EMAIL_PW}"     # or an access token
    shift; shift; shift  # remaining arguments are aliases to add

    # each "alias" argument is in the format "email-alias > forward-to"

    [ $# -eq 0 ] && return 0
    
    #
    # get the existing aliases
    #
    local current_aliases=() alias
    if ! rest_urlencoded GET ${url%/}/admin/mail/aliases "$admin_email" "$admin_pass" --insecure 2>/dev/null; then
        echo "Unable to enumerate aliases: rc=$? err=$REST_ERROR" 1>&2
        return 1
    fi
    for alias in $REST_OUTPUT; do
        current_aliases+=("$alias")
    done

    #
    # add the new aliases
    #
    local aliasdef
    for aliasdef; do
        alias="$(awk -F'[> ]' '{print $1}' <<<"$aliasdef")"
        local forwards_to="$(sed 's/.*> *\(.*\)/\1/' <<<"$aliasdef")"
        if array_contains "$alias" "${current_aliases[@]}"; then
            echo "Not adding alias $aliasdef: already exists"
            
        elif ! rest_urlencoded POST ${url%/}/admin/mail/aliases/add "$admin_email" "$admin_pass" --insecure -- "address=$alias" "forwards_to=$forwards_to" 2>/dev/null
        then
            echo "Unable to add alias $alias: rc=$? err=$REST_ERROR" 1>&2
            return 2
        else
            echo "Add: $aliasdef"
        fi
    done

    return 0
}


