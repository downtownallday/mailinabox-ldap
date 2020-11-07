#!/bin/bash

#
# this mod will enable oauth2 on roundcube for testing
# .. the authentication server must be running locally
#

source setup/functions.sh # load our functions
source /etc/mailinabox.conf # load global vars

# enable test oauth2 in roundcube
RCM_DIR=/usr/local/lib/roundcubemail
CONF=${1:-$RCM_DIR/config/config.inc.php}

#
# 'session_path' below prevents leaking the roundcube session cookie
# to other web services on this box like the admin daemon and more
# importantly other pages installed in user-data/www. it tells the
# browser to only send the roundcube session cookie to urls starting
# with /mail
#
php tools/editconf.php $CONF config \
    'enable_installer' 'true' \
    'session_path' '/mail/' \
    'oauth_provider' 'miab-ldap' \
    'oauth_provider_name' 'Mail-in-a-Box LDAP' \
    'oauth_auth_uri' "https://$PRIMARY_HOSTNAME/miab-ldap/oauth/authorize" \
    'oauth_auth_parameters' "array()"  \
    'oauth_token_uri' "http://localhost:10222/oauth/token" \
    'oauth_scope' "mailbox introspect" \
    'oauth_client_id' 'roundcube' \
    'oauth_client_secret' "$(generate_password 32)" \
    'oauth_identity_uri' "http://localhost:10222/oauth/v1/introspect" \
    'oauth_identity_fields' 'array("username")' \
    'oauth_verify_peer' "true" \
    'oauth_login_redirect' "false"


# update NGINX to proxy-pass /miab-ldap/ requests to the
# management daemon

nginx_conf="/etc/nginx/conf.d/local.conf"
if ! grep -F 'location /miab-ldap/' "$nginx_conf" >/dev/null; then
    # insert additional configuration before the line containing
    # the comment "Nextcloud configuration."
    awk '/Nextcloud configuration/ { system("cat") } { print }' "$nginx_conf" >"$nginx_conf.new" <<EOF

        location /miab-ldap/oauth/ {
                proxy_pass http://127.0.0.1:10222/oauth/;
                proxy_set_header  X-Forwarded-For \$proxy_add_x_forwarded_for;
                add_header X-Frame-Options "DENY";
                add_header X-Content-Type-Options nosniff;
                add_header Content-Security-Policy "frame-ancestors 'none';";
        }

        location /miab-ldap/user/ {
                proxy_pass http://127.0.0.1:10222/user/;
                proxy_set_header  X-Forwarded-For \$proxy_add_x_forwarded_for;
                add_header X-Frame-Options "DENY";
                add_header X-Content-Type-Options nosniff;
                add_header Content-Security-Policy "frame-ancestors 'none';";
        }

        # Below is a temporary workaround to get Roundcube OAuth2
        # redirect_ui working without roundcube code changes

        location ~ /index.php/login/oauth {
                 set \$args '_task=login&_action=oauth&\$args';
                 rewrite .* /mail/ permanent;
        }
        location ~ ^/\$ {
                if (\$args = "_task=mail") {
                    set \$args '';
                    rewrite .* /mail/ permanent;
                }
        }

EOF

    rm -f "$nginx_conf"
    mv "$nginx_conf.new" "$nginx_conf"
    systemctl restart nginx
    
fi
