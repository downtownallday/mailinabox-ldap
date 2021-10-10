#!/bin/bash

#
# WARNING
#
# this script modifies files under git control and is intended for
# automated testing only!
#

dry_run=${1:-false}

# roundcube

modify_nginx_conf() {
    local fn="$1"
    local tmp="${2:-/tmp/nginx_modify.$$.conf}"
    local dry_run="${3:-false}"
    awk '
BEGIN                       { inblock=0 }
/location.*\/mail\/.*\.php/ { inblock=1; print; next; }
/^\s*\}\s*$/                { inblock=0; print; next; }
inblock==1 && /fastcgi_pass\s+php-fpm/ {
                              print "\t\t# setup mod: php_timeout_long";
                              print "\t\tfastcgi_read_timeout 240s;";
                              print "\t\tfastcgi_send_timeout 240s;";
                              print "\t\tfastcgi_connect_timeout 60s;";
                              print; next;
                            }
                            { print }' \
                                "$fn"> "$tmp"

    if [ $dry_run != "true" ] ; then
        # only apply if not already applied
        ! grep "php_timeout_long" "$fn" >/dev/null && cp "$tmp" "$fn"
        rm -f "$tmp"
    else
        echo "cp $tmp $fn"
    fi
}

# modify conf/nginx-alldomains.conf, which is used to rebuild
# /etc/nginx/conf.d/local.conf every time a new domain is created
modify_nginx_conf "conf/nginx-alldomains.conf" "/tmp/x1" $dry_run

# modify active nginx config
modify_nginx_conf "/etc/nginx/conf.d/local.conf" "/tmp/x2" $dry_run

# reload nginx
systemctl reload nginx || exit 1

