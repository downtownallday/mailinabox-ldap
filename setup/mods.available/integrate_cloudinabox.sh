#!/bin/bash

source setup/functions.sh # load our functions
source /etc/mailinabox.conf # load global vars

touch /etc/mailinabox_integrations.conf
. /etc/mailinabox_integrations.conf

RCM_DIR=/usr/local/lib/roundcubemail
RCM_PLUGIN_DIR=${RCM_DIR}/plugins


configure_zpush() {
    # have zpush use cloudinabox's nextcloud for carddav/caldav
    # instead of the nextcloud that comes with mail-in-a-box
    local nc_host="${1:-}"
    local nc_prefix="${2:-/cloud}"
    [ "$nc_prefix" == "/" ] && nc_prefix=""
    
    # Configure CardDav
    if [ ! -z "$nc_host" ]
    then
        cp local/conf/zpush/backend_carddav.php /usr/local/lib/z-push/backend/carddav/config.php
        cp local/conf/zpush/backend_caldav.php /usr/local/lib/z-push/backend/caldav/config.php
        sed -i "s/127\.0\.0\.1/$nc_host/g" /usr/local/lib/z-push/backend/carddav/config.php
        sed -i "s^NC_PREFIX^$nc_prefix^g" /usr/local/lib/z-push/backend/carddav/config.php
        sed -i "s/127\.0\.0\.1/$nc_host/g" /usr/local/lib/z-push/backend/caldav/config.php
        sed -i "s^NC_PREFIX^$nc_prefix^g" /usr/local/lib/z-push/backend/caldav/config.php
    fi
}


configure_roundcube() {
    # replace the plugin configuration from the default Mail-In-A-Box
    # (see webmail.sh)
    local name="${1:-ownCloud}"
    local nc_host="${1:-$PRIMARY_HOSTNAME}"
    local nc_prefix="${2:-/cloud}"
    [ "$nc_prefix" == "/" ] && nc_prefix=""
    
    # Configure CardDav
    cat > ${RCM_PLUGIN_DIR}/carddav/config.inc.php <<EOF
<?php
/* Do not edit. Written by Mail-in-a-Box integrations. Regenerated on updates. */
\$prefs['_GLOBAL']['hide_preferences'] = true;
\$prefs['_GLOBAL']['suppress_version_warning'] = true;
\$prefs['cloud'] = array(
	 'name'         =>  '$name',
	 'username'     =>  '%u', // login username
	 'password'     =>  '%p', // login password
	 'url'          =>  'https://${nc_host}${nc_prefix}/remote.php/carddav/addressbooks/%u/contacts',
	 'active'       =>  true,
	 'readonly'     =>  false,
	 'refresh_time' => '02:00:00',
	 'fixed'        =>  array('username','password'),
	 'preemptive_auth' => '1',
	 'hide'        =>  false,
);
?>
EOF
}


disable_miab_nextcloud() {
    local nc_host="$1"
    local nc_prefix="$2"

    echo "Disabling miab's nextcloud in favor of ${nc_host}${nc_prefix}"

    # configure roundcube contacts
    configure_roundcube "$nc_host" "$nc_prefix"
    
    # configure zpush (which links to contacts & calendar)
    configure_zpush "$nc_host" "$nc_prefix"

    # prevent nginx from serving any miab-installed nextcloud files
    chmod 000 /usr/local/lib/owncloud
}


remote_cloudinabox_handler() {
    echo ""
    echo "What is the hostname of your cloud-in-a-box? "
    local ans_hostname
    if [ -z "${CLOUDINABOX_HOSTNAME:-}" ]; then
        read -p "[leave blank to skip] " ans_hostname
        [ -z "$ans_hostname" ] && return 0
    else
        read -p "Enter \"none\" to disable [$CLOUDINABOX_HOSTNAME] " ans_hostname
        if [ -z "$ans_hostname" ]; then
            ans_hostname="$CLOUDINABOX_HOSTNAME"
            
        elif [ "$ans_hostname" == "none" ]; then
            ans_hostname=""
        fi
    fi

    if [ ! -z "$ans_hostname" ]; then
        disable_miab_nextcloud "$ans_hostname" "/"
    fi
    
    if [ "$ans_hostname" != "${CLOUDINABOX_HOSTNAME:-}" ]; then
        CLOUDINABOX_HOSTNAME="$ans_hostname"
        tools/editconf.py /etc/mailinabox_integrations.conf \
                          "CLOUDINABOX_HOSTNAME=$ans_hostname"
    fi
}


remote_cloudinabox_handler
