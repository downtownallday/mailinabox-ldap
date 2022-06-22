#!/bin/bash

# Run this on a VM to pre-install all the packages, then
# take a snapshot - it will greatly speed up subsequent
# test installs

#
# What won't be installed:
#
# Nextcloud and Roundcube are downloaded with wget by the setup
# scripts, so they are not included
#
# postfix, postgrey and slapd because they require terminal input
#


if [ ! -d "setup" ]; then
    echo "Run from the miab root directory"
    exit 1
fi

source tests/lib/system.sh
source tests/lib/color-output.sh

dry_run=true

if [ "$1" == "--no-dry-run" ]; then
    dry_run=false
fi

if $dry_run; then
    echo "WARNING: dry run is TRUE, no changes will be made"
fi


# prevent apt from running needrestart(1)
export NEEDRESTART_SUSPEND=true

# what major version of ubuntu are we installing on?
OS_MAJOR=$(. /etc/os-release; echo $VERSION_ID | awk -F. '{print $1}')


remove_line_continuation() {
    local file="$1"
    awk '
BEGIN            { C=0 } 
C==1 && /[^\\]$/ { C=0; print $0; next } 
C==1             { printf("%s",substr($0,0,length($0)-1)); next } 
/\\$/            { C=1; printf("%s",substr($0,0,length($0)-1)); next } 
                 { print $0 }' \
                     "$file"
}

install_packages() {
    while read line; do
        pkgs=""
        case "$line" in
             apt_install* )
                 pkgs="$(cut -c12- <<<"$line")"
                 ;;
             "apt-get install"* )
                 pkgs="$(cut -c16- <<<"$line")"
                 ;;
             "apt install"* )
                 pkgs="$(cut -c12- <<<"$line")"
                 ;;
        esac
        
        # don't install postfix - causes problems with setup scripts
        # and requires user input. exclude postgrey because it will
        # install postfix as a dependency
        pkgs="$(sed 's/postgrey//g' <<< "$pkgs")"
        pkgs="$(sed 's/postfix-[^ $]*//g' <<<"$pkgs")"
        pkgs="$(sed 's/postfix//g' <<<"$pkgs")"

        # don't install slapd - it requires user input
        pkgs="$(sed 's/slapd//g' <<< "$pkgs")"

        # manually set PHP_VER if necessary
        if grep "PHP_VER" <<<"$pkgs" >/dev/null; then
            pkgs="$(sed "s/\${*PHP_VER}*/$PHP_VER/g" <<< "$pkgs")"
        fi

        if [ $OS_MAJOR -ge 22 ]; then
            # don't install opendmarc on ubuntu 22 and higher - it requires
            # interactive user input
            pkgs="$(sed 's/opendmarc//g' <<< "$pkgs")"
        fi
        
        if [ ! -z "$pkgs" ]; then
            H2 "install: $pkgs"
            if ! $dry_run; then
                #apt-get install -y -qq $pkgs
                exec_no_output apt-get install -y $pkgs
            fi
        fi
    done
}

install_ppas() {
    H1 "Add apt repositories"
    grep 'hide_output add-apt-repository' setup/system.sh |
        while read line; do
            line=$(sed 's/^hide_output //' <<< "$line")
            H2 "$line"
            if ! $dry_run; then
                exec_no_output $line
            fi
        done 
}


# install PPAs from sources
install_ppas

# obtain PHP_VER variable from sources
PHP_VER=$(grep "^PHP_VER=" setup/functions.sh  | awk -F= '{ print $2 }')


if ! $dry_run; then
    H1 "Upgrade system"
    H2 "apt update"
    exec_no_output apt-get update -y
    H2 "apt upgrade"
    exec_no_output apt-get upgrade -y --with-new-pkgs
    H2 "apt autoremove"
    exec_no_output apt-get autoremove -y
fi

for file in $(ls setup/*.sh); do
    H1 "$file"
    remove_line_continuation "$file" | install_packages
done

if ! $dry_run; then
    # bonus
    H1 "install extras"
    H2 "openssh-server"
    exec_no_output apt-get install -y openssh-server
    # ssh-rsa no longer a default algorithm, but still used by vagrant
    echo "PubkeyAcceptedAlgorithms +ssh-rsa" > /etc/ssh/sshd_config.d/miabldap.conf
    H2 "emacs"
    exec_no_output apt-get install -y emacs-nox
    H2 "nptdate"
    exec_no_output apt-get install -y ntpdate

    # these are added by system-setup scripts and needed for test runner
    H2 "python3-dnspython jq"
    exec_no_output apt-get install -y python3-dnspython jq

    # remove apache, which is what setup will do
    H2 "remove apache2"
    exec_no_output apt-get -y purge apache2 apache2-\*

    echo ""
    echo ""
    echo "Done. Take a snapshot...."
    echo ""
fi
