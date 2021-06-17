#!/bin/bash

source setup/functions.sh # load our functions
source /etc/mailinabox.conf # load global vars

# see instructions at:
#  https://doc.dovecot.org/installation_guide/dovecot_community_repositories/ubuntu_packages/

if version_greater_equal "$(/usr/sbin/dovecot --version)" "2.3.11"
then
    echo "Already at dovecot 2.3"
    exit 0
fi

source /etc/os-release
if [ "$VERSION_CODENAME" != "bionic" ]; then
    echo "This script only works on Ubuntu bionic!"
    exit 1
fi

curl -s https://repo.dovecot.org/DOVECOT-REPO-GPG | gpg --import -q
gpg --export ED409DA1 > /etc/apt/trusted.gpg.d/dovecot.gpg

apt-add-repository -y 'deb https://repo.dovecot.org/ce-2.3-latest/ubuntu/bionic bionic main'
apt-get update
apt_install dovecot-core

# re-run affected portions of setup
setup/mail-dovecot.sh
setup/mail-users.sh
setup/spamassassin.sh
