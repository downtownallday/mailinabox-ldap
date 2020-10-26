#!/bin/bash

#
# this mod will enable dovecot debugging output to stdout
#
# run dovecot in interactive mode with 'dovecot -F' to see the output
#

source setup/functions.sh # load our functions
source /etc/mailinabox.conf # load global vars

tools/editconf.py \
    /etc/dovecot/dovecot.conf \
    auth_verbose=yes \
    auth_debug=yes \
    auth_debug_passwords=yes \
    mail_debug=yes \
    verbose_ssl=no \
    auth_verbose_passwords=plain \
    log_path=/dev/stdout

echo "DOVECOT debug logging to stdout turned on -- use interactive 'dovecot -F'"
