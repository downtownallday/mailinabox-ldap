#!/bin/bash
# -*- indent-tabs-mode: t; tab-width: 4; -*-
#####
##### This file is part of Mail-in-a-Box-LDAP which is released under the
##### terms of the GNU Affero General Public License as published by the
##### Free Software Foundation, either version 3 of the License, or (at
##### your option) any later version. See file LICENSE or go to
##### https://github.com/downtownallday/mailinabox-ldap for full license
##### details.
#####

# Turn on "strict mode." See http://redsymbol.net/articles/unofficial-bash-strict-mode/.
# -e: exit if any command unexpectedly fails.
# -u: exit if we have a variable typo.
# -o pipefail: don't ignore errors in the non-last command in a pipeline
set -euo pipefail

PHP_VER=8.0

# ansi escapes for hilighting text
F_DANGER=$(echo -e "\033[31m")
F_WARN=$(echo -e "\033[93m")
F_SUCCESS=$(echo -e "\033[32m")
F_RESET=$(echo -e "\033[39m")

function hide_output {
	# This function hides the output of a command unless the command fails
	# and returns a non-zero exit code.

	# Get a temporary file.
	OUTPUT=$(mktemp)

	# Execute command, redirecting stderr/stdout to the temporary file. Since we
	# check the return code ourselves, disable 'set -e' temporarily.
	set +e
	"$@" &> "$OUTPUT"
	E=$?
	set -e

	# If the command failed, show the output that was captured in the temporary file.
	if [ $E != 0 ]; then
		# Something failed.
		echo
		echo "FAILED: $*"
		echo -----------------------------------------
		cat "$OUTPUT"
		echo -----------------------------------------
		exit $E
	fi

	# Remove temporary file.
	rm -f "$OUTPUT"
}

function wait_for_apt_lock {
	# check to see if other package managers have a lock on new
	# installs, and wait for them to finish
	local count=0
	while fuser /var/lib/dpkg/lock >/dev/null 2>&1 || fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do
		if [ $count -eq 0 ]; then
			echo "Waiting for apt to become unlocked..."
		fi
		sleep 6
		let count+=1
		if [ $count -gt 100 ]; then
			echo "Timeout waiting for apt to become unlocked - another process may be using it"
			break
		fi
	done
	return 0
}

function apt_get_quiet {
	# Run apt-get in a totally non-interactive mode.
	#
	# Somehow all of these options are needed to get it to not ask the user
	# questions about a) whether to proceed (-y), b) package options (noninteractive),
	# and c) what to do about files changed locally (we don't cause that to happen but
	# some VM providers muck with their images; -o).
	#
	# Although we could pass -qq to apt-get to make output quieter, many packages write to stdout
	# and stderr things that aren't really important. Use our hide_output function to capture
	# all of that and only show it if there is a problem (i.e. if apt_get returns a failure exit status).
	wait_for_apt_lock
	DEBIAN_FRONTEND=noninteractive hide_output apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confnew" "$@"
}

function apt_install {
	# Install a bunch of packages. We used to report which packages were already
	# installed and which needed installing, before just running an 'apt-get
	# install' for all of the packages.  Calling `dpkg` on each package is slow,
	# and doesn't affect what we actually do, except in the messages, so let's
	# not do that anymore.
	apt_get_quiet install "$@"
}

function get_default_hostname {
	# Guess the machine's hostname. It should be a fully qualified
	# domain name suitable for DNS. None of these calls may provide
	# the right value, but it's the best guess we can make.
	set -- "$(hostname --fqdn      2>/dev/null ||
                 hostname --all-fqdns 2>/dev/null ||
                 hostname             2>/dev/null)"
	printf '%s\n' "$1" # return this value
}

function get_publicip_from_web_service {
	# This seems to be the most reliable way to determine the
	# machine's public IP address: asking a very nice web API
	# for how they see us. Thanks go out to icanhazip.com.
	# See: https://major.io/icanhazip-com-faq/
	#
	# Pass '4' or '6' as an argument to this function to specify
	# what type of address to get (IPv4, IPv6).
	curl -"$1" --fail --silent --max-time 15 icanhazip.com 2>/dev/null || /bin/true
}

function get_default_privateip {
	# Return the IP address of the network interface connected
	# to the Internet.
	#
	# Pass '4' or '6' as an argument to this function to specify
	# what type of address to get (IPv4, IPv6).
	#
	# We used to use `hostname -I` and then filter for either
	# IPv4 or IPv6 addresses. However if there are multiple
	# network interfaces on the machine, not all may be for
	# reaching the Internet.
	#
	# Instead use `ip route get` which asks the kernel to use
	# the system's routes to select which interface would be
	# used to reach a public address. We'll use 8.8.8.8 as
	# the destination. It happens to be Google Public DNS, but
	# no connection is made. We're just seeing how the box
	# would connect to it. There many be multiple IP addresses
	# assigned to an interface. `ip route get` reports the
	# preferred. That's good enough for us. See issue #121.
	#
	# With IPv6, the best route may be via an interface that
	# only has a link-local address (fe80::*). These addresses
	# are only unique to an interface and so need an explicit
	# interface specification in order to use them with bind().
	# In these cases, we append "%interface" to the address.
	# See the Notes section in the man page for getaddrinfo and
	# https://discourse.mailinabox.email/t/update-broke-mailinabox/34/9.
	#
	# Also see ae67409603c49b7fa73c227449264ddd10aae6a9 and
	# issue #3 for why/how we originally added IPv6.

	target=8.8.8.8

	# For the IPv6 route, use the corresponding IPv6 address
	# of Google Public DNS. Again, it doesn't matter so long
	# as it's an address on the public Internet.
	if [ "$1" == "6" ]; then target=2001:4860:4860::8888; fi

	# Get the route information.
	route=$(ip -"$1" -o route get $target 2>/dev/null | grep -v unreachable)

	# Parse the address out of the route information.
	address=$(echo "$route" | sed "s/.* src \([^ ]*\).*/\1/")

	if [[ "$1" == "6" && $address == fe80:* ]]; then
		# For IPv6 link-local addresses, parse the interface out
		# of the route information and append it with a '%'.
		interface=$(echo "$route" | sed "s/.* dev \([^ ]*\).*/\1/")
		address=$address%$interface
	fi

	echo "$address"
}

function ufw_allow {
	if [ -z "${DISABLE_FIREWALL:-}" ]; then
		# ufw has completely unhelpful output
		ufw allow "$1" > /dev/null;
	fi
}

function ufw_limit {
	if [ -z "${DISABLE_FIREWALL:-}" ]; then
		# ufw has completely unhelpful output
		ufw limit "$1" > /dev/null;
	fi
}

function restart_service {
	hide_output service "$1" restart
}

## Dialog Functions ##
function message_box {
	dialog --title "$1" --msgbox "$2" 0 0
}

function input_box {
	# input_box "title" "prompt" "defaultvalue" VARIABLE
	# The user's input will be stored in the variable VARIABLE.
	# The exit code from dialog will be stored in VARIABLE_EXITCODE.
	# Temporarily turn off 'set -e' because we need the dialog return code.
	declare -n result=$4
	declare -n result_code=$4_EXITCODE
	set +e
	result=$(dialog --stdout --title "$1" --inputbox "$2" 0 0 "$3")
	result_code=$?
	set -e
}

function input_menu {
	# input_menu "title" "prompt" "tag item tag item" VARIABLE
	# The user's input will be stored in the variable VARIABLE.
	# The exit code from dialog will be stored in VARIABLE_EXITCODE.
	declare -n result=$4
	declare -n result_code=$4_EXITCODE
	local IFS=^$'\n'
	set +e
	result=$(dialog --stdout --title "$1" --menu "$2" 0 0 0 "$3")
	result_code=$?
	set -e
}

function wget_verify {
	# Downloads a file from the web and checks that it matches
	# a provided hash. If the comparison fails, exit immediately.
	URL=$1
	HASH=$2
	DEST=$3
	CHECKSUM="$HASH  $DEST"
	rm -f "$DEST"
	hide_output wget --compression=auto -O "$DEST" "$URL"
	if ! echo "$CHECKSUM" | sha1sum --check --strict > /dev/null; then
		echo "------------------------------------------------------------"
		echo "Download of $URL did not match expected checksum."
		echo "Found:"
		sha1sum "$DEST"
		echo
		echo "Expected:"
		echo "$CHECKSUM"
		rm -f "$DEST"
		exit 1
	fi
}

function git_clone {
	# Clones a git repository, checks out a particular commit or tag,
	# and moves the repository (or a subdirectory in it) to some path.
	# We use separate clone and checkout because -b only supports tags
	# and branches, but we sometimes want to reference a commit hash
	# directly when the repo doesn't provide a tag.
	REPO=$1
	TREEISH=$2
	SUBDIR=$3
	TARGETPATH=$4
	TMPPATH=/tmp/git-clone-$$
	rm -rf $TMPPATH "$TARGETPATH"
	git clone -q "$REPO" $TMPPATH || exit 1
	(cd $TMPPATH; git checkout -q "$TREEISH";) || exit 1
	mv $TMPPATH/"$SUBDIR" "$TARGETPATH"
	rm -rf $TMPPATH
}

function generate_password() {
	# output a randomly generated password of the length specified as
	# the first argument. If no length is given, a password of 64
	# characters is generated.
	#
	# The actual returned password may be longer than requested to
	# avoid base64 padding characters
	#
	local input_len extra pw_length="${1:-64}"
	# choose a length (longer) that will avoid padding chars
	let extra="4 - $pw_length % 4"
	[ $extra -eq 4 ] && extra=0
	let input_len="($pw_length + $extra) / 4 * 3"
	# change forward slash to comma because forward slash causes problems
	# when used in regular expressions (for instance sed) or curl using
	# basic auth supplied in the url (https://user:pass@host)
	dd if=/dev/urandom bs=1 count=$input_len 2>/dev/null | base64 --wrap=0 | awk '{ gsub("/", ",", $0); print $0}'
}

function kernel_ipv6_lo_disabled() {
	# Returns 0 if ipv6 is disabled on the loopback adapter
	local v="$(sysctl -n net.ipv6.conf.lo.disable_ipv6)"
	[ "$v" == "1" ] && return 0
	return 1
}


declare -i verbose=${verbose:-0}

while [ $# -gt 0 ]; do
	if [ "$1" == "-verbose" -o "$1" == "-v" ]; then
		let verbose+=1
		shift
	else
		break
	fi
done

die() {
	local msg="${1:-}"
	local rtn="${2:-1}"
	[ ! -z "$msg" ] && echo "FATAL: $msg" || \
			echo "An unrecoverable error occurred, exiting"
	exit $rtn
}

is_verbose() {
    [ $verbose -gt 0 ] && return 0
    return 1
}

say_debug() {
	[ $verbose -gt 1 ] && echo "$@"
	return 0
}

say_verbose() {
	[ $verbose -gt 0 ] && echo "$@"
	return 0
}

say() {
	echo "$@"
}

wait_for_management_daemon() {
	local progress="${1:-progress}" # show progress? "progress"/"no-progress"
	local max_wait="${2:-60}" # seconds, 0=forever
	local start="$(date +%s)"
	local elapsed=0 now
	[ "$max_wait" = "forever" ] && max_wait=0

	# Wait for the management daemon to start...
	until nc -z -w 4 127.0.0.1 10222
	do
		now="$(date +%s)"
		# let returns 1 if the equasion evaluates to zero, which will
		# cause the script to exit because of set -e. add one.
		[ $now -eq $start ] && let now+=1
		let elapsed="$now - $start"
		if [ $max_wait -ne 0 -a $elapsed -gt $max_wait ]; then
			echo "Timeout waiting for Mail-in-a-Box management daemon to start"
			return 1
		fi
		if [ "$progress" = "progress" ]; then
			echo "Waiting for the Mail-in-a-Box management daemon to start..."
		fi
		sleep 2
	done
}

install_hook_handler() {
	# this is used by local setup mods to install a hook handler for
	# the management daemon. source /etc/mailinabox.conf before
	# calling
	local handler_file="$1"
	local dst="${LOCAL_MODS_DIR:-local}/management_hooks_d"
	if [ ! -d "$dst" -o -e "$dst/$(basename "$handler_file")" ]; then
		mkdir -p "$dst"
		cp "$handler_file" "$dst"
		if systemctl is-active --quiet mailinabox; then
			systemctl restart mailinabox
			wait_for_management_daemon no-progress
		fi
	else
		cp "$handler_file" "$dst"
		# let the daemon know there's a new hook handler
		if systemctl is-active --quiet mailinabox; then
			tools/hooks_update >/dev/null
		fi
	fi
}

remove_hook_handler() {
	# source /etc/mailinabox.conf before calling
	local hook_py=$(basename "$1")
	local dst="${LOCAL_MODS_DIR:-local}/management_hooks_d/$hook_py"
	if [ -e "$dst" ]; then
		rm -f "$dst"
		# let the daemon know installed hooks have been updated
		if systemctl is-active --quiet mailinabox; then
			tools/hooks_update >/dev/null
		fi
	fi
}
