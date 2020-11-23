#!/bin/bash

# Set up oauth JWT signing keys
#
# Must be run after management.sh, because it depends on managment's
# python3 isolated environment
#
# Signing keys may be regenerated/rotated at any time by running this
# script. New keys do not require a restart of the management daemon
# or dovecot
#

source setup/functions.sh
source /etc/mailinabox.conf # load global vars

PYTHON="/usr/local/lib/mailinabox/env/bin/python3"
STORAGE_OAUTH_ROOT="$STORAGE_ROOT/authorization_server"

# even though dovecot documentation says it supports HS512, dovecot
# core dumps when using it on dovecot 2.3.11
#
# "Nov 23 16:03:26 auth: Panic: file hmac.c: line 26 (hmac_init): assertion failed: (meth->context_size <= HMAC_MAX_CONTEXT_SIZE)"
#
# using HS384 doesn't seem to do anything (just a failed login). only
# HS256 works
bits=256

# generate a RFC7515 JSON Web Key for signing JWTs. we choose the
# "HS512" algorithm (HMAC using SHA-512) because HMAC's are small
# and fast, plus dovecot is local so it's easy to share the secret

# use unix time as the key-id
kid=$(date +%s)

# generate the key
k_b64_compact=$($PYTHON -c "import authlib.jose as jose; k=jose.JsonWebKey().generate_key('oct',${bits},is_private=True); print(k['k'])")

# authlib key generation uses the compact url-safe base64
# variant. dovecot (as of 2.3.11) doesn't accept it, so get the
# standard base64 representation for dovecot's validation dictionary
k_b64=$($PYTHON -c "from authlib.common.encoding import urlsafe_b64decode; import base64; raw=urlsafe_b64decode(b'$k_b64_compact'); print(base64.b64encode(raw).decode('utf-8'));")

# create the "keys" directory
mkdir -p "$STORAGE_OAUTH_ROOT/keys"
    
# Set the umask so the key file is never world-readable
(umask 037;
 cat > "$STORAGE_OAUTH_ROOT/keys/jwt_signing_key-$kid.json" <<EOF
{
  "kty": "oct",
  "alg": "HS${bits}",
  "kid": "$kid",
  "k": "$k_b64_compact"
}
EOF
)

# Symlink to the active key
ln -sf jwt_signing_key-$kid.json "$STORAGE_OAUTH_ROOT/keys/jwt_signing_key.json"

# Add the validation key to dovecot's OAuth JWT validation dictionary
azp="roundcube"  # "authorized party" (must match "azp" in token claims)
mkdir -p "$STORAGE_OAUTH_ROOT/dovecot/$azp/HS${bits}"
echo -n "$k_b64" > "$STORAGE_OAUTH_ROOT/dovecot/$azp/HS${bits}/$kid"

# Age off dovecot validation keys older than 10 days. A new
# validation/signing key was just created and new tokens will be
# singed by it. We want to honor tokens that have already been created
# with older keys, but not forever. It's safer to put a time boundry
# on the rotated keys.

find "$STORAGE_OAUTH_ROOT/dovecot" -type f -mtime 10 -exec rm {} \;

