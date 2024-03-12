# -*- indent-tabs-mode: t; tab-width: 4; python-indent-offset: 4; -*-
#####
##### This file is part of Mail-in-a-Box-LDAP which is released under the
##### terms of the GNU Affero General Public License as published by the
##### Free Software Foundation, either version 3 of the License, or (at
##### your option) any later version. See file LICENSE or go to
##### https://github.com/downtownallday/mailinabox-ldap for full license
##### details.
#####


from mailconfig import open_database, find_mail_user
import mfa_totp

def strip_order_prefix(rec, attributes):
	'''strip the order prefix from X-ORDERED ldap values for the
	list of attributes specified

    `rec` is modified in-place

	the server returns X-ORDERED values ordered so the values will be
	sorted in the record making the prefix superfluous.

	For example, the function will change:
       totpSecret: {0}secret1
       totpSecret: {1}secret2
    to:
	   totpSecret: secret1
       totpSecret: secret2

	TODO: move to backend.py and/or integrate with LdapConnection.search()
	'''
	for attr in attributes:
		# ignore attribute that doesn't exist
		if not attr in rec: continue
		# ..as well as None values and empty list
		if not rec[attr]: continue

		newvals = []
		for val in rec[attr]:
			i = val.find('}')
			newvals.append(val[i+1:])
		rec[attr] = newvals

def get_mfa_user(email, env, conn=None):
	'''get the ldap record for the user along with all MFA-related
	attributes

	'''
	user = find_mail_user(env, email, ['objectClass','totpSecret','totpMruToken','totpMruTokenTime','totpLabel'], conn)
	if not user:
		raise ValueError("User does not exist.")
	strip_order_prefix(user, ['totpSecret','totpMruToken','totpMruTokenTime','totpLabel'])
	return user



def get_mfa_state(email, env):
	'''return details about what MFA schemes are enabled for a user
	ordered by the priority that the scheme will be tried, with index
	zero being the first.

	'''
	user = get_mfa_user(email, env)
	state_list = []
	state_list += mfa_totp.get_state(user)
	return state_list

def get_public_mfa_state(email, env):
	'''return details about what MFA schemes are enabled for a user
	ordered by the priority that the scheme will be tried, with index
	zero being the first. No secrets are returned by this function -
	only those details that are needed by the end user to identify a
	particular MFA by label and the id of each so it may be disabled.

	'''
	mfa_state = get_mfa_state(email, env)
	return [
		{ "id": s["id"], "type": s["type"], "label": s["label"] }
		for s in mfa_state
	]

def get_hash_mfa_state(email, env):
	'''return details about what MFA schemes are enabled for a user
	ordered by the priority that the scheme will be tried, with index
	zero being the first. This function may return secrets. It's
	intended use is for the result to be included as part of the input
	to a hashing function to generate a user api key (see
	auth.py:create_user_key)

	'''
	mfa_state = get_mfa_state(email, env)
	return [
		{ "id": s["id"], "type": s["type"], "secret": s["secret"] }
		for s in mfa_state
	]

def enable_mfa(email, type, secret, token, label, env):
	'''enable MFA using the scheme specified in `type`. users may have
multiple mfa schemes enabled of the same type.

	'''
	user = get_mfa_user(email, env)
	if type == "totp":
		mfa_totp.enable(user, secret, token, label, env)
	else:
		msg = "Invalid MFA type."
		raise ValueError(msg)

def disable_mfa(email, mfa_id, env):
	'''disable a specific MFA scheme. `mfa_id` identifies the specific
	entry and is available in the `id` field of an item in the list
	obtained from get_mfa_state()

	'''
	user = get_mfa_user(email, env)
	if mfa_id is None:
		# Disable all MFA for a user.
		return mfa_totp.disable(user, None, env)
	elif mfa_id.startswith("totp:"):
		# Disable a particular MFA mode for a user.
		return mfa_totp.disable(user, mfa_id, env)
	else:
		return False

def validate_auth_mfa(email, request, env):
	# Validates that a login request satisfies any MFA modes
	# that have been enabled for the user's account. Returns
	# a tuple (status, [hints]). status is True for a successful
	# MFA login, False for a missing token. If status is False,
	# hints is an array of codes that indicate what the user
	# can try. Possible codes are:
	# "missing-totp-token"
	# "invalid-totp-token"

	mfa_state = get_mfa_state(email, env)

	# If no MFA modes are added, return True.
	if len(mfa_state) == 0:
		return (True, [])

	# Try the enabled MFA modes.
	hints = set()
	for mfa_mode in mfa_state:
		if mfa_mode["type"] == "totp":
			user = get_mfa_user(email, env)
			result, hint = mfa_totp.validate_auth(user, mfa_mode, request, True, env)
			if not result:
				hints.add(hint)
			else:
				return (True, [])

	# On a failed login, indicate failure and any hints for what the user can do instead.
	return (False, list(hints))
