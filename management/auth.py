# -*- indent-tabs-mode: t; tab-width: 4; python-indent-offset: 4; -*-
import base64, os, os.path, hmac, json
import logging

from flask import make_response

import utils
from mailconfig import validate_login, get_mail_password, get_mail_user_privileges
from mfa import get_hash_mfa_state, validate_auth_mfa
from auth_oauth import (
	decode_and_validate_jwt,
	ExpiredTokenError
)

log = logging.getLogger(__name__)


DEFAULT_KEY_PATH   = '/var/lib/mailinabox/api.key'
DEFAULT_AUTH_REALM = 'Mail-in-a-Box Management Server'

class KeyAuthService:
	"""Generate an API key for authenticating clients

	Clients must read the key from the key file and send the key with all HTTP
	requests. The key is passed as the username field in the standard HTTP
	Basic Auth header.
	"""
	def __init__(self):
		self.auth_realm = DEFAULT_AUTH_REALM
		self.key = self._generate_key()
		self.key_path = DEFAULT_KEY_PATH

	def write_key(self):
		"""Write key to file so authorized clients can get the key

		The key file is created with mode 0640 so that additional users can be
		authorized to access the API by granting group/ACL read permissions on
		the key file.
		"""
		def create_file_with_mode(path, mode):
			# Based on answer by A-B-B: http://stackoverflow.com/a/15015748
			old_umask = os.umask(0)
			try:
				return os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT, mode), 'w')
			finally:
				os.umask(old_umask)

		os.makedirs(os.path.dirname(self.key_path), exist_ok=True)

		with create_file_with_mode(self.key_path, 0o640) as key_file:
			key_file.write(self.key + '\n')
				
	def authenticate(self, request, env, oauth_config, leeway=0):
		"""Test if the client key passed in HTTP Authorization header matches the service key
		or if the or username/password passed in the header matches an administrator user.
		Returns a tuple of the user's email address and list of user privileges (e.g.
		('my@email', []) or ('my@email', ['admin']); raises a ValueError on login failure.
		If the user used an API key, the user's email is returned as None."""

		def parse_authorization_header(header):
			if not header:
				raise ValueError("No authorization header provided.")
			if " " not in header:
				raise ValueError("Authorization header invalid.")
			scheme, value = header.split(maxsplit=1)
			return {
				'scheme': scheme,
				'value': value
			}

		def decode(s):
			return base64.b64decode(s.encode('ascii')).decode('ascii')

		def parse_basic_auth(basic_auth_credentials):
			credentials = decode(basic_auth_credentials)
			if ":" not in credentials:
				return None, None
			username, password = credentials.split(':', maxsplit=1)
			return username, password

		# credentials may come from the "Authorization" header or from
		# the cookie "auth-bearer"
		if request.headers.get('Authorization') is not None:
			header = parse_authorization_header(
				request.headers.get('Authorization')
			)
		elif 'auth-bearer' in request.cookies:
			header = parse_authorization_header(
				'Bearer ' + request.cookies['auth-bearer']
			)
		else:
			raise ValueError("No authorization provided.")
		
		result = {
			'scheme': header['scheme']
		}
		
		if header['scheme'] == 'Basic':
			username, password = parse_basic_auth(header['value'])
			if username in (None, ""):
				raise ValueError("Authorization header invalid.")
			elif username == self.key:
				# The user passed the master API key which grants administrative privs.
				result.update({
					'user_id': None,
					'privs': ["admin"]
				})
			
			else:
				# The user is trying to log in with a username and either a password
				# (and possibly a MFA token) or a user-specific API key.
				result.update({
					'user_id': username,
					'privs': self.check_user_auth(username, password, request, env)
				})
		
		elif header['scheme'] == 'Bearer':
			try:
				claims = decode_and_validate_jwt(
					oauth_config,
					header['value'],
					leeway
				)
				result.update({
					'user_id': claims['sub'],
					'privs': claims['privs'],
					'bearer_token': header['value'],
					'claims': claims,
				})
			except Exception as e:
				log.warning(
					'Could not verify jwt: %s: %s', 
					str(e), 
					header['value']
				)
				raise ValueError("Bearer token validation failed.") from e
			
		else:
			raise ValueError("Unknown authorization scheme")	

		log.debug("auth succeeded: %s", result, {
			"username": result["user_id"]
		})
		return result

	def check_user_auth(self, email, pw, request, env):
		# Validate a user's login email address and password. If MFA is enabled,
		# check the MFA token in the X-Auth-Token header.
		#
		# On success returns a list of privileges (e.g. [] or ['admin']). On login
		# failure, raises a ValueError with a login error message.

		# Sanity check.
		if email == "" or pw == "":
			raise ValueError("Enter an email address and password.")

		# The password might be a user-specific API key. create_user_key raises
		# a ValueError if the user does not exist.
		if hmac.compare_digest(self.create_user_key(email, env), pw):
			# OK.
			pass
		else:
			# Get the hashed password of the user. Raise a ValueError if the
			# email address does not correspond to a user.
			if not validate_login(email, pw, env):
				# Login failed.
				raise ValueError("Invalid password.")

			# If MFA is enabled, check that MFA passes.
			status, hints = validate_auth_mfa(email, request, env)
			if not status:
				# Login valid. Hints may have more info.
				raise ValueError(",".join(hints))

		# Get privileges for authorization. This call should never fail because by this
		# point we know the email address is a valid user. But on error the call will
		# return a tuple of an error message and an HTTP status code.
		privs = get_mail_user_privileges(email, env)
		if isinstance(privs, tuple): raise ValueError(privs[0])

		# Return a list of privileges.
		return privs

	def create_user_key(self, email, env):
		# Create a user API key, which is a shared secret that we can re-generate from
		# static information in our database. The shared secret contains the user's
		# email address, current hashed password, and current MFA state, so that the
		# key becomes invalid if any of that information changes.
		#
		# Use an HMAC to generate the API key using our master API key as a key,
		# which also means that the API key becomes invalid when our master API key
		# changes --- i.e. when this process is restarted.
		#
		# Raises ValueError via get_mail_password if the user doesn't exist.

		# Construct the HMAC message from the user's email address and current password.
		msg = b"AUTH:" + email.encode("utf8") + b" " + ";".join(get_mail_password(email, env)).encode("utf8")

		# Add to the message the current MFA state, which is a list of MFA information.
		# Turn it into a string stably.
		msg += b" " + json.dumps(get_hash_mfa_state(email, env), sort_keys=True).encode("utf8")

		# Make the HMAC.
		hash_key = self.key.encode('ascii')
		return hmac.new(hash_key, msg, digestmod="sha256").hexdigest()

	def _generate_key(self):
		raw_key = os.urandom(32)
		return base64.b64encode(raw_key).decode('ascii')
