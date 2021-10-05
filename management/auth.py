# -*- indent-tabs-mode: t; tab-width: 4; python-indent-offset: 4; -*-
import base64, os, os.path, hmac, json, secrets
from datetime import timedelta
import logging

from expiringdict import ExpiringDict

import utils
from mailconfig import validate_login, get_mail_password, get_mail_user_privileges
from mfa import get_hash_mfa_state, validate_auth_mfa
from auth_oauth import (
	decode_and_validate_jwt,
)

log = logging.getLogger(__name__)


DEFAULT_KEY_PATH   = '/var/lib/mailinabox/api.key'
DEFAULT_AUTH_REALM = 'Mail-in-a-Box Management Server'

class AuthService:
	def __init__(self):
		self.auth_realm = DEFAULT_AUTH_REALM
		self.key_path = DEFAULT_KEY_PATH
		self.max_session_duration = timedelta(days=2)

		self.init_system_api_key()
		self.sessions = ExpiringDict(max_len=64, max_age_seconds=self.max_session_duration.total_seconds())

	def init_system_api_key(self):
		"""Write an API key to a local file so local processes can use the API"""

		def create_file_with_mode(path, mode):
			# Based on answer by A-B-B: http://stackoverflow.com/a/15015748
			old_umask = os.umask(0)
			try:
				return os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT, mode), 'w')
			finally:
				os.umask(old_umask)

		self.key = secrets.token_hex(32)

		os.makedirs(os.path.dirname(self.key_path), exist_ok=True)

		with create_file_with_mode(self.key_path, 0o640) as key_file:
			key_file.write(self.key + '\n')
				
	def authenticate(self, request, env, oauth_config, leeway=0, login_only=False, logout=False):
		"""Test if the HTTP Authorization header's username matches the system key, a session key,
		or if the username/password passed in the header matches a local user.
		Returns a tuple of the user's email address and list of user privileges (e.g.
		('my@email', []) or ('my@email', ['admin']); raises a ValueError on login failure.
		If the user used the system API key, the user's email is returned as None since
		this key is not associated with a user."""

		def parse_authorization_header(header):
			if not header:
				raise ValueError("No authorization header provided.")
			try:
				scheme, value = header.split(maxsplit=1)
				return {
					'scheme': scheme,
					'value': value
				}
			except ValueError:
				raise ValueError("Authorization header invalid.")

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
			header['scheme'] = 'Bearer-cookie';
		else:
			raise ValueError("No authorization provided.")
		
		result = {
			'scheme': header['scheme']
		}
		
		if header['scheme'] == 'Basic':
			username, password = parse_basic_auth(header['value'])
			if username in (None, ""):
				raise ValueError("Authorization header invalid.")

			# If user passed the system API key, grant administrative privs. This key
			# is not associated with a user.
			elif username == self.key and not login_only:
				# The user passed the master API key which grants administrative privs.
				if not oauth_config['client']['allow_api_key_login']:
					log.warning("system api key login is disabled")
					raise ValueError("system api key login is disabled")
				
				result.update({
					'user_id': None,
					'privs': ["admin"]
				})
				log.warning('Usage of admin key')
				return result
			
			else:
				log.warning("Invalid authentication: basic auth not permitted")
				raise ValueError("Unsupported authentication method")

		
		if header['scheme'] in ['Bearer', 'Bearer-cookie']:
			try:
				claims = decode_and_validate_jwt(
					oauth_config,
					header['value'],
					leeway
				)
				result.update({
					'user_id': claims['sub'],
					'privs': claims['privs'],
					'claims': claims,
				})
			except Exception as e:
				log.warning(
					'Could not verify jwt: %s: ...%s', 
					str(e), 
					header['value'][-5:]
				)
				raise ValueError("Bearer token validation failed.") from e
			
		else:
			raise ValueError("Unsupported authorization scheme")

		log.debug('auth succeeded: token="%s" %s leeway=%s',
				  '' if header['scheme'] != 'Bearer' \
				     else '...'+header['value'][-5:],
				  result, 
				  leeway,
				  {
					  "client": oauth_config['client']["client_id"],
					  "username": result["user_id"]
				  })
		return result

	def check_user_auth(self, email, pw, request, env):
		# Validate a user's login email address and password. If MFA is enabled,
		# check the MFA token in the X-Auth-Token header.
		#
		# On login failure, raises a ValueError with a login error message. On
		# success, nothing is returned.

		# Authenticate.
		if not validate_login(email, pw, env):
			# Login failed.
			raise ValueError("Incorrect email address or password.")

		# If MFA is enabled, check that MFA passes.
		status, hints = validate_auth_mfa(email, request, env)
		if not status:
			# Login valid. Hints may have more info.
			raise ValueError(",".join(hints))

	def create_user_password_state_token(self, email, env):
		# Create a token that changes if the user's password or MFA options change
		# so that sessions become invalid if any of that information changes.
		msg = ';'.join(get_mail_password(email, env)).encode("utf8")

		# Add to the message the current MFA state, which is a list of MFA information.
		# Turn it into a string stably.
		msg += b" " + json.dumps(get_hash_mfa_state(email, env), sort_keys=True).encode("utf8")

		# Make a HMAC using the system API key as a hash key.
		hash_key = self.key.encode('ascii')
		return hmac.new(hash_key, msg, digestmod="sha256").hexdigest()

