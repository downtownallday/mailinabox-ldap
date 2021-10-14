# -*- indent-tabs-mode: t; tab-width: 4; python-indent-offset: 4; -*-

import logging
from authlib.oauth2.rfc6749 import ClientMixin
from authlib.oauth2.rfc6750 import BearerToken

log = logging.getLogger(__name__)

#
# clients
# the Client class must implement the functions listed here:
# https://docs.authlib.org/en/latest/specs/rfc6749.html#authlib.oauth2.rfc6749.ClientMixin
#
#

class AuthClient(ClientMixin):
	'''OAUTH2_TOKEN_EXPIRES_IN:

	   default values are from authlib's BearerToken class found in
	   authlib/oauth2/rfc6750/wrappers.py:

	   They are:

         authorization_code: 864000,
         implicit: 3600,
         password: 864000,
         client_credentials: 864000

	   Authlib code comments also refer to:

		 'urn:ietf:params:oauth:grant-type:jwt-bearer': 3600

	   Any key not found when accessing the dict will receive the
	   default value of BearerToken.DEFAULT_EXPIRES_IN currently set
	   to 3600.

	   An AuthClient may override any of the settings below.

	'''

	
	def __init__(self, id, name, secret, supported_scopes, redirect_uri_prefix, grant_types=[ "authorization_code","refresh_token" ], perms=None, token_policy=None, jwt_private_claims_fn=None, check_user_restrictions_fn=None):

		self.client_id = id
		self.client_name = name
		self.client_secret = secret
		self.supported_scopes = supported_scopes
		self.redirect_uri_prefix = redirect_uri_prefix
		self.default_redirect_uri = redirect_uri_prefix
		self.grant_types = grant_types
		self.check_user_restrictions_fn = check_user_restrictions_fn

		self.perms = perms or []
		self.token_policy = {
			# Authlib keywords
			'OAUTH2_TOKEN_EXPIRES_IN': {
				# access_token lifetime per grant_type
				# key=grant_type, value=seconds
				'authorization_code': 60 * 60 * 24,
				'urn:ietf:params:oauth:grant-type:jwt-bearer': 3600,
			},
			'OAUTH2_ACCESS_TOKEN_GENERATOR': True,
			'OAUTH2_REFRESH_TOKEN_GENERATOR': False,
			
			# Our additional keywords
			'OAUTH2_AUTHORIZATION_CODE_EXPIRES_IN': 1 * 60 * 60, # 1 hour
			'OAUTH2_REFRESH_TOKEN_EXPIRES_IN': {
				# refresh_token lifetime per grant_type
				# key=grant_type, value=seconds
				'authorization_code': (60 * 60 * 24) + (60 * 60 * 2),
				'refresh_token': (60 * 60 * 24) + (60 * 60 * 2)
			},
			'OAUTH2_ACCESS_TOKEN_LENGTH': 42,
			'OAUTH2_REFRESH_TOKEN_LENGTH': 48,
			'OAUTH2_JWT_TOKENS': False,
		}
		
		if token_policy:
			for key in token_policy:
				if type(token_policy[key]) == dict:
					self.token_policy[key].update(token_policy[key])
				else:
					self.token_policy[key] = token_policy[key]
					
		log.debug("token_policy for %s: %r" % (self.client_id, self.token_policy))

		def no_jwt_private_claims(client, grant_type, user, scope):
			return {}
		
		self.jwt_private_claims=jwt_private_claims_fn or no_jwt_private_claims
		
		
	def check_client_secret(self, pw):
		if self.client_secret is None:
			return True
		return ( pw == self.client_secret )

	def check_grant_type(self, grant_type):
		if grant_type in self.grant_types:
			return True
		log.warning(
			"unhandled grant_type: %s" % grant_type,
			{ 'client': self.client_id }
		)
		return False

	def check_redirect_uri(self, redirect_uri):
		ok = False
		if self.redirect_uri_prefix is None:
			ok = True
		elif type(self.redirect_uri_prefix) is list:
			for prefix in self.redirect_uri_prefix:
				if redirect_uri.startswith(prefix):
					ok = True
					break
		else:
			ok = redirect_uri.startswith(self.redirect_uri_prefix)
			
		if not ok:
			log.warning(
				'redirect uri rejected! redirect_uri="%s", expecting prefix "%s"' % (redirect_uri, self.redirect_uri_prefix),
				{ 'client': self.client_id }
			)
		return ok


	def check_response_type(self, response_type):
		# response_type=="code" or "token"
		log.debug(
			"check_response_type: %s" % response_type,
			{ 'client': self.client_id }
		)
		return True

	def check_token_endpoint_auth_method(self, method):
		# also allowable is "none" for client w/o secret
		if self.client_secret is None:
			return method == 'none'
		if method not in ['client_secret_basic', 'client_secret_post']:
			log.warning(
				'auth method "%s" not allowed' % method,
				{ 'client': self.client_id }
			)
			return False
		return True

	def check_user_restrictions(self, user):
		if user is None or not self.check_user_restrictions_fn:
			# ok
			return user
		user = self.check_user_restrictions_fn(user)
		return user

	def get_allowed_scope(self, scope):
		''' return a subset of scopes in `scope` that are supported
		by the client

		'''
		if not scope: return ''
		allowed = [s for s in scope.split() if s in self.supported_scopes]
		return " ".join(allowed)

	def get_client_id(self):
		return self.client_id

	def get_default_redirect_uri(self):
		return self.default_redirect_uri

	def has_client_secret(self):
		return self.client_secret is not None

	def get_introspect_permission(self, token):
		# clients can introspect their own tokens
		if token.get_client_id() == self.get_client_id():
			return 'introspect-self'
		
		# allowed to introspect any client's tokens, not just its own
		if 'introspect-any' in self.perms:
			return 'introspect-any'
		
		return None
		
	def has_introspect_permission(self, token):
		perm = self.get_introspect_permission(token)
		return perm or False

	def get_token_policy(self, name, default_value=None):
		debug_token_policy = False
		if type(name) is str:
			name = [ name ]

		def logv(key, v):
			if debug_token_policy:
				log.debug('token_policy: %r: %s=%s', name, key, v, {
					'client': self.client_id
				})
			
		v = self.token_policy
		for key in name:
			v = v.get(key, None)
			if v is None:
				if default_value is not None:
					logv(key, "%s (default)" % default_value)
					return default_value
				
				if len(name)==2 and name[0]=='OAUTH2_TOKEN_EXPIRES_IN':
					v = BearerToken.GRANT_TYPES_EXPIRES_IN.get(key, BearerToken.DEFAULT_EXPIRES_IN)
					logv(key, v)
					return v

				elif len(name)==2 and name[0]=='OAUTH2_REFRESH_TOKEN_EXPIRES_IN':
					v = BearerToken.GRANT_TYPES_EXPIRES_IN.get(key, BearerToken.DEFAULT_EXPIRES_IN) * 2
					logv(key, v)
					return v
					

				raise ValueError("Unknown token policy %s" % name)

		logv(key, v)
		return v
	
