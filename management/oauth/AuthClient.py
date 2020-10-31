# -*- indent-tabs-mode: t; tab-width: 4; python-indent-offset: 4; -*-

import logging
from authlib.oauth2.rfc6749 import ClientMixin

log = logging.getLogger(__name__)

#
# clients
# the Client class must implement the functions listed here:
# https://docs.authlib.org/en/latest/specs/rfc6749.html#authlib.oauth2.rfc6749.ClientMixin
#
#

class AuthClient(ClientMixin):
	client_id = None
	client_name = None
	client_secret = None
	supported_scopes = []
	default_redirect_uri = "/"
	authorization_code_lifetime_s = 4 * 60 * 60  # 4 hours
	perms = [ ]
	redirect_uri_prefix = None
	token_policy = {
		# Authlib keywords
		'OAUTH2_TOKEN_EXPIRES_IN': {
			# access_token lifetime per grant_type
			# key=grant_type, value=seconds
			'authorization_code': 60 * 60 * 24
		},
		'OAUTH2_ACCESS_TOKEN_GENERATOR': None,
		'OAUTH2_REFRESH_TOKEN_GENERATOR': None,
		
		# Our additional keywords
		'OAUTH2_REFRESH_TOKEN_EXPIRES_IN': {
			# refresh_token lifetime per grant_type
			# key=grant_type, value=seconds
			'authorization_code': (60 * 60 * 24) + (60 * 60 * 2),
			'refresh_token': (60 * 60 * 24) + (60 * 60 * 2)
		},
		'OAUTH2_ACCESS_TOKEN_LENGTH': None,
		'OAUTH2_REFRESH_TOKEN_LENGTH': None,
	}
	
	def __init__(self, id, name, secret, supported_scopes, redirect_uri_prefix, perms=None, token_policy=None):
		self.client_id = id
		self.client_name = name
		self.client_secret = secret
		self.supported_scopes = supported_scopes
		self.redirect_uri_prefix = redirect_uri_prefix
		self.default_redirect_uri = redirect_uri_prefix
		if perms: self.perms = perms
		if token_policy: self.token_policy.update(token_policy)
		
	def check_client_secret(self, pw):
		if self.client_secret is None:
			return True
		return ( pw == self.client_secret )

	def check_grant_type(self, grant_type):
		if grant_type == "authorization_code":
			return True
		if grant_type == "refresh_token":
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
		if type(name) is str:
			name = [ name ]
		v = self.token_policy
		for key in name:
			v = v.get(key, None)
			if v is None:
				# log.debug(
				# 	'policy %s: %s (default)' % (".".join(name), default_value),
				# 	{ 'client': self.client_id }
				# )
				return default_value
		# log.debug(
		# 	'policy %s: %s (client)' % (".".join(name), v),
		# 	{ 'client': self.client_id }
		# )
		return v
	
