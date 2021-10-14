# -*- indent-tabs-mode: t; tab-width: 4; python-indent-offset: 4; -*-

import logging
from authlib.oauth2.rfc6749 import grants
from .server_globals import G

log = logging.getLogger(__name__)


class MyRefreshTokenGrant(grants.RefreshTokenGrant):
	TOKEN_ENDPOINT_AUTH_METHODS = [
		'client_secret_basic',
		'client_secret_post',
#		'none',
	]
	
	INCLUDE_NEW_REFRESH_TOKEN = True
	
	def authenticate_refresh_token(self, refresh_token_string):
		token = G.storage.authenticate_refresh_token(refresh_token_string)
		if log.isEnabledFor(logging.DEBUG):
			if token:
				log.debug(
					'valid refresh token found: "%s" access_token="%s"',
					token.short_refresh_token(),
					token.short_access_token(),
					{
						'client': token.get_client_id(),
						'username': token.user_id,
					}
				)
			else:
				log.debug('refresh token not found or inactive: "%s"',
						  refresh_token_string)
				
		return token

	def authenticate_user(self, credential):
		''' make sure user exists and is not expired / locked out, etc '''
		return G.storage.query_user(credential.user_id)

	def issue_token(self, user, credential):
		# overrides base class to provide correct expires_in and
		# per-client INCLUDE_NEW_REFRESH_TOKEN policy
		#
		# `user` is an authenticated user (see MiabUsersMixin)
		# `credential` is a Token object containing the old credentials
		client = G.storage.query_client(credential.get_client_id())
		expires_in = client.get_token_policy(
			['OAUTH2_TOKEN_EXPIRES_IN', 'refresh_token' ],
			credential.get_expires_in()
		)
		include_new_refresh_token = client.get_token_policy(
			'INCLUDE_NEW_REFRESH_TOKEN',
			self.INCLUDE_NEW_REFRESH_TOKEN
		)
			
		#expires_in = credential.get_expires_in()
		scope = self.request.scope
		if not scope:
			scope = credential.get_scope()

		token = self.generate_token(
			user=user,
			expires_in=expires_in,
			scope=scope,
			#include_refresh_token=self.INCLUDE_NEW_REFRESH_TOKEN,
			include_refresh_token=include_new_refresh_token,
		)
		return token

		
	def revoke_old_credential(self, credential):
		client = G.storage.query_client(credential.get_client_id())
		delay = 0
		if client:
			delay = client.get_token_policy('OAUTH2_REVOKE_DELAY_SECS', 0)
		G.storage.revoke_token(credential, delay_s=delay)
