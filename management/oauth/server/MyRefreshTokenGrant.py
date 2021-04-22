# -*- indent-tabs-mode: t; tab-width: 4; python-indent-offset: 4; -*-

import logging
from authlib.oauth2.rfc6749 import grants
from .server_globals import G

log = logging.getLogger(__name__)


class MyRefreshTokenGrant(grants.RefreshTokenGrant):
	TOKEN_ENDPOINT_AUTH_METHODS = [
		'client_secret_basic',
		'client_secret_post',
		'none',
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

	def revoke_old_credential(self, credential):
		G.storage.revoke_token(credential, delay_s=0)
