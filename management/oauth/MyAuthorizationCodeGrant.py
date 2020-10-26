# -*- indent-tabs-mode: t; tab-width: 4; python-indent-offset: 4; -*-

import logging
import time
from authlib.oauth2.rfc6749 import grants
from .server_globals import G

log = logging.getLogger(__name__)


class MyAuthorizationCodeGrant(grants.AuthorizationCodeGrant):
	TOKEN_ENDPOINT_AUTH_METHODS = [
		'client_secret_basic',
		'client_secret_post',
		'none',
	]

	def save_authorization_code(self, code, request):
		log.debug("save_authorization_code: %s" % code)
		auth_code = G.storage.save_authorization_code(
			code,
			request.client,  # AuthClient object
			request.user,    # return value from G.storage.query_user()
			request.redirect_uri,
			request.scope,
			request.data.get('code_challenge'),
			request.data.get('code_challenge_method'),
			time.time()
		)
		return auth_code

	def query_authorization_code(self, code, client):
		auth_code = G.storage.query_authorization_code(
			code,
			client.client_id)
		return auth_code

	def delete_authorization_code(self, authorization_code):
		G.storage.delete_authorization_code(authorization_code)

	def authenticate_user(self, authorization_code):
		return G.storage.query_user(authorization_code.user_id)

