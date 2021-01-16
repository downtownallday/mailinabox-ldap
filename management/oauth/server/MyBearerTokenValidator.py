# -*- indent-tabs-mode: t; tab-width: 4; python-indent-offset: 4; -*-

from authlib.oauth2.rfc6750 import BearerTokenValidator
from .server_globals import G


class MyBearerTokenValidator(BearerTokenValidator):
	def authenticate_token(self, token_string):
		return G.storage.authenticate_access_token(token_string)

	def request_invalid(self, request):
		return False

	def token_revoked(self, token):
		return not token.is_active()
