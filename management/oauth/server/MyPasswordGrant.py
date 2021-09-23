# -*- indent-tabs-mode: t; tab-width: 4; python-indent-offset: 4; -*-

import logging
import time
from authlib.oauth2.rfc6749 import grants
from .server_globals import G

log = logging.getLogger(__name__)


class MyPasswordGrant(grants.ResourceOwnerPasswordCredentialsGrant):
    
	def authenticate_user(self, username, password):
		user = G.storage.authenticate_user(username, password, self.request)
		if user:
			user = self._client.check_user_restrictions(user)
		return user

	def authenticate_token_endpoint_client(self):
		# override the AuthLib base class method to keep a reference
		# to the AuthClient instance returned by
		# authenticate_token_endpoint_client()
		self._client = super(MyPasswordGrant, self).authenticate_token_endpoint_client()
		return self._client
	
