# -*- indent-tabs-mode: t; tab-width: 4; python-indent-offset: 4; -*-

import time
from authlib.oauth2.rfc6749 import AuthorizationCodeMixin


class AuthCode(AuthorizationCodeMixin):
	code = None
	client_id = None
	user_id = None
	redirect_uri = None
	scope = None
	code_challenge = None
	code_challenge_method = None
	issued_at = None
	expires_in = None

	def __init__(self, d):
		self.code = d.get("code")
		self.client_id = d.get("client_id")
		self.user_id = d.get("user_id")
		self.redirect_uri = d.get("redirect_uri")
		self.scope = d.get("scope")
		self.code_challenge = d.get("code_challenge", None)
		self.code_challenge_method = d.get("code_challenge_method", None)
		self.issued_at = int(d.get("issued_at"))
		self.expires_in = int(d.get("expires_in", 0))

	def get_expires_at(self):
		''' required by AuthLib ResourceProtector '''
		return self.issued_at + self.expires_in

	def get_expires_in(self):
		return self.expires_in

	def is_expired(self):
		if time.time() >= (self.issued_at + self.expires_in):
			return True
		return False

	def get_redirect_uri(self):
		return self.redirect_uri

	def get_scope(self):
		return self.scope

