# -*- indent-tabs-mode: t; tab-width: 4; python-indent-offset: 4; -*-

import time
import json
from authlib.oauth2.rfc6749 import TokenMixin


class Token(TokenMixin):
	access_token = None
	refresh_token = None
	client_id = None
	user_id = None
	issued_at = None
	expires_in = None
	refresh_expires_in = None
	scope = None
	revoked = False
	token_type = None  # "Bearer"

	def __init__(self, d):
		self.access_token = d.get("access_token")
		self.refresh_token = d.get("refresh_token", None)
		self.client_id = d.get("client_id")
		self.user_id = d.get("user_id")
		self.issued_at = int(d.get("issued_at"))
		self.expires_in = int(d.get("expires_in"))
		self.refresh_expires_in = int(d.get("refresh_expires_in", 0))
		self.scope = d.get("scope")
		self.revoked = d.get("revoked", False)
		self.token_type = d.get("token_type")

	def to_dict(self):
		d = {
			"access_token": self.access_token,
			"client_id": self.client_id,
			"user_id": self.user_id,
			"issued_at": self.issued_at,
			"expires_in": self.expires_in,
			"scope": self.scope,
			"revoked": self.revoked,
			"token_type": self.token_type
		}
		
		if self.refresh_token:
			d.update({
				"refresh_token": self.refresh_token,
				"refresh_expires_in": self.refresh_expires_in
			})
			
		return d
	
	def short_access_token(self):
		if self.access_token: return '...'+self.access_token[-5:]
		return ''

	def short_refresh_token(self):
		if self.refresh_token: return '...'+self.refresh_token[-5:]
		return ''

	def stringify(self):
		return json.dumps(self.to_dict())

	def get_client_id(self):
		return self.client_id

	def is_active(self):
		return not self.is_expired() and not self.is_revoked()

	def is_revoked(self):
		return self.revoked
	
	def is_expired(self):
		return time.time() >= self.get_expires_at()
			
	def get_expires_at(self):
		''' required by AuthLib ResourceProtector '''
		return self.get_issued_at() + self.get_expires_in()

	def get_issued_at(self):
		return self.issued_at

	def get_expires_in(self):
		return self.expires_in

	def expire_from_now(self, sec):
		''' set the access_token and refresh_token expire times to
		    `sec` seconds from now

		'''
		now = int(time.time())
		new_expires_in = (now - self.issued_at) + sec
		self.expires_in = min(self.expires_in, new_expires_in)
		self.refresh_expires_in = self.expires_in
		
	def get_scope(self):
		''' required by Authlib ResourceProtector '''
		return self.scope

	def get_refresh_expires_in(self):
		return self.refresh_expires_in

	def get_refresh_expires_at(self):
		''' when the refresh_token expires '''
		return self.get_issued_at() + self.get_refresh_expires_in()

	def is_refresh_expired(self):
		return time.time() >= self.get_refresh_expires_at()

	def is_refresh_active(self):
		return self.refresh_token and not self.is_refresh_expired() and not self.is_revoked()
