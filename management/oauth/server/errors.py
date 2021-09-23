# -*- indent-tabs-mode: t; tab-width: 4; python-indent-offset: 4; -*-
from authlib.oauth2 import (
	OAuth2Error
)

class InsufficientPrivilegeError(OAuth2Error):
	error="insufficient_privilege"
	description="Admin privileges required"
	status_code=403  # forbidden

class AuthenticationFailureError(OAuth2Error):
	error="access_denied"
	status_code=403  # forbidden

	def __init__(self, description):
		super(AuthenticationFailureError, self).__init__(description=description)
