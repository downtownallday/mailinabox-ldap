# -*- indent-tabs-mode: t; tab-width: 4; python-indent-offset: 4; -*-
import logging

from .errors import (
	AuthenticationFailureError
)
from .Storage import Storage
from mailconfig import find_mail_user

log = logging.getLogger(__name__)


class MiabUsersMixin(Storage):
	''' this mixin requires the following class variables:
	    env: the miab environment
	    auth_service: the daemon's AuthService instance (auth.py)
	'''
	def query_user(self, user_id):
		user = find_mail_user(self.env, user_id, attributes=[
			'cn',
			'mail',
			'maildrop',
			'mailaccess'
		])
		if user:
			user['user_id'] = user['maildrop'][0]
				
		return user

	def authenticate_user(self, username, password, request):
		log_args = {
			"username": username,
			"client": request.client.get_client_id() if request.client else None
		}
		try:
			privs = self.auth_service.check_user_auth(
				username,
				password,
				request,
				self.env
			)
		except ValueError as e:
			raise AuthenticationFailureError(str(e))

		except Exception as e:
			# unexpected server error
			log.error(
				"Problem authenticating user: %s",
				e,
				log_args,
				exc_info=e)
			return None

		return self.query_user(username)
