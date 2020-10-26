# -*- indent-tabs-mode: t; tab-width: 4; python-indent-offset: 4; -*-
import logging

from .Storage import Storage
from mailconfig import find_mail_user

log = logging.getLogger(__name__)


class MiabUsersMixin(Storage):

	def query_user(self, user_id):
		user = find_mail_user(self.env, user_id, attributes=['cn','mail','maildrop'])
		if user:
			user['user_id'] = user['maildrop'][0]
			if user_id != user['user_id']:
				log.warning('user_id mismatch')
				
		return user

