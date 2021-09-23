# -*- indent-tabs-mode: t; tab-width: 4; python-indent-offset: 4; -*-

import os
import stat
import logging
import json
from datetime import timedelta
import hashlib
import urllib
from flask import (
	request,
	session,
	sessions,
	jsonify,
	redirect,
	current_app
)
from functools import wraps

from authlib.common.security import generate_token

from daemon_ui_common import (
	send_common_ui_file
)
from mailconfig import (
	find_mail_user
)
import mfa, mfa_totp


log = logging.getLogger(__name__)


# keep a reference to read-only global 'env' for global function
# get_session_user()
env = None

# keep a reference to global auth_service
auth_service = None


#
# essential session-related functions
#

def _get_user_password_state_hash(user_id):
	# Obtain and add salt to the password state token, then use a
	# minimal hash function to re-hash. The result will end up in the
	# session cookie, which is a signed but unencrypted object. We
	# don't use a secure hashing function here because the session
	# cookie is tamper resistant and collissions are highly highly
	# unlikely (a change in a password resulting in the same hash). We
	# just need to know whether the password state changed without
	# revealing anything about the password so the session can be
	# invalidated.
	#
	# note: salt is random text that's currently regenerated anytime
	# setup/oauth.sh is run or the salt file is removed and the oauth
	# daemon restarted
	salt = current_app.session_interface.salt
	user_password_state = auth_service.create_user_password_state_token(
		user_id,
		env
	)
	plaintext = user_password_state + salt
	return (
		user_password_state,
		hashlib.md5(plaintext.encode('utf-8')).hexdigest()
	)


def get_session_user():
	'''get details about the currently logged-in user. do not send to
	end-users. use get_session_me() instead.

	if the user is not logged in, returns None

	'''
	if 'user_id' not in session: return None
	user_id = session['user_id']
	user = find_mail_user(env, user_id, attributes=[
		'cn',
		'mail',
		'maildrop',
		'mailaccess'
	])
	if not user: return None	
	user['user_id'] = user['maildrop'][0]

	# invalidate the session if the user password state changed
	if 'user_password_state_hash' not in session:
		session.clear()
		return None
	
	user_password_state, user_password_state_hash = \
		_get_user_password_state_hash(user_id)
	if session['user_password_state_hash'] != user_password_state_hash:
		session.clear()
		return None
	
	# # if valid, return the user_password_state in the user object
	# user['user_password_state'] = user_password_state
	return user


def set_session_user(user_id, stay_signed_in):
	''' establish a server session for a user  '''
	session.clear()
	session['user_id'] = user_id
	if stay_signed_in is not None:
		session.permanent = stay_signed_in
		log.info('login permanent=%s', stay_signed_in)
	update_session()

	
def update_session():
	# store a hash of the user password state token in the
	# session. don't store the user_password_state itself because the
	# session cookie is not encrypted, only signed. it's sufficient to
	# know if the password state changed and deem the session invalid
	# if that happened. this will happen, for instance, if the user's
	# password or MFA config was changed by an admin
	#
	user_password_state, user_password_state_hash = \
		_get_user_password_state_hash(session['user_id'])
	session['user_password_state_hash'] = \
		user_password_state_hash
	
	
def logout_session_user():
	log.info('logout')
	session.clear()

def user_login_required(login_redirect=False, privs=None):
	'''Decorator to protect views that require a user be authenticated
	returns the looked-up user as named argument 'user'. eg:

	@app.route('/user/profile')
	@user_login_required()
	def handler(user):  ...

	'''
	_login_redirect = login_redirect
	_privs = privs or []
	if type(privs) is str: _privs = [ privs ]
	
	def decorator(func):
		@wraps(func)
		def wrapper(*args, **kwargs):
			user = get_session_user()
			if not user:
				if _login_redirect:
					url = urllib.parse.urlparse(request.url)
					return redirect('/user/login?redirect_to=' + url.path[1:])
				else:
					response = jsonify(
						status='error',
						reason='Login required'
					)
					return (response, 403)
			for priv in _privs:
				if priv not in user['mailaccess']:
					response = jsonify(
						status='error', 
						reason='Insufficient privilege'
					)
					return (response, 403)
			return func(*args, user=user, **kwargs)
		return wrapper
	return decorator

def admin_login_required(login_redirect=False):
	''' Decorator to protect views that require admin privilege '''
	return user_login_required(
		login_redirect,
		privs='admin'
	)


def get_session_me(include_mfa_state=False):
	'''get information about the server and details about the currently
	logged in user that is appropriate to return to the end-user

	'''
	me = {
		'server_hostname': env['PRIMARY_HOSTNAME']
	}
	user = get_session_user()
	if user:
		me.update({
			'user_id': user['user_id'],
			'name': user['cn'][0],
			'email': user['mail'][0],
		})
		if include_mfa_state:
			# IMPORTANT: this should match what GET /admin/mfa/status returns
			me.update({
				'enabled_mfa': mfa.get_public_mfa_state(user['user_id'], env),
				'new_mfa': {
					'totp': mfa_totp.provision(user['user_id'], env)
				}
			})

	return me
		


class MySecureCookieSessionInterface(sessions.SecureCookieSessionInterface):
	'''subclass the default secure cookie implementation to use a more
	secure hashing algorithm and random salt

	'''
	_salt = None

	def digest_method(self):
		return hashlib.sha3_256()

	@property
	def salt(self):
		# salt here doesn't behave like salt - changing it causes the
		# session to become invalid, so probably it's simply appended
		# to secret_key but not kept with the session cookie.
		#
		# because of this, persist the salt value and reuse it so
		# sessions don't become invalid on every restart
		if not self._salt:
			salt_file = '/var/lib/mailinabox/session_salt.txt'
			isnew = False
			if not os.path.exists(salt_file):
				with open(salt_file, "w") as fp:
					fp.write(generate_token(12))
				os.chmod(salt_file, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)
				isnew = True

			with open(salt_file, "r") as fp:
				self._salt = fp.read().strip()
			log.debug('SESSION SALT: %s %s', self._salt, '(new)' if isnew else '(from %s)' % salt_file)
		return self._salt


def add_sessions(app, miabenv, miab_auth_service, log_failed_login):
	'''call this function to add Flask sessions

	see daemon_user.py for endpoints for login and logout

	`app` is a Flask instance
	`miabenv` is the Mail-in-a-Box environment (read-only)
	`auth_service` is the daemon.py's KeyAuthService instance
	`log_failed_login` is a function to be called when a login fails, which
          will log to syslog text that in-turn causes fail2ban to advance
	      its counter for possibly blocking the remote

	'''

	global env
	env = miabenv

	global auth_service
	auth_service = miab_auth_service

	if not app.secret_key:
		# enable Flask sessions
		app.config.from_mapping({
			'SECRET_KEY': auth_service.key,
			'PERMANENT_SESSION_LIFETIME': timedelta(days=7),
			'SESSION_COOKIE_NAME': 'miabsession',
			'SESSION_COOKIE_SECURE': True,
			'SESSION_COOKIE_SAMESITE': 'Strict',
			'SESSION_COOKIE_HTTPONLY': True,
			'SESSION_REFRESH_EACH_REQUEST': True,
		})
		app.session_interface = MySecureCookieSessionInterface()
		log.debug('sessions: digest=%s key=%s', app.session_interface.digest_method(), app.secret_key)


	def secret_updated():
		# call this whenever the auth_service master key changes
		app.secret_key = auth_service.key
		log.debug('session secret update: key=%s', app.secret_key)
	
	return secret_updated
