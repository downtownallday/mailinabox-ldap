# -*- indent-tabs-mode: t; tab-width: 4; python-indent-offset: 4; -*-

import os
import logging
import json
from datetime import timedelta
from flask import (
	request,
	session,
	jsonify
)
from functools import wraps

from daemon_ui_common import send_common_ui_file
from mailconfig import (
	find_mail_user
)
import mfa, mfa_totp


log = logging.getLogger(__name__)

# keep a reference to read-only global 'env' for global function
# get_session_user()
env = None

#
# essential session-related functions
#

def get_session_user():
	'''get information about the currently logged-in user. do not send to
	end-users. use get_session_me() instead

	'''
	if 'user_id' not in session: return None
	user_id = session['user_id']
	user = find_mail_user(env, user_id, attributes=[
		'cn',
		'mail',
		'maildrop'
	])
	if user:
		user['user_id'] = user['maildrop'][0]				
		return user

def set_session_user(user_id, stay_signed_in):
	session['user_id'] = user_id
	session.permanent = stay_signed_in
	log.info('login permanent=%s', stay_signed_in)
	
def logout_session_user():
	log.info('logout')
	session.clear()

def user_login_required(func):
	'''Decorator to protect views that require a user be authenticated
	returns the looked-up user as named argument 'user'

	'''
	@wraps(func)
	def wrapper(*args, **kwargs):
		user = get_session_user()
		if not user:
			return ("login_required", 403)
		return func(*args, user=user, **kwargs)
	return wrapper


def get_session_me(include_mfa_state=False):
	'''get information about the server and details about the currently
	logged in user that is safe to return to the end-user

	'''
	me = {
		'server_hostname': env['PRIMARY_HOSTNAME']
	}
	user = get_session_user()
	if user:
		me.update({
			'user_id': user['user_id'],
			'name': user['cn'][0],
		})
		if include_mfa_state:
			# IMPORTANT: this should match what GET /mfa/status returns
			me.update({
				'enabled_mfa': mfa.get_public_mfa_state(user['user_id'], env),
				'new_mfa': {
					'totp': mfa_totp.provision(user['user_id'], env)
				}
			})

	return me
		

		
def add_sessions(app, miabenv, auth_service, log_failed_login):
	'''call this function to add Flask sessions, plus endpoints for login
	and logout

	`app` is a Flask instance
	`miabenv` is the Mail-in-a-Box environment
	`auth_service` is the daemon.py's KeyAuthService instance
	`log_failed_login` is a function to be called when a login fails, which
          will log to syslog text that in-turn causes fail2ban to advance
	      its counter for possibly blocking the remote

	'''

	global env
	env = miabenv
	
	if not app.secret_key:
		# enable Flask sessions
		app.config.from_mapping({
			'SECRET_KEY': auth_service.key,
			'PERMANENT_SESSION_LIFETIME': timedelta(days=7),
			'SESSION_COOKIE_SECURE': True,
			'SESSION_COOKIE_SAMESITE': 'Strict',
			'SESSION_REFRESH_EACH_REQUEST': True,
			'SESSION_COOKIE_PATH': '/miab-ldap/',
		})
		

	@app.route("/user/login", methods=['POST'])
	def session_user_login():
		try:
			data = json.loads(request.data)
			username = data['username']
			password = data['password']
			stay_signed_in = data.get('stay_signed_in', False)
			
		except (KeyError, json.decoder.JSONDecodeError) as e:
			return ("Bad request", 400)

		try:
			privs = auth_service.check_user_auth(
				username,
				password,
				request,
				env)
			
		except ValueError as e:
			if "missing-totp-token" in str(e):
				# password is okay, so get the labels for each totp
				# device configured
				labels = []
				try:
					states = mfa.get_public_mfa_state(username, env)
					labels = [ state["label"] for state in states ]
				except ValueError as e2:
					log.error(
						'Error getting mfa state: %s', e2,
						{ 'username': username },
						exc_info=e2
					)
					
				return jsonify(
					status='missing-totp-token',
					reason=str(e),
					labels=labels
				)
			
			else:
				# Log the failed login
				log_failed_login(request)
				return jsonify(
					status="invalid",
					reason=str(e)
				)
			
		except Exception as e:
			# unexpected server error
			log.error(
				"Problem authenticating user: %s", e,
				{ 'username': username },
				exc_info=e)
			return ("Authentication failed", 403)

		set_session_user(username, stay_signed_in)
		
		return jsonify(
			status="ok",
			me=get_session_me()
		)

		
	@app.route('/user/logout')
	def user_logout():
		logout_session_user()
		return send_common_ui_file('logout.html')

