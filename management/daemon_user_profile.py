# -*- indent-tabs-mode: t; tab-width: 4; python-indent-offset: 4; -*-

import os
import logging
import json
from flask import (
	request,
	jsonify,
	send_from_directory
)
from daemon_ui_common import (
	send_common_ui_file
)
from daemon_sessions import (
	get_session_user,
	get_session_me,
	user_login_required
)
from mailconfig import (
	validate_login,
	set_mail_password
)
import mfa, mfa_totp


log = logging.getLogger(__name__)
user_ui_dir = os.path.join(os.path.dirname(__file__), 'oauth/ui')

def send_user_ui_file(filename):
	return send_from_directory(user_ui_dir, filename)



def add_user_profile(app, env, auth_service, log_failed_login):
	'''
	call this function to add endpoints to handle user profiles

	requires:
        daemon_sessions (sesssion support)
        daemon_ui_common (common ui files)

	`app` is a Flask instance
	`env` is the Mail-in-a-Box environment
	`auth_service` is the daemon.py's KeyAuthService instance
	`log_failed_login` is a function to be called when a login fails, which
          will log to syslog text that in-turn causes fail2ban to advance
	      its counter for possibly blocking the remote

	'''

	@app.route("/user/ui/<path:filename>", methods=['GET'])
	def user_ui_file(filename):
		return send_user_ui_file(filename)

	@app.route("/user/profile", methods=['GET'])
	def user_profile():
		return send_user_ui_file('user-profile-page.html')
	
	@app.route("/user/me", methods=['GET'])
	def user_me():
		mfa_state = ( request.args.get('mfa_state') == 'y' )
		return jsonify( get_session_me( include_mfa_state=mfa_state ))
			
	@app.route('/user/password', methods=['POST'])
	@user_login_required
	def user_password(user):
		try:
			data = json.loads(request.data)
			old_password = data['old_password']
			new_password = data['new_password']
			
		except (KeyError, json.decoder.JSONDecodeError) as e:
			return ("Bad request", 400)

		# validate the old password
		email = user['user_id']
		if not validate_login(email, old_password, env):
			log_failed_login(request)
			return jsonify(
				success=False,
				reason_key='old_password',
				reason='Authentication failed, invalid password'
			)

		# validate the new password
		if old_password == new_password:
			return jsonify(
				success=False,
				reason_key='new_password',
				reason='The passwords cannot be the same.'
			)

		# other password validations occur in set_mail_password
		try:
			result = set_mail_password(email, new_password, env)
			if type(result)==tuple and result[1] > 200:
				return jsonify(
					success=False,
					reason_key='new_password',
					reason=result[0]
				)
			
			return jsonify(success=True)
		
		except ValueError as e:
			return jsonify(
				success=False,
				reason_key='new_password',
				reason=str(e)
			)
		

	@app.route('/user/mfa/disable', methods=['POST'])
	@user_login_required
	def user_mfa_disable(user):
		try:
			data = json.loads(request.data)
			mfa_id = data['mfa-id']
			password = data['password']
			
		except (KeyError, json.decoder.JSONDecodeError) as e:
			return ("Bad request", 400)

		# validate the current password
		email = user['user_id']
		if not validate_login(email, password, env):
			log_failed_login(request)
			return jsonify(
				success=False,
				reason_key="password",
				reason="Authentication failed"
			)

		# validate the mfa login
		try:
			(valid_status, hints) = mfa.validate_auth_mfa(email, request, env)
			if not valid_status:
				log_failed_login(request)
				return jsonify(
					success=False,
					reason_key="mfa",
					reason="; ".join(hints)
				)
		except ValueError as e:
			log_failed_login(request)
			return jsonify(
				success=False,
				reason_key="mfa",
				reason="The server was unable to validate MFA credentials"
			)

		# disable MFA
		try:
			mfa.disable_mfa(email, mfa_id, env)
		except Exception as e:
			log.error("Unable to disable MFA: %s", e, exc_info=e)
			return jsonify(
				success=False,
				reason_key="mfa",
				reason="The server was unable to disable MFA"
			)
		
		return jsonify(success=True)


	@app.route('/user/mfa/totp/enable', methods=['POST'])
	@user_login_required
	def user_mfa_totp_enable(user):
		try:
			data = json.loads(request.data)
			secret = data['secret']
			token = data['token']
			label = data['label']

		except (KeyError, json.decoder.JSONDecodeError) as e:
			return ("Bad request", 400)
		
		try:
			mfa_totp.validate_secret(secret)
			mfa.enable_mfa(user['user_id'], "totp", secret, token, label, env)
		except ValueError as e:
			return jsonify(
				success=False,
				reason_key="mfa",
				reason=str(e)
			)
		
		return jsonify(success=True)


