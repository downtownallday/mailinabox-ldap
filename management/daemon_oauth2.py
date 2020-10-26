# -*- indent-tabs-mode: t; tab-width: 4; python-indent-offset: 4; -*-

import os
import logging
import json

from flask import request, session, url_for, redirect, jsonify, send_from_directory
from functools import wraps
from authlib.integrations.flask_oauth2 import current_token
from authlib.oauth2.rfc6749 import (
	OAuth2Error,
	InvalidClientError,
	MissingAuthorizationError
)

from oauth.SqliteStorage import SqliteStorage
from oauth.MiabClientsMixin import MiabClientsMixin
from oauth.MiabUsersMixin import MiabUsersMixin
import oauth.oauth2 as oauth2
import oauth.scope_properties as scope_properties

log = logging.getLogger(__name__)


# miab integration
from mailconfig import validate_login, set_mail_password
import mfa, mfa_totp


# Storage class for persisting and querying users, tokens, clients, etc
class MyStorage(SqliteStorage, MiabClientsMixin, MiabUsersMixin):
	def __init__(self, env, db_path):
		self.env = env
		super(MyStorage, self).__init__(db_path)


def add_oauth2(app, env, auth_service, log_failed_login):
	# enable Flask sessions
	if not app.secret_key:
		app.secret_key = auth_service.key
		
	if app.debug or "DEBUG" in os.environ:
		# init logging
		logging.basicConfig(level=logging.DEBUG)
		app.config.from_mapping({
			'EXPLAIN_TEMPLATE_LOADING': True,
			'TESTING': True
		})
		
	# instantiate client/user/token store
	storage = MyStorage(
		env,
		os.path.join(
			env["STORAGE_ROOT"], "authorization_server", "authserver.sqlite")
	)

	# create oauth2 authorization server
	authorization, require_oauth = oauth2.create_auth_server(
		app,
		storage
	)

	# allow Authlib to issue tokens over HTTP since daemon.py is
	# hidden behind Nginx (which handles HTTPS for us)
	os.environ['AUTHLIB_INSECURE_TRANSPORT']='1'


	# UI support
	ui_dir = os.path.join(os.path.dirname(app.template_folder), 'oauth_ui')
	def send_ui_file(filename):
		log.debug("Deliver file: %s from %s" % (filename, ui_dir))
		return send_from_directory(ui_dir, filename)
	

	# session-related functions
	def get_session_user():
		''' get the current logged-in user '''
		if 'user_id' not in session: return None
		user_id = session['user_id']
		return storage.query_user(user_id)

	def set_session_user(user_id):
		session['user_id'] = user_id

	def logout_session_user():
		session.clear()

			
	#
	# oauth routes
	#

	@app.route("/oauth/ui/<path:filename>", methods=['GET'])
	def get_ui_file(filename):
		return send_ui_file(filename)
		
	@app.route("/oauth/authorize", methods=["GET","POST"])
	def authorize():
		'''OAuth2 authorization request

		'''
		user = get_session_user()
		if not user:
			return send_ui_file('authorization-page.html')

		# validate OAuth2 parameters from client
		try:
			log.debug("VALIDATE CONSENT REQUEST")
			grant = authorization.validate_consent_request(end_user=user)
			log.debug("VALIDATE SUCCEEDED, GRANT=%s" % grant)
		except OAuth2Error as error:
			return error.error

		# validate end-user consent
		consent = request.form.get('consent', 'false')
		if consent != 'true':
			return send_ui_file('authorization-page.html')
		
		return authorization.create_authorization_response(grant_user=user)

	
	def get_me(include_mfa_state=False):
		''' get information about the currently logged in user '''
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
		
	@app.route("/oauth/me", methods=['GET'])
	def oauth_me():
		return jsonify( get_me() )
	
	@app.route("/oauth/clientinfo", methods=["POST"])
	def clientinfo():
		'''given a client_id and list of scopes, return the OAuth2 client
		   name, allowed scopes and scope properties (description,
		   etc). post data is supplied as JSON.

		   this is a public function

		'''
		
		try:
			data = json.loads(request.data)
			client_id = data['client_id']
			scope = data['scope']
		except (KeyError, json.decoder.JSONDecodeError) as e:
			return ("Invalid request", 400)
			
		client = storage.query_client(client_id)
		if not client:
			return ("No such client", 404)

		allowed_scope = client.get_allowed_scope(scope)
		
		return jsonify(
			client_id=client.client_id,
			client_name=client.client_name,
			scope_properties=scope_properties.get(
				allowed_scope,
				for_end_user=True
			)
		)


	@app.route("/oauth/login", methods=['POST'])
	@app.route("/user/login", methods=['POST'])
	def oauth_login():
		try:
			data = json.loads(request.data)
			username = data['username']
			password = data['password']
			
		except (KeyError, json.decoder.JSONDecodeError) as e:
			return ("Invalid request", 400)

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
					log.error('Error getting mfa state of %s: %s' %
							  (username, e2))
					
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
			log.error("Problem authenticating user %s: %s", (username, e))
			return ("Authentication failed", 403)

		set_session_user(username)
		return jsonify(
			status="ok",
			me=get_me()
		)

		
	
	@app.route("/oauth/token", methods=['POST'])
	def issue_token():
		''' issue tokens '''
		log.debug("HANDLE issue_token: POST data=%s" % request.form)
		response = authorization.create_token_response(request)
		if response.status_code == 401:
			# client auth failed, log the attempt
			log_failed_login(request)
		return response


	@app.route("/oauth/revoke", methods=['POST'])
	def revoke_token():
		''' revoke tokens '''
		log.debug("HANDLE revoke_token: POST data=%s" % request.form)
		response = authorization.create_endpoint_response(oauth2.MyRevocationEndpoint.ENDPOINT_NAME)
		if response.status_code == 401:
			# client auth failed, log the attempt
			log_failed_login(request)
		return response


	@app.route("/oauth/v1/introspect", methods=["GET"])
	@require_oauth('introspect')
	def v1_introspect_get():
		''' introspection per rfc with Authorization: Bearer

		'''
		ep = oauth2.MyIntrospectionEndpoint(authorization)
		return jsonify(ep.introspect_token(current_token))


	@app.route("/oauth/v1/tokeninfo", methods=["GET", "POST"])
	def v1_introspect_post():
		'''allow clients to get information about their own access tokens, or
	       or for access tokens they have special permissions for.

		   added to support dovecot's XOAUTH2 implementation

		'''
		if request.method == "GET":
			access_token_string = request.args.get("access_token")
			if not access_token_string:
				return ('Access token is required', 400)

			# setting the state is required or boom in
			# authlib/oauth2/rfc6749/authenticate_client.py", line 6
			request.state = request.args.get('state')

			# authenticate the client using basic auth
			try:
				client = oauth2.authenticate_client(request, required=True)
			except (InvalidClientError, MissingAuthorizationError) as e:
				if e.status_code == 401:
					log_failed_login(request)
				return e.error
			except OAuth2Error as e:
				return e.error

			# introspect the access_token supplied
			ep = oauth2.MyIntrospectionEndpoint(authorization)
			token = ep.query_token(access_token_string, "access_token", client)
			return jsonify(ep.introspect_token(token))

		else:
			response = authorization.create_endpoint_response(oauth2.MyIntrospectionEndpoint.ENDPOINT_NAME)
			if response.status_code == 401:
				log_failed_login(request)
			return respone




	#
	# user routes
	# (also see POST /user/login above)
	#


	# Decorator to protect views that require a user be authenticated
	# returns the looked-up user as named argument 'user'
	def user_login_required(func):
		@wraps(func)
		def wrapper(*args, **kwargs):
			user = get_session_user()
			if not user:
				return ("login_required", 403)
			return func(*args, user=user, **kwargs)
		return wrapper

	@app.route("/user/ui/<path:filename>", methods=['GET'])
	def get_user_ui_file(filename):
		return send_ui_file(filename)

	@app.route("/user/profile", methods=['GET'])
	def user_profile():
		return send_ui_file('user-profile-page.html')
	
	@app.route("/user/me", methods=['GET'])
	def user_me():
		mfa_state = ( request.args.get('mfa_state') == 'y' )
		return jsonify( get_me( include_mfa_state=mfa_state ))
			
	@app.route('/user/password', methods=['POST'])
	@user_login_required
	def user_password(user):
		try:
			data = json.loads(request.data)
			old_password = data['old_password']
			new_password = data['new_password']
			
		except (KeyError, json.decoder.JSONDecodeError) as e:
			return ("Invalid request", 400)

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
			return ("Invalid request", 400)

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
			log.error("Unable to disable MFA for user '%s': %s" % (user['user_id'], e))
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
			return ("Invalid request", 400)
						
		try:
			mfa_totp.validate_secret(secret)
		except ValueError as e:
			return (str(e), 400)

		try:
			mfa.enable_mfa(user['user_id'], "totp", secret, token, label, env)
		except ValueError as e:
			return jsonify(
				success=False,
				reason_key="mfa",
				reason=str(e)
			)
		
		return jsonify(success=True)


	@app.route('/user/logout')
	@user_login_required
	def user_logout(user):
		logout_session_user()
		return send_ui_file('user-profile-page.html')
			
