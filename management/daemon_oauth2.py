# -*- indent-tabs-mode: t; tab-width: 4; python-indent-offset: 4; -*-

import os
import logging
import json

from flask import (
	request,
	jsonify,
	send_from_directory
)
from authlib.integrations.flask_oauth2 import (
	current_token
)
from authlib.oauth2.rfc6749 import (
	OAuth2Error,
	InvalidClientError,
	MissingAuthorizationError
)
from daemon_sessions import (
	get_session_user,
	get_session_me
)

from oauth.server.SqliteStorage import SqliteStorage
from oauth.server.MiabClientsMixin import MiabClientsMixin
from oauth.server.MiabUsersMixin import MiabUsersMixin
import oauth.server.oauth2 as oauth2
import oauth.server.scope_properties as scope_properties


log = logging.getLogger(__name__)
oauth_ui_dir = os.path.join(os.path.dirname(__file__), 'oauth/ui')


def send_oauth_ui_file(filename):
	return send_from_directory(oauth_ui_dir, filename)


# Our oauth Storage class for persisting and querying users, tokens,
# clients, etc
class MyStorage(SqliteStorage, MiabClientsMixin, MiabUsersMixin):
	def __init__(self, env, db_path, auth_service, debug=False):
		self.env = env
		self.auth_service = auth_service
		self.debug = debug		
		super(MyStorage, self).__init__(db_path)


		
def add_oauth2(app, env, auth_service, log_failed_login):
	'''
	call this function to add authorization services

	requires:
       daemon_sessions

	`app` is a Flask instance
	`env` is the Mail-in-a-Box environment
	`auth_service` is the daemon.py's KeyAuthService instance
	`log_failed_login` is a function to be called when a login fails, which
          will log to syslog text that in-turn causes fail2ban to advance
	      its counter for possibly blocking the remote

	'''
	
	# instantiate client/user/token store
	STORAGE_OAUTH_ROOT=os.path.join(env["STORAGE_ROOT"], "authorization_server")
	storage = MyStorage(
		env,
		os.path.join(STORAGE_OAUTH_ROOT, "authserver.sqlite"),
		auth_service,
		app.debug
	)

	# create oauth2 authorization server		
	authorization, require_oauth = oauth2.create_auth_server(
		app,
		storage,
		env['PRIMARY_HOSTNAME'], # "issuer"
		os.path.join(STORAGE_OAUTH_ROOT,"keys/jwt_signing_key.json")
	)

	# allow Authlib to issue tokens over HTTP since daemon.py is
	# hidden behind Nginx (which handles HTTPS for us)
	os.environ['AUTHLIB_INSECURE_TRANSPORT']='1'

				
	#
	# oauth routes
	#

	@app.route("/oauth/ui/<path:filename>", methods=['GET'])
	def get_oauth_ui_file(filename):
		return send_oauth_ui_file(filename)
		
	@app.route("/oauth/authorize", methods=["GET","POST"])
	def authorize():
		'''OAuth2 authorization request

		'''
		log_opt = {	'client': request.args.get('client_id')	}
		log.debug("authorization request", log_opt)

		user = get_session_user()
		if not user:
			return send_oauth_ui_file('authorization-page.html')

		# validate OAuth2 parameters from client
		try:
			grant = authorization.validate_consent_request(end_user=user)
		except OAuth2Error as error:
			return (error.error, 400)

		# validate end-user consent
		consent = request.form.get('consent', 'false')
		if consent != 'true':
			return send_oauth_ui_file('authorization-page.html')

		log.info("authorization consent granted by user", log_opt)
		return authorization.create_authorization_response(grant_user=user)

	
	@app.route("/oauth/me", methods=['GET'])
	def oauth_me():
		''' public '''
		return jsonify( get_session_me() )
	
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
			return ("Bad request", 400)
			
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

	
	@app.route("/oauth/token", methods=['POST'])
	def issue_token():
		''' issue tokens '''
		grant_type = request.form.get('grant_type')
		log_opt = {	'client': request.form.get('client_id') }
		log.debug("request token for grant_type=%s", grant_type, log_opt)
		
		response = authorization.create_token_response(request)
		if response.status_code == 401:
			# client auth failed, log the attempt
			log_failed_login(request)
		elif response.status_code != 200:
			log.debug('returning token: %s', response.data, log_opt)
		return response


	@app.route("/oauth/revoke", methods=['POST'])
	def revoke_token():
		''' revoke tokens '''
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
		log.debug(
			'introspect granted to Bearer issued-to="%s" on-behalf-of="%s"',
			current_token.get_client_id(),
			current_token.user_id,
			{ 'client': 'Bearer' }
		)
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

