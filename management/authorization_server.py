# -*- indent-tabs-mode: t; tab-width: 4; python-indent-offset: 4; -*-

#
# startup:
#
#   source /usr/local/lib/mailinabox/env/bin/activate
#   python3 authorization_server.py
#
# requirements:
#
#   pip install Authlib
#
# test:
#
#   1. [k9] get an authorization code. in browser:
#      a. https://localhost:8443/admin/oauth/authorize?response_type=code&client_id=mail-user&scope=profile%20mailbox%20introspect
#      b. login at redirect
#      c. should now be at {redirect_uri}?code=<code>
#
#   2. [k9] get an access token
#      curl -u mail-user:x -XPOST http://localhost:10222/oauth/token -F grant_type=authorization_code -F code=${code}
#
#   3. [k9] log into dovecot/imap w/xoauth2 using token
#
#   4. [dovecot] call tokeninfo & introspection api to verify token:
#      curl -u dovecot:Test_1234 http://localhost:10222/oauth/v1/tokeninfo?access_token=${access_token}
#      curl -XPOST -H "Authorization: Bearer ${access_token}" http://localhost:10222/oauth/v1/introspect -F token="${access_token}" -F token_type_hint=access_token
#      curl -u dovecot:Test_1234 -XPOST http://localhost:10222/oauth/v1/userinfo -F token="${access_token}" -F token_type_hint=access_token
#      curl -H "Authorization: Bearer ${access_token}" http://localhost:10222/api/v1/me
#
#   5. [roundcube] revoke
#      curl -u roundcube:rcm_test_123 -XPOST http://localhost:10222/oauth/revoke -F token="${access_token}"
#

from flask import Flask, request, session, url_for, render_template, redirect, jsonify
from authlib.integrations.flask_oauth2 import current_token
from authlib.oauth2 import OAuth2Error

import os, uuid, logging, json
import urllib.parse

import utils, backend
from mailconfig import find_mail_user, validate_login
from oauth.SqliteStorage import SqliteStorage
from oauth.MiabClientsMixin import MiabClientsMixin
from oauth.MiabUsersMixin import MiabUsersMixin
import oauth.oauth2 as oauth2

# init logging
logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)

# load mail-in-a-box environment
env = utils.load_environment()

# create Flask app
app = Flask(__name__, template_folder=os.path.abspath(os.path.join(os.path.dirname(__file__), "templates")))
app.debug = True

# set secret_key to enable sessions - this random uuid will invalidate
# all previous sessions
app.secret_key = uuid.uuid4().hex


# manage sessions
def get_user(email):
	user = find_mail_user(env, email, attributes=['cn','mail','maildrop'])
	if user:
		user['user_id'] = user['maildrop'][0]
	return user
    
def get_session_user():
	''' get the current logged-in user '''
	if 'user_id' not in session: return None
	user_id = session['user_id']
	return get_user(user_id)


# authlib configuration
class MyStorage(SqliteStorage, MiabClientsMixin, MiabUsersMixin):
	def __init__(self, env, db_path):
		self.env = env
		super(MyStorage, self).__init__(db_path)
		

authorization, require_oauth = oauth2.create_auth_server(
	app,
	MyStorage(env, os.path.join(env["STORAGE_ROOT"], "authorization_server", "authserver.sqlite"))
)



#
# routes
#

@app.route("/login", methods=["GET", "POST" ])
def login():
	if request.method == 'GET':
		print("RENDER: authorization_login.html")
		return render_template('authorization_login.html')
	email = request.form.get('username')
	pw = request.form.get('password')
	log.debug("GOT user=%s, pw=%s" % (email, pw))

	# TODO: check TOTP
	try:
		ok = validate_login(email, pw, env)
		if not ok: raise ValueError('Invalid username or password')
	except ValueError as e:
		log.debug("LOGIN VALIDATION FAILED: %s" % e)
		return render_template("authorization_login.html", error=str(e))

	log.debug("LOGIN VALIDATION SUCCEEDED - redirect to 'next=%s" % request.args.get("next"))
	user = get_user(email)
	session['user_id'] = user['user_id']
	return redirect(request.args.get('next'))
    

@app.route("/logout")
def logout():
	del session['email']
	return redirect("/login")


@app.route("/oauth/authorize", methods=["GET","POST"])
def authorize():
	user = get_session_user()
	if not user:
		log.debug("REDIRECT: /login?next=" + urllib.parse.quote(request.full_path))
		return redirect("/login?next=" + urllib.parse.quote(request.full_path))

	log.debug("GOT SESSION USER '%s'" % user["cn"][0])
	if request.method == 'GET':
		try:
			log.debug("VALIDATE CONSENT REQUEST")
			grant = authorization.validate_consent_request(end_user=user)
		except OAuth2Error as error:
			log.debug("GET GRANT FAILED: %s" % error)
			return error.error
		log.debug("GET GRANT SUCCEEDED: %s" % grant)
		return render_template('authorize.html', user=user, grant=grant)
	
	if 'email' in request.form:
		user = get_user(request.form.get('email'))
        
	if "confirm" in request.form:
		grant_user = user
	else:
		grant_user = None

	return authorization.create_authorization_response(grant_user=grant_user)


@app.route("/oauth/token", methods=['POST'])
def issue_token():
	log.debug("FUNC issue_token: POST data=%s" % request.form)
	return authorization.create_token_response(request)


@app.route("/oauth/revoke", methods=['POST'])
def revoke_token():
	return authorization.create_endpoint_response(oauth2.MyRevocationEndpoint.ENDPOINT_NAME)


@app.route("/api/v1/me")
@require_oauth('profile')
def api_v1_me():
	''' `current_token` is an oauth.storage.Token object '''
	user = get_user(current_token.user_id)
	return jsonify({
		"username": user["user_id"],
		"name": user["cn"][0]
	})


@app.route("/oauth/v1/introspect", methods=["GET"])
@require_oauth('introspect')
def v1_introspect_get():
	''' introspection per rfc with Authorization: Bearer

	'''
	ep = oauth2.MyIntrospectionEndpoint(authorization)
	return jsonify(ep.introspect_token(current_token))


@app.route("/oauth/v1/tokeninfo", methods=["GET", "POST"])
def v1_introspect_post():
	''' allow clients to get token information

	'''
	if request.method == "GET":
		access_token_string = request.args.get("access_token")
		if not access_token_string:
			return ('Access token is required', 400)
        
		# setting the state is required or boom in
		# authlib/oauth2/rfc6749/authenticate_client.py", line 6
		request.state = request.args.get('state')

		# authenticate the client using basic auth
		client = oauth2.authenticate_client(request, required=True)

		# introspect the access_token supplied
		ep = oauth2.MyIntrospectionEndpoint(authorization)
		token = ep.query_token(access_token_string, "access_token", client)
		return jsonify(ep.introspect_token(token))

	else:
		return authorization.create_endpoint_response(oauth2.MyIntrospectionEndpoint.ENDPOINT_NAME)



app.run(port=10222)

