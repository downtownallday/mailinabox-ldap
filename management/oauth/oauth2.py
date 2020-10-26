# -*- indent-tabs-mode: t; tab-width: 4; python-indent-offset: 4; -*-

#
# supporing authorization code flow, refresh
#  see: https://auth0.com/docs/flows/authorization-code-flow
#  see: https://docs.authlib.org/en/latest/specs/rfc6749.html
#
 
import logging

from authlib.integrations.flask_oauth2 import ResourceProtector
from authlib.oauth2.rfc6749 import ClientAuthentication
from authlib.oauth2.rfc6749.util import extract_basic_authorization
from authlib.oauth2.rfc6749 import InvalidClientError

from .MyAuthorizationServer import *
from .MyBearerTokenValidator import MyBearerTokenValidator
from .server_globals import G, init_server_globals

log = logging.getLogger(__name__)


def authenticate_client(request, required=True):
	''' authenticate the client with basic auth

	'''
	client_id, client_secret = extract_basic_authorization(request.headers)
	if client_id and client_secret:
		client_authenticator = 	ClientAuthentication(G.storage.query_client)
		client = client_authenticator.authenticate(   # throws
		 	request,
		 	[ 'client_secret_basic' ]
		)
		return client
	
	if required:
		raise InvalidClientError(status_code=401)
	

def create_auth_server(app, storage_inst):
	init_server_globals(storage_inst)

	# the authorization server instance
	authorization = MyAuthorizationServer(app)

	# protect resources with @require_oauth("scope"), requiring a
	# user supply a Bearer token that has access to the named scope
	require_oauth = ResourceProtector()
	bearer_token_validator = MyBearerTokenValidator()
	require_oauth.register_token_validator(bearer_token_validator)

	return authorization, require_oauth
