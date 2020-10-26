# -*- indent-tabs-mode: t; tab-width: 4; python-indent-offset: 4; -*-

#
# supports authorization code flow with refresh
#  see: https://auth0.com/docs/flows/authorization-code-flow
#  see: https://docs.authlib.org/en/latest/specs/rfc6749.html
#
 
from authlib.integrations.flask_oauth2 import AuthorizationServer

from authlib.oauth2.rfc7636 import CodeChallenge
from authlib.oauth2.rfc7009 import RevocationEndpoint
from authlib.oauth2.rfc7662 import IntrospectionEndpoint
from authlib.oauth2.rfc6750 import BearerToken

from authlib.oauth2.rfc6749 import TokenEndpoint
from authlib.oauth2.rfc6749 import InvalidGrantError

from authlib.common.security import generate_token

import time
import logging

from .Token import Token
from .MyAuthorizationCodeGrant import MyAuthorizationCodeGrant
from .MyRefreshTokenGrant import MyRefreshTokenGrant
from .server_globals import G

log = logging.getLogger(__name__)

	
class MyRevocationEndpoint(RevocationEndpoint):
	def query_token(self, token_string, token_type_hint, client):
		token = G.storage.find_token(token_string, token_type_hint)
		if token and token.get_client_id() == client.get_client_id():
			return token

	def revoke_token(self, token):
		G.storage.revoke_token(token)

		
class MyIntrospectionEndpoint(IntrospectionEndpoint):
	def query_token(self, token_string, token_type_hint, client):
		token = G.storage.find_token(token_string, token_type_hint)
		if token:
			if client.has_introspect_permission(token):
				return token
			else:
				log.info('%s: access to token "%s": not allowed' % (client.get_client_id(), token_string))
			
			
	def introspect_token(self, token):
		'''
		see: https://tools.ietf.org/html/rfc7662#section-2.2
		'''
		if not token or not token.is_active():
			if token:
				log.debug("introspect: token is inactive: %s" % token.access_token)
			return {
				"active": False
			}
		
		else:
			return {
				"active": True,                     # required
				"scope": token.scope,               # optional
				"client_id": token.get_client_id(), # optional
				"username": token.user_id,          # optional
				"token_type": token.token_type,     # optional
				"exp": token.get_expires_at(),      # optional
				"iat": token.get_issued_at(),       # optional
				#"nbf":   # optional: "not before"
				#"sub":   # optional: "subject of the token - user's ident"
				"aud": token.client_id,             # optional "audience"
				"iss": G.TOKEN_ISSUER,
				#"jti":   # optional: string identifier of the token
			}
			
			
			


def save_token(token, request):
	'''save a newly issued token

	    token is a dict from authlib, such as:
	    {"access_token": "wKXFz5VL7xf7cwxbhxpnkzj6XYZSVQREywwyk7Lz4g", "expires_in": 864000, "scope": "profile mailbox", "token_type": "Bearer"}
	'''
	# dir(request): ['__class__', '__delattr__', '__dict__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__', '__gt__', '__hash__', '__init__', '__init_subclass__', '__le__', '__lt__', '__module__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', '__weakref__', 'args', 'auth_method', 'body', 'client', 'client_id', 'credential', 'data', 'form', 'grant_type', 'headers', 'method', 'query', 'redirect_uri', 'response_type', 'scope', 'state', 'uri', 'user']
	#print(request.auth_method)  # "client_secret_basic"
	#print(request.client)       # AuthClient object
	#print(request.client_id)    # None
	#print(request.credential)   # AuthCode object
	#print(request.grant_type)   # "authorization_code"
	#print(request.redirect_uri) # None
	#print(request.scope)        # None
	#print(request.user)         # ldap3 object from find_mail_user()

	refresh_token_expires_in = request.client.get_token_policy(
		['OAUTH2_REFRESH_TOKEN_EXPIRES_IN', request.grant_type],
		token["expires_in"] * 2
	)
	
	d={
		"access_token": token.get('access_token', None),
		"refresh_token": token.get('refresh_token', None),
		"client_id": request.client.client_id,
		"user_id": request.user["user_id"],
		"issued_at": time.time(),
		"expires_in": token["expires_in"],
		"refresh_expires_in": refresh_token_expires_in,
		"scope": token["scope"],
		"token_type": token["token_type"]
	}

	if request.grant_type == 'authorization_code':
		G.storage.save_token(None, Token(d))

	elif request.grant_type == 'refresh_token':
		G.storage.save_token(request.credential, Token(d))

	else:
		log.info('unhandled grant type "%s" from %s' % (request.grant_type, request.client.client_name))
		raise InvalidGrantError()



class MyAuthorizationServer(AuthorizationServer):
	'''OAUTH2_TOKEN_EXPIRES_IN:

	    default values are from authlib's BearerToken class found in
	    authlib/oauth2/rfc6750/wrappers.py:

	    They are:

        authorization_code: 864000,
        implicit: 3600,
        password: 864000,
        client_credentials: 864000

	    Authlib code comments also refer to:

		'urn:ietf:params:oauth:grant-type:jwt-bearer': 3600

	    Any key not found when accessing the dict will receive the
	    default value of BearerToken.DEFAULT_EXPIRES_IN currently set
	    to 3600.

	    An AuthClient may override any of the settings below.

	'''

	OAUTH2_TOKEN_EXPIRES_IN = {
		# 'authorization_code': 60 * 60,   # access_token lifetime 1 hour
		'authorization_code': 60 * 2,   # access_token lifetime 1 hour
		# 'urn:ietf:params:oauth:grant-type:jwt-bearer': 3600,
	}	
	OAUTH2_ACCESS_TOKEN_GENERATOR=True
	OAUTH2_REFRESH_TOKEN_GENERATOR=False
	OAUTH2_ACCESS_TOKEN_LENGTH=42
	OAUTH2_REFRESH_TOKEN_LENGTH=48

	def __init__(self, app):
		super(MyAuthorizationServer, self).__init__(
			app=app,
			query_client=G.storage.query_client,
			save_token=save_token)

		# supported grants
		self.register_grant(MyAuthorizationCodeGrant, [CodeChallenge(required=True)])
		self.register_grant(MyRefreshTokenGrant)
	
		# support revocation
		self.register_endpoint(MyRevocationEndpoint)

		# support introspection
		self.register_endpoint(MyIntrospectionEndpoint)

		
	
	def create_token_expires_in_generator(self, config):
		'''override base class to provide per-client expires_in values
		   instead of universal ones. ignore `conifg`, which is
		   `app.config`.

		'''
		data={}
		data.update(BearerToken.GRANT_TYPES_EXPIRES_IN)
		data.update(self.OAUTH2_TOKEN_EXPIRES_IN)
		def expires_in(client, grant_type):
			return client.get_token_policy(
				['OAUTH2_TOKEN_EXPIRES_IN', grant_type],
				data.get(grant_type, BearerToken.DEFAULT_EXPIRES_IN)
			)
		return expires_in

	
	def create_bearer_token_generator(self, config):
		''' override base class to provide per-client configuration. ignore
		    `config` which is `app.config`

		'''
		defaults = {
			'OAUTH2_ACCESS_TOKEN_GENERATOR': self.OAUTH2_ACCESS_TOKEN_GENERATOR,
			'OAUTH2_REFRESH_TOKEN_GENERATOR': self.OAUTH2_REFRESH_TOKEN_GENERATOR,
			'OAUTH2_ACCESS_TOKEN_LENGTH': self.OAUTH2_ACCESS_TOKEN_LENGTH,
			'OAUTH2_REFRESH_TOKEN_LENGTH': self.OAUTH2_REFRESH_TOKEN_LENGTH
		}
			
		def access_token_generator(client, grant_type, user, scope):
			generate = client.get_token_policy(
				'OAUTH2_ACCESS_TOKEN_GENERATOR',
				defaults['OAUTH2_ACCESS_TOKEN_GENERATOR']
			)
			length = client.get_token_policy(
				'OAUTH2_ACCESS_TOKEN_LENGTH',
				defaults['OAUTH2_ACCESS_TOKEN_LENGTH']
			)
			if generate is True:
				return generate_token(length)

		def refresh_token_generator(client, grant_type, user, scope):
			generate = client.get_token_policy(
				'OAUTH2_REFRESH_TOKEN_GENERATOR',
				defaults['OAUTH2_REFRESH_TOKEN_GENERATOR']
			)
			length = client.get_token_policy(
				'OAUTH2_REFRESH_TOKEN_LENGTH',
				defaults['OAUTH2_REFRESH_TOKEN_LENGTH']
			)
			if generate is True:
				return generate_token(length)
		
		return BearerToken(
			access_token_generator,
			refresh_token_generator,
			self.create_token_expires_in_generator(config)
		)
