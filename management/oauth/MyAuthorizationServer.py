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

from authlib.oidc.core.grants import OpenIDCode
from authlib.oidc.core import UserInfo

from authlib.common.security import generate_token
from authlib.common.encoding import (to_bytes, urlsafe_b64encode, json_b64encode, urlsafe_b64decode)
from authlib import jose


import time
import logging
import os
import json
import base64

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
			perm = client.get_introspect_permission(token)
			log_opts = { 'client': client.client_id }
			if perm:
				log.debug(
					'introspect granted perm=%s issued-to="%s" on-behalf-of="%s"',
					perm,
					token.get_client_id(),
					token.user_id,
					log_opts
				)
				return token
			else:
				log.warning(
					'introspect denied token=%s token_type_hint=%s',
					token_string,
					token_type_hint,
					log_opts
				)
			
			
	def introspect_token(self, token):
		'''
		see: https://tools.ietf.org/html/rfc7662#section-2.2
		'''
		if not token or not token.is_active():
			if token and log.isEnabledFor(logging.DEBUG):
				log.debug(
					"introspect: token is inactive: %s", token.access_token,
					{ 'client': token.get_client_id() }
				)
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
		log.info(
			'unhandled grant type "%s"', request.grant_type,
			{ 'client': request.client.client_id }
		)
		raise InvalidGrantError()

	log_opt = { 'client': d['client_id'] }
	token_types = [ key for key in ['access_token','refresh_token'] if d[key] ]
	log.info(
		'%s issued for grant_type=%s scope="%s" on-behalf-of="%s"',
		','.join(token_types),
		request.grant_type,
		d['scope'],
		d['user_id'],
		log_opt
	)



class MyOpenIDCode(OpenIDCode):
	'''this attaches 'id_token' to the returned json of a token grant. to
       activate, the authorization request must include 'openid' in
       the list of scopes

	'''
	def get_jwt_config(self, grant):
		'''
		grant = AuthorizationCodeGrant instance
		'''
		jwt_signing_key = grant.server.get_jwt_signing_key()
		client = grant.client
		# exp = grant.server.generate_token._get_expires_in(
		# 	client,
		# 	grant.request.grant_type
		# )
		exp = client.get_token_policy(
			['OAUTH2_TOKEN_EXPIRES_IN', grant.request.grant_type]
		)
		
		config = {
			'alg': jwt_signing_key['alg'],
			'key': jwt_signing_key['k'],
			'iss': G.TOKEN_ISSUER,
			'exp': exp
		}
		log.debug("OPENID: grant=%s jwt_config=%s" % (grant, config))
		return config

	def get_audiences(self, request):
		# overrides the base class
		#
		# this ends up in id_token as 'aud'. roundcube (pre-release)
		# currently requires that it matches the roundcube client id
		# 'roundcube' and cannot be an array (the base class returns
		# an array, or we wouldn't need to override this).
		#
		# 'aud' in id_token is different than 'aud' in the jwt token
		# itself which will be a list of scopes (as required by dovecot).
		client = request.client
		return client.get_client_id()

	def exists_nonce(self, nonce, request):
		return False

	def generate_user_info(self, user, scope):
		# roundcube gets the username from id_token (avoiding an
		# introspection request). see roundcube config
		# $config['oauth_identity_fields']
		user_info = UserInfo(
			sub=user['user_id'],
			username=user['user_id'],
			name=user['cn'][0],
			email=user['mail'][0],
		)
		#if 'mailbox' in scope:
		#	user_info['email'] = user['mail'][0]
		log.debug("OPENID: user_info=%s" % user_info)
		return user_info
	


class MyAuthorizationServer(AuthorizationServer):

	def __init__(self, app, jwt_signing_key_path):
		super(MyAuthorizationServer, self).__init__(
			app=app,
			query_client=G.storage.query_client,
			save_token=save_token)

		self.jwt_signing_key_path = jwt_signing_key_path
				
		# supported grants
		self.register_grant(MyAuthorizationCodeGrant, [CodeChallenge(required=True), MyOpenIDCode()])
		self.register_grant(MyRefreshTokenGrant)
	
		# support revocation
		self.register_endpoint(MyRevocationEndpoint)

		# support introspection
		self.register_endpoint(MyIntrospectionEndpoint)


	def get_jwt_signing_key(self):
		with open(self.jwt_signing_key_path) as f:
			jwt_signing_key = json.loads(f.read())
			jwt_signing_key['k'] = \
				urlsafe_b64decode(to_bytes(jwt_signing_key['k']))
			return jwt_signing_key
		
	
	def create_token_expires_in_generator(self, config):
		'''override base class to provide per-client expires_in values
		   instead of universal ones. ignore `conifg`, which is
		   `app.config`.

		'''
		def expires_in(client, grant_type):
			return client.get_token_policy(['OAUTH2_TOKEN_EXPIRES_IN', grant_type])
		return expires_in

	
	def create_bearer_token_generator(self, config):
		''' override base class to provide per-client configuration. ignore
		    `config` which is `app.config`

		'''
		expires_in_fn = self.create_token_expires_in_generator(config)
		
		def access_token_generator(client, grant_type, user, scope):
			generate = client.get_token_policy('OAUTH2_ACCESS_TOKEN_GENERATOR')
			if not generate:
				return None

			jwt_tokens = client.get_token_policy('OAUTH2_JWT_TOKENS')
			
			if not jwt_tokens:
				length = client.get_token_policy('OAUTH2_ACCESS_TOKEN_LENGTH')
				return generate_token(length)

			else:
				jwt_signing_key = self.get_jwt_signing_key()
				
				# see: https://docs.authlib.org/en/latest/specs/rfc7519.html
				header = {
					'typ': 'JWT',
					'alg': jwt_signing_key['alg'],
					'kid': jwt_signing_key['kid'],
				}
				iat = int(time.time()) # issued-at
				claims = client.jwt_private_claims(client, grant_type, user, scope)
				claims.update({
					'iss': G.TOKEN_ISSUER,
					'azp': client.get_client_id(),
					'sub': user['user_id'],
					'aud': client.get_allowed_scope(scope),
					'iat': iat,
					'exp': iat + expires_in_fn(client, grant_type)
				})
				key = jwt_signing_key['k']
				signed_token = jose.jwt.encode(header, claims, key)
				
				log_opts = { 'client': client.client_id }
				log.debug('generate jwt token: header=%s claims=%s signed=%s',
						  header, claims, signed_token, log_opts)
				
				return signed_token.decode('utf-8')
			

		def refresh_token_generator(client, grant_type, user, scope):
			generate = client.get_token_policy('OAUTH2_REFRESH_TOKEN_GENERATOR')
			if generate:
				length = client.get_token_policy('OAUTH2_REFRESH_TOKEN_LENGTH')
				return generate_token(length)
		
		return BearerToken(
			access_token_generator,
			refresh_token_generator,
			expires_in_fn
		)
