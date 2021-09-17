# -*- indent-tabs-mode: t; tab-width: 4; python-indent-offset: 4; -*-

import os
import json
import requests
import logging
import urllib

import encryption_utils

from authlib.common.encoding import (
	to_bytes,
	urlsafe_b64decode,
)
from authlib import jose
from authlib.jose.errors import (
    MissingClaimError,
    InvalidClaimError,
    ExpiredTokenError,
    InvalidTokenError,
)
from flask import (
	jsonify,
	redirect
)


log = logging.getLogger(__name__)


class MyJWTClaims(jose.JWTClaims):
	def get_privs(self):
		privs = self.get('privs')
		if not privs:
			return []
		if isinstance(privs, list):
			return privs
		else:
			return [ privs ]
		
	def has_priv(self, name):
		return name in self.get_privs()

	def get_user_id(self):
		return self.get('sub')

	def get_expires(self):
		# seconds since unix epoch
		return self.get('exp')

	def validate(self, now=None, leeway=0):
		# validate claims
		# Throws:
		#   MissingClaimError
		#   InvalidClaimError
		#   ExpiredTokenError
		#   InvalidTokenError
		aud = self.get('aud')
		if aud and isinstance(aud, str):
			self['aud'] = aud.split(' ')
		super(MyJWTClaims, self).validate(now, leeway)
		

def decode_and_validate_jwt(oauth_config, jwt, leeway=0):
	'''
	1. validates the signature on the jwt using the siging key
	oauth_config['jwt_signature_key']

	2. validates the required claims and values as defined in
	oauth_config['jwt_claims_options'] (see Authlib source
    authlib/jose/rfc7519/claims.py)
	
	Retuns: a MyJWTClaims instance

	Throws jose errors:
	   DecodeError
	   BadSignatureError
	   MissingClaimError
	   InvalidClaimError
	   ExpiredTokenError
	   InvalidTokenError

	'''
	claims = jose.jwt.decode(
		jwt,
		oauth_config['jwt_signature_key']['k'],
		MyJWTClaims,
		oauth_config['jwt_claims_options']
	)
	claims.validate(leeway=leeway)			
	return claims


def get_client_config(env):
	''' retrieve the oauth config for the managment console
	    returns: dict
	'''
	client_config = '/var/lib/mailinabox/mgmt_oauth_config.json'
	with open(client_config) as f:
		return json.loads(f.read())

def get_jwt_signature_verification_key(env):
	'''return the signing verification key as a dict
	eg: {
	     "kty": "oct",
	     "alg": "HS256",
	     "kid": "1618498344",
	     "k": <bytes>
        }

	 since we're on the same host as the oauth server, we can load the
	 server's key directly (HMAC shared secret)

	'''
	jwt_signing_key_path = os.path.join(
		env['STORAGE_ROOT'],
		'authorization_server/keys/jwt_signing_key.json'
	)
	
	with open(jwt_signing_key_path) as f:
		jwt_signing_key = json.loads(f.read())
		jwt_signing_key['k'] = \
			urlsafe_b64decode(to_bytes(jwt_signing_key['k']))
		return jwt_signing_key


def obtain_access_token(oauth_config, authorization_code):
	'''	obtain an access token using an authorization code grant '''
	post = requests.post(
		oauth_config['client']['oauth_token_url'],
		auth=(
			oauth_config['client']['client_id'],
			oauth_config['client']['client_password']
		),
		data=[
			('grant_type', 'authorization_code'),
			('code', authorization_code),
			('redirect_uri', oauth_config['client']['authorize_url'])
		],
		allow_redirects=False,
		timeout=5, # seconds
	)

	if post.status_code != 200:
		log.error(
			'status=%s result=%s',
			post.status_code,
			post.text,
			{ 'client': oauth_config['client']['client_id'] }
		)

	# example post.json():
	# {"access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiIsImtpZCI6IjE2MTg2MTg5MzgifQ.eyJpc3MiOiJvYXV0aDIubG9jYWwiLCJhenAiOiJtaWFibGRhcCIsInN1YiI6InFhQGFiYy5jb20iLCJhdWQiOiJtaWFibGRhcC1jb25zb2xlIiwiaWF0IjoxNjE4NjU2ODkyLCJleHAiOjE2MTkyNjE2OTJ9.JyEcsaUrUsoNgOpxIv23D8z_jGwSCfFDgFSW3fZ3hN78bFsz_ijBh0hAUMI7nBb9E9lIRe7DnpNkB0f298ieiA", "expires_in": 604800, "refresh_token": null, "scope": "miabldap-console", "token_type": "Bearer"}
	return post


def refresh_access_token(oauth_config, refresh_token):
	'''obtain a new access token and new refresh_token using a refresh
	token

	'''
	post = requests.post(
		oauth_config['client']['oauth_token_url'],
		auth=(
			oauth_config['client']['client_id'],
			oauth_config['client']['client_password']
		),
		data=[
			('grant_type', 'refresh_token'),
			('refresh_token', refresh_token),
		],
		allow_redirects=False,
		timeout=5, # seconds
	)

	if post.status_code != 200:
		log.error(
			'status=%s result=%s',
			post.status_code,
			post.text,
			{ 'client': oauth_config['client']['client_id'] }
		)

	return post


def revoke_token(oauth_config, token, token_type):
	'''revoke the token'''
	post = requests.post(
		oauth_config['client']['oauth_revoke_url'],
		auth=(
			oauth_config['client']['client_id'],
			oauth_config['client']['client_password']
		),
		data=[
			('token', token),
			('token_type_hint', token_type),
		],
		allow_redirects=False,
		timeout=5, # seconds
	)

	if post.status_code != 200:
		log.error(
			'status=%s result=%s',
			post.status_code,
			post.text,
			{ 'client': oauth_config['client']['client_id'] }
		)

	return post


def create_authorization_response(oauth_config, code, state):
	# obtain an access token from the oauth server
	post = obtain_access_token(oauth_config, code)
	if post.status_code == 400:
		#json = post.json()
		#return ( json.get('error_description', json.get('error')), 400 )
		return redirect('/')
	elif post.status_code != 200:
		return ("Error contacting oauth server", 500)

	# decode and validate the access token; get the user id
	json = post.json()
	try:
		claims = decode_and_validate_jwt(
			oauth_config,
			json['access_token']
		)
	except Exception as e:
		log.error(
			'unable to validate token!', 
			{ 'client': oauth_config['client']['client_id'] },
			exc_info=e
		)
		return (str(e), 500)

	def setcookie(name, value):
		response.headers.add('Set-Cookie', f'{name}={urllib.parse.quote(value)}; Secure; Path=/; SameSite=Strict; max-age=30')

	# redirect with the access token in cookies
	response = redirect('/') 
	setcookie("auth-user", claims.get_user_id())
	setcookie("auth-token", json['access_token'])
	setcookie("auth-refresh-token", encryption_utils.encrypt(json['refresh_token']))
	setcookie("auth-expires-in", str(json['expires_in'])),
	setcookie("auth-privileges", ",".join(claims.get_privs()))
	setcookie("auth-state-ssi", str(state['ssi']))
	return response




def create_refresh_response(oauth_config, request, s_refresh_token):
	try:
		refresh_token = encryption_utils\
			.decrypt(s_refresh_token)\
			.decode('ascii', 'strict')
	except Exception as e:
		log.warning('refresh_token failed validation: %s', str(e))
		return ('Token not valid', 403)
	
	# retrieve new tokens from the oauth server
	post = refresh_access_token( oauth_config, refresh_token )
	if post.status_code >= 400 and post.status_code < 500:
		log.warning('refresh_token rejected: %s', post.text)
		return ('Token not valid', 403)
	elif post.status_code != 200:
		return ("Error contacting oauth server", 500)
	
	log_opts = oauth_log_opts = {
		'client': oauth_config['client']['client_id'],
		'username': request.user_email
	}

	# decode and validate the new access_token token
	json = post.json()
	try:
		claims = decode_and_validate_jwt(
			oauth_config,
			json['access_token']
		)
		if request.user_email != claims.get_user_id():
			# authenticated user has someone else's refresh token!
			log.warning('Refreshed token user id mismatch!: token user=%s', claims.get_user_id(), log_opts)
			#raise InvalidClaimError('sub')
			return ('Invalid request', 403)

	except Exception as e:
		log.error('unable to validate token!', log_opts, exc_info=e)
		return (str(e), 500)

	return jsonify({
		"token": json['access_token'],
		"refresh_token": encryption_utils.encrypt(json['refresh_token']),
		"expires_in": json['expires_in'],
		"privileges": claims.get_privs()
	})


def create_revoke_response(oauth_config, s_refresh_token):
	try:
		refresh_token = encryption_utils\
			.decrypt(s_refresh_token)\
			.decode('ascii', 'strict')
	except Exception as e:
		log.warning('refresh_token failed validation: %s', str(e))
		return (InvalidTokenError().error, 403)
	
	post = revoke_token( oauth_config, refresh_token, 'refresh_token' )
	if post.status_code == 200:
		return "OK"
	if post.status_code >= 400 and post.status_code <500:
		log.warning('revoke rejected: %s', post.text)
		return (post.json().get('error', InvalidTokenError().error), 403)
	else:
		return ("Error contacting oauth server", 500)
