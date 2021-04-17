# -*- indent-tabs-mode: t; tab-width: 4; python-indent-offset: 4; -*-

import os
import json
import requests
import logging
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

log = logging.getLogger(__name__)


class MyJWTClaims(jose.JWTClaims):
	def has_priv(self, name):
		privs = self.get('privs')
		if not privs:
			return False
		if isinstance(privs, list):
			privs_list = privs
		else:
			privs_list = [ privs ]
		return name in privs_list

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
		

def decode_and_validate_jwt(oauth_config, jwt):
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
	log.debug('validate jwt: %s', jwt)
	claims = jose.jwt.decode(
		jwt,
		oauth_config['jwt_signature_key']['k'],
		MyJWTClaims,
		oauth_config['jwt_claims_options']
	)
	claims.validate()			
	return claims


def get_client_config(env):
	'''since we're on the same host as the oauth server, we can load the
	 client password directly

	'''
	client_config = os.path.join(
		env['STORAGE_ROOT'],
		'authorization_server/client_config.json'
	)
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

def obtain_access_token(authorization_code, oauth_config):
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
			'status=%s code=%s result=%s',
			post.status_code,
			authorization_code,
			post.text,
			{ 'client': oauth_config['client']['client_id'] }
		)

	# example post.json():
	# {"access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiIsImtpZCI6IjE2MTg2MTg5MzgifQ.eyJpc3MiOiJvYXV0aDIubG9jYWwiLCJhenAiOiJtaWFibGRhcCIsInN1YiI6InFhQGFiYy5jb20iLCJhdWQiOiJtaWFibGRhcC1jb25zb2xlIiwiaWF0IjoxNjE4NjU2ODkyLCJleHAiOjE2MTkyNjE2OTJ9.JyEcsaUrUsoNgOpxIv23D8z_jGwSCfFDgFSW3fZ3hN78bFsz_ijBh0hAUMI7nBb9E9lIRe7DnpNkB0f298ieiA", "expires_in": 604800, "refresh_token": null, "scope": "miabldap-console", "token_type": "Bearer"}
	return post
