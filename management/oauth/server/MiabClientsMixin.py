# -*- indent-tabs-mode: t; tab-width: 4; python-indent-offset: 4; -*-

import logging
import subprocess
from urllib.parse import urlparse
import subprocess
import os
import json
import time

from .Storage import Storage
from .AuthClient import AuthClient

from .errors import (
	InsufficientPrivilegeError
)

log = logging.getLogger(__name__)

class ParseError(Exception):
	def __init__(self, message):
		self.message = message


class MiabClientsMixin(Storage):

	clients = { }

	def get_oauth_pw_from_local_roundcubemail(self):
		'''get the oauth shared secret directly from the local installation
        of roundcubemail

		'''
		RCM_CONFIG_DIR="/usr/local/lib/roundcubemail/config"
		pw = subprocess.check_output([
			'php',
			'-r',
			"require('config.inc.php'); print($config['oauth_client_secret']);"
		], cwd=RCM_CONFIG_DIR)
		pw = pw.decode('utf-8')
		return pw

	def get_oauth_pw_from_local_dovecot(self):
		DOVECOT_OAUTH2_CONFIG="/etc/dovecot/dovecot-oauth2.conf.ext"
		pw = None
		with open(DOVECOT_OAUTH2_CONFIG) as f:
			line=None
			while line != '':
				line = f.readline()
				if line.startswith('tokeninfo_url'):
					url = urlparse(line[line.index('=')+1:].strip())
					pw = url.password
					break
		if not pw:
			raise ParseError("Unable to extract dovecot client password from %s" % DOVECOT_OAUTH2_CONFIG)
		return pw

	def get_dovecot_version(self):
		result = subprocess.check_output(
			['/usr/sbin/dovecot', '--version'],
			encoding='utf-8'
		)
		idx = result.find(' ')
		if idx>0: result = result[0:idx]
		v = result.split('.')
		major = int(v[0])
		minor = int(v[1])
		release = int(v[2])
		log.debug('dovecot version is %s.%s.%s' % (major, minor, release))
		return major, minor, release

	def get_console_client_info(self):
		client_config = "/var/lib/mailinabox/mgmt_oauth_config.json"
		with open(client_config) as f:
			return json.loads(f.read())
	
	def query_client(self, client_id):

		if client_id in self.clients:
			return self.clients[client_id]

		inst = None
		
		if client_id == "roundcube":
			#
			# for now, since roundcube is installed locally, get the
			# shared secret directly from the local roundcube
			# config.inc.php file
			#
			pw = self.get_oauth_pw_from_local_roundcubemail()

			#
			# only dovecot 2.3.11 and higher support JWT tokens
			#
			(major, minor, release) = self.get_dovecot_version()
			jwt_tokens = (major>=2 and minor>=3 and release>=11)
			if jwt_tokens:
				log.debug('will send JWT tokens to roundcube/dovecot')

			#
			# private claims function providing additional JWT claims
			# required by dovecot and roundcube
			#
			def jwt_private_claims(client, grant_type, user, scope):
				return {
					# required by dovecot
					'username': user['user_id'],
					'active': True,
					# Add jti to avoid UNIQUE contraint failure when
					# roundcube sends simultaneous refresh
					# queries. Without jti, each of the generated
					# access tokens are identical since all claims are
					# identical, including 'iat' which is accurate
					# only to the second
					'jti': str(time.time()) # eg: "1632396409.6227248"
				}

			# create the AuthClient instance
			inst = AuthClient(
				'roundcube',
				'Roundcube',
				# roundcube client password
				pw,
				
				# scopes supported
				[
					'introspect',
					'mailbox',
					'openid'
				],
				
				# valid redirect uri prefixes
				[
					'https://' + self.env['PRIMARY_HOSTNAME'] + '/mail/',
				],
				
				token_policy = {
					'OAUTH2_TOKEN_EXPIRES_IN': {
						# access_token lifetime per grant_type
						#'authorization_code': 60 * 60 * 24
						'authorization_code': 60 * (1 if self.debug else 15),
						'refresh_token': 60 * (1 if self.debug else 15),
					},
					'OAUTH2_REFRESH_TOKEN_EXPIRES_IN': {
						# refresh_token lifetime per grant_type
						'authorization_code': 60 * 60 * 24 * 1,
						'refresh_token': 60 * 60 * 24 * 7
					},
					'OAUTH2_REFRESH_TOKEN_GENERATOR': True,
					'OAUTH2_REVOKE_DELAY_SECS': 5,
					'OAUTH2_JWT_TOKENS': jwt_tokens
				},

				jwt_private_claims_fn = jwt_private_claims
			)

		elif client_id == "dovecot":
			#
			# for now, since dovecot is installed locally, get the
			# shared secret directly from the local dovecot
			# config file
			#
			pw = self.get_oauth_pw_from_local_dovecot()

			# create the AuthClient instance
			inst = AuthClient(
				'dovecot',
				'dovecot bearer authorization client',
				pw,
				[],      # scopes supported
				None,                # expected redirect_uri prefix
				perms=['introspect-any']  # special permissions
			)

		elif client_id == "miabldap":
			client_config = self.get_console_client_info()
			
			#
			# private claims function providing additional JWT claims
			# required by the console
			#
			def jwt_private_claims(client, grant_type, user, scope):
				return {
					'privs': user['mailaccess']
				}

			# create the AuthClient instance
			inst = AuthClient(
				client_id,

				# name
				'Mail-in-a-Box Control Panel',

				# client password
				client_config['client_password'],

				# scopes supported
				[ 
					'introspect',
					'miabldap-console'
				],

				# valid redirect uri prefixes
				[ 
					client_config['authorize_url']
				],

				token_policy = {
					'OAUTH2_TOKEN_EXPIRES_IN': {
						# access_token lifetime per grant_type
						'authorization_code': 60 * (1 if self.debug else 15),
						'refresh_token': 60 * (1 if self.debug else 15)
					},
					'OAUTH2_REFRESH_TOKEN_EXPIRES_IN': {
						# refresh_token lifetime per grant_type
						'authorization_code': 60 * 60 * 24 * 1,
						'refresh_token': 60 * 60 * 24 * 7
					},
					'OAUTH2_REFRESH_TOKEN_GENERATOR': True,
					'OAUTH2_JWT_TOKENS': True,
				},

				jwt_private_claims_fn = jwt_private_claims
			)

		elif client_id == "miabldap-cli":
			#
			# private claims function providing additional JWT claims
			# required by the console
			#
			def jwt_private_claims(client, grant_type, user, scope):
				return {
					'privs': user['mailaccess']
				}

			def check_user_restrictions_fn(user):
				# only allow admin users
				if user is None:
					return None
				if 'admin' not in user['mailaccess']:
					log.warning(
						'Authorization of user restricted - not an admin',
						{ "username": user['user_id'],
						  "client": 'miabldap-cli' }
					)
					raise InsufficientPrivilegeError()
				else:
					return user

			# create the AuthClient instance
			inst = AuthClient(
				client_id,

				# name
				'Mail-in-a-Box CLI',

				# client password
				'miabldap-cli',

				# scopes supported
				[ 
					'introspect',
					'miabldap-console'
				],

				# valid redirect uri prefixes
				None,

				grant_types = [
					"password"
				],

				token_policy = {
					'OAUTH2_TOKEN_EXPIRES_IN': {
						# access_token lifetime per grant_type
						'password': 60 * (5 if self.debug else 60),
					},
					'OAUTH2_REFRESH_TOKEN_GENERATOR': False,
					'OAUTH2_JWT_TOKENS': True,
				},

				check_user_restrictions_fn = check_user_restrictions_fn,
				jwt_private_claims_fn = jwt_private_claims
			)


		if inst:
			self.clients[client_id] = inst
			return inst
		
		log.info('storage.query_client: client_id "%s": not found!' % client_id)

		return None
