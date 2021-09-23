#!/usr/bin/python3
# -*- indent-tabs-mode: t; tab-width: 4; python-indent-offset: 4; -*-
#
# This is a command line tool that obtains an access token that may be
# used for API calls to the MIAB-LDAP console.
#
# To use it with the management/cli.py tool, set the environment variable
# MIAB_ACCESS_TOKEN to the output of this tool. eg:
#
# from a shell:
#     export MIAB_ACCESS_TOKEN_SERVER=<miab-server>
#     export MIAB_ACCESS_TOKEN=$(access_token.py $MIAB_ACCESS_TOKEN_SERVER <username> <password>)
#     management/cli.py user
#

import requests
import urllib.parse
import json
import sys
import logging
import os

log = logging.getLogger(__name__)


def usage():
	print(f"Usage: {sys.argv[0]} [-debug] [-output-sh] [-method-code] server username password [totp-code]")
	print(f"    -debug: turn on debug output/logging")
	print(f"    -output-sh: output shell commands")
	print(f"    -method-code use the oauth2 authorization code method instead of the resource owner password method. note that the resource owner password method requires that the user be admin, but the authorization code method does not. server must be 'localhost'")
	print(f"    server: the fully-qualified domain name of your miab-ldap server")
	print(f"    username: the email address of an admin to obtain an access token for")
	print(f"    password: the login password for 'username'")
	print(f"    totp-code: supply a TOTP code for 'username' if TOTP is enabled on the account")
	sys.exit(1)


def verify_ca_bundle():
	# valid root certificates ---
	#   urllib3 expects the return value of this function to be:
	#      True to do certificate validation with python's ca bundle
	#      False to not check certificates at all, or
	#      a path to a valid certificate bundle
	bundles = [
		'/etc/ssl/certs/ca-certificates.crt', # debian
	]
	for bundle in bundles:
		if os.path.exists(bundle): return bundle
	return True


def get_client_config(server, method):

	if method == 'authorization_code':
		if server not in [None, 'localhost', '127.0.0.1', '::1']:
			raise ValueError('server must be localhost when using the authorization code method')		
		client_config = '/var/lib/mailinabox/mgmt_oauth_config.json'
		with open(client_config) as f:
			client_config = json.loads(f.read())

		# so the session cookie from user_login_url is valid in
		# oauth_login_url, we must ensure they use the same host
		oauth_login_url=urllib.parse.urlparse(client_config['oauth_login_url'])
		prefix='/auth'
		if oauth_login_url.netloc in ['localhost', '127.0.0.1', '::1']:
			prefix = ''
		client_config.update({
			"server": server,
			"verify_server_certs": verify_ca_bundle(),
			"scope": "miabldap-console",
			"user_login_url": f"{oauth_login_url.scheme}://{oauth_login_url.netloc}{prefix}/user/login",
		})
		return client_config

	else:
		client_config = {
			"server": server,
			"verify_server_certs": verify_ca_bundle(),
			"client_id": "miabldap-cli",
			"client_password": "miabldap-cli",
			"scope": "miabldap-console",
			"oauth_token_url": f"https://{server}/auth/oauth/token",
		}
		if server in [None, 'localhost', '127.0.0.1', '::1']:
			for key in ['oauth_token_url']:
				client_config[key] = client_config[key].replace(f"https://{server}/auth/", 'http://127.0.0.1:10222/')
		
		return client_config


	
def process_command_line():
	opt = {
		"server": None,
		"username": None,
		"password": None,
		"second_factor": None,
		"debug": False,
		"output_format": "plain",
		"method": "password"   # ResourceOwnerPasswordCredentialsGrant
	}
	argi=1
	while argi < len(sys.argv):
		arg = sys.argv[argi]
		if arg.startswith('-'):
			if arg=="-debug" or arg=='-d':
				opt["debug"] = True
				argi += 1
			elif arg=="-output-sh":
				opt["output_format"] = "sh"
				argi += 1
			elif arg=="-method-code":
				opt["method"] = "authorization_code" # authorization code method
				argi += 1
			elif arg=="-method-password":
				opt["method"] = "password" # password grant method
				argi += 1
			else:
				usage()
		else:
			break

	if len(sys.argv) < argi+3:
		usage()
		
	opt.update({
		"server": sys.argv[argi],
		"username": sys.argv[argi+1],
		"password": sys.argv[argi+2]
	})
	
	if len(sys.argv) > argi+3 and sys.argv[argi+3] != '':
		opt.update({
			"second_factor": {
				"type": "totp",
				"code": sys.argv[argi+3]
			}
		})

	return opt




def get_access_token_password_grant(client_config, username, password, second_factor):
	headers = None
	if isinstance(second_factor,dict) and second_factor['type']=='totp':
		headers={ 'X-Auth-Token': second_factor['code']	}

	post = requests.post(
		client_config['oauth_token_url'],
		headers=headers,
		auth=(
			client_config['client_id'],
			client_config['client_password']
		),
		data={
			"grant_type": "password",
			'username': username,
			'password': password,
			"scope": client_config['scope'],
		},
		allow_redirects=False,
		timeout=5, # seconds
		verify=client_config["verify_server_certs"],
	)
	
	post.raise_for_status() # raise requests.exceptions.HTTPError if not 200
	return post.json()
	




def login(username, password, second_factor=None):
	'''Login to the oauth server and return a session cookie

	   username: email address of miab user
	   password: user's password
	   second_factor: None if TOTP not in use, otherwise dict:
		 {
		   "type": 'totp',
		   "code": '6-digit-code'
		 }

	   returns a session cookie pertaining to the login
	   may raise requests.exceptions.RequestException
	'''
	
	# 1. POST /auth/user/login json:{username=String,password=String}
	#	add X-Auth-Token header with TOTP challenge if needed
	#	+ record session cookie "miabsession"
	
	headers = None
	if isinstance(second_factor,dict) and second_factor['type']=='totp':
		headers={ 'X-Auth-Token': second_factor['code']	}

	post = requests.post(
		client_config["user_login_url"],
		headers=headers,
		data={
			'username': username,
			'password': password
		},
		allow_redirects=False,
		timeout=5, # seconds
		verify=client_config["verify_server_certs"],
	)
	
	post.raise_for_status() # raise requests.exceptions.HTTPError if not 200

	json = post.json()
	if json['status'] != 'ok':
		raise requests.exceptions.RequestException("server return not-ok result: %s" % json)

	return post.cookies



def get_authorization_code(client_config, cookies):
	''' obtain an authorization code from the oauth server
		returns the authorization code
		raises requests.exceptions.RequestException
	'''	

	# 2. POST /auth/oauth/authorize?
	#  response_type=code&
	#  client_id=miabldap-cli&
	#  scope=miabldap-console introspect&
	
	#  FORM encoded DATA:
	#	 consent=true
	
	#  COOKIES: include login session cookie
	#  + extract "code" from server's redirect

	post = requests.post(
		client_config['oauth_login_url'],
		params={
			"response_type": "code",
			"client_id": client_config["client_id"],
			"scope": client_config["scope"],
			"redirect_uri": client_config["authorize_url"]
		},
		cookies=cookies,
		data={ "consent": "true" },
		allow_redirects=False,
		timeout=5, # seconds
		verify=client_config["verify_server_certs"],
	)

	post.raise_for_status() # raise requests.exceptions.HTTPError if not 200

	location = urllib.parse.urlparse(post.headers['location'])
	code = urllib.parse.parse_qs(location.query)['code'][0]
	return code


def get_access_token_using_code(client_config, code):
	''' get an access token for the given authorization code
		returns response dict {
		   "access_token": str,
		   "expires": int,
		   ...
		}
		raises requests.exceptions.RequestException
	'''
	
	# 3. POST /auth/oauth/token?
	#	  FORM endoded DATA:
	#		 grant_type=authorization_code
	#		 code=<code from previous step>
	#	  RESPONSE json contains access_token, expires, etc
	post = requests.post(
		client_config['oauth_token_url'],
		auth=(
			client_config['client_id'],
			client_config['client_password']
		),
		data={
			"grant_type": "authorization_code",
			"code": code,
			"redirect_uri": client_config["authorize_url"]
		},
		allow_redirects=False,
		timeout=5, # seconds
		verify=client_config["verify_server_certs"],
	)

	post.raise_for_status() # raise requests.exceptions.HTTPError if not 200
	return post.json()	


def get_access_token_code_grant(client_config, username, password, second_factor):
	try:
		# 1. login
		err_msg = 'Unable to login'
		cookies = login(
			opt["username"],
			opt["password"],
			opt["second_factor"]
		)
		log.debug('login successful: cookies= %r', cookies)
		
		# 2. get authorization code
		err_msg = 'Unable to get authorization code'
		code = get_authorization_code(client_config, cookies)
		log.debug(f"got authorization code success: {code}")
		
		# 3. get access token
		err_msg = 'Unable to get access token'
		auth = get_access_token_using_code(client_config, code)
		return auth
	
	except requests.exceptions.RequestException as e:
		raise ValueError(err_msg) from e


opt = process_command_line()
if opt["debug"]:
	logging.basicConfig(level=logging.DEBUG)

log.debug('opt=%r', opt)
try:
	err_msg = 'Unable to read client config'
	client_config = get_client_config(opt["server"], opt["method"])
	log.debug('client_config=%r', client_config)
	
	err_msg = 'Unable to get access token'
	if opt["method"] == "password":
		auth = get_access_token_password_grant(
			client_config,
			opt["username"],
			opt["password"],
			opt["second_factor"]
		)
	elif opt["method"] == "authorization_code":
		auth = get_access_token_code_grant(
			client_config,
			opt["username"],
			opt["password"],
			opt["second_factor"]
		)
	else:
		raise ValueError(f"Unknown method {opt['method']}")
	
	# success - output result
	log.debug('auth=%r', auth)
	
	if opt["output_format"] == "sh":
		print(f"# token expires in {auth['expires_in']/60} minutes")
		print("# set the envionment variable needed by management/cli.py")
		print(f"export MIAB_ACCESS_TOKEN={auth['access_token']}")
		print(f"export MIAB_ACCESS_TOKEN_SERVER={opt['server']}")
		
	else:
		print(f"{auth['access_token']}")


except requests.exceptions.RequestException as e:
	log.debug(err_msg, exc_info=e)
	print(f"{err_msg}: {e}: {e.response.text}")
	sys.exit(1)

except ValueError as e:
	if isinstance(e.__cause__, requests.exceptions.RequestException):
		log.debug(e)
		print(f"{e}: {e.__cause__}: {e.__cause__.response.text}")
		sys.exit(1)
	else:
		raise e
