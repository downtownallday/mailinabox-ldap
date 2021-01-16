# -*- indent-tabs-mode: t; tab-width: 4; python-indent-offset: 4; -*-

class Storage():
	'''
	users
	'''
	def query_user(self, user_id):
		'''locate a user by user_id (email), and return a dictionary with at
		   least the keys 'user_id' (string). if the user is expired
		   or invalid, returns None

		'''
		raise NotImplementedError()

	'''
	clients
	'''
	def query_client(self, client_id):
		raise NotImplementedError()

    
	'''
	authorization codes
	'''
	def save_authorization_code(self, code, client, user, redirect_uri, scope, code_challenge, code_challenge_method, issued_at):
		raise NotImplementedError()
        
	def query_authorization_code(self, code, client_id):
		raise NotImplementedError()

	def delete_authorization_code(self, auth_code):
		raise NotImplementedError()


	'''
	tokens
	'''
	def save_token(self, old_token, token):
		raise NotImplementedError()

	def revoke_token(self, token):
		raise NotImplementedError()
    			
	def authenticate_access_token(self, token_string):
		raise NotImplementedError()

	def authenticate_refresh_token(self, refresh_token_string):
		raise NotImplementedError()

	def find_token(self, token_string, token_type_hint):
		'''	find an existing token using the hint provided

		'''
		token = None
		if token_type_hint == 'access_token':
			token = self.authenticate_access_token(token_string)
		elif token_type_hint == 'refresh_token':
			token = self.authenticate_refresh_token(token_string)
		else:
			token = self.authenticate_access_token(token_string)
			if not token:
				token = self.authenticate_refresh_token(token_string)
		return token


	'''
	maintenance
	'''
	def gc(self):
		raise NotImplementedError()
	
