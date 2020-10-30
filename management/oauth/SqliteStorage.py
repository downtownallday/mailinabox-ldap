# -*- indent-tabs-mode: t; tab-width: 4; python-indent-offset: 4; -*-

import sqlite3
import os, stat
import json
import logging
import time

from .Storage import Storage
from .AuthCode import AuthCode
from .Token import Token


log = logging.getLogger(__name__)

#
# schema
#

db_info_create_table_stmt = "CREATE TABLE IF NOT EXISTS db_info(id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT NOT NULL, value TEXT NOT NULL)"

schema_updates = [
	# update 0
	[
		"CREATE TABLE authorization_codes(code TEXT NOT NULL, client_id TEXT NOT NULL, active_until INTEGER NOT NULL, json TEXT NOT NULL, PRIMARY KEY(code, client_id)) WITHOUT ROWID",

		"CREATE INDEX idx_authorization_codes_active_until ON authorization_codes(active_until)",

		"CREATE TABLE tokens(access_token TEXT NOT NULL, refresh_token TEXT, active_until INTEGER NOT NULL, json TEXT NOT NULL, PRIMARY KEY(access_token)) WITHOUT ROWID",

		"CREATE INDEX idx_tokens_refresh_token ON tokens(refresh_token)",
		"CREATE INDEX idx_tokens_active_until ON tokens(active_until)",

		"INSERT INTO db_info (key,value) VALUES ('schema_version', '0')"
	]
]




class SqliteStorage(Storage):
	GC_FREQUENCY_S = 5 * 60
	last_gc_time = 0
	db_path = None
	
	def __init__(self, db_path):
		self.db_path = db_path

		# create the parent directory and set its permissions
		parent = os.path.dirname(db_path)
		if not os.path.exists(parent):
			os.makedirs(parent)
			os.chmod(parent,
					 stat.S_IRWXU |
					 stat.S_IRGRP |
					 stat.S_IXGRP |
					 stat.S_IROTH |
					 stat.S_IXOTH
			)
			
		# update the schema to the latest version, or create it
		db_exists = os.path.exists(db_path)
		self.update_schema()

		# if the database is new, set file permissions
		if not db_exists:
			os.chmod(db_path,
					 stat.S_IRUSR |
					 stat.S_IWUSR
			)

		# garbage collect on startup
		self.gc()
		

	def connect(self):
		return sqlite3.connect(self.db_path)
		
	def update_schema(self):
		''' update the schema to the latest version

		'''
		c = None
		conn = None
		try:
			conn = self.connect()
			c = conn.cursor()
			c.execute(db_info_create_table_stmt)
			conn.commit()
			c.execute("SELECT value from db_info WHERE key='schema_version'")
			v = c.fetchone()
			if v is None:
				v = -1
			else:
				v = int(v[0])
			for idx in range(v+1, len(schema_updates)):
				for stmt in schema_updates[idx]:
					try:
						c.execute(stmt)
					except Exception as e:
						log.error('problem with sql statement at version=%s error="%s" stmt="%s"' % (idx, e, stmt))
						raise e
					
			conn.commit()
			
		finally:
			if c: c.close(); c=None
			if conn: conn.close(); conn=None
		

	#
	# codes
	#

	def save_authorization_code(self, code, client, user, redirect_uri, scope, code_challenge, code_challenge_method, issued_at):
		auth_code = {
			"code": code,
			"client_id": client.client_id,
			"user_id": user["user_id"],
			"redirect_uri": redirect_uri,
			"scope": scope,
			"code_challenge": code_challenge,
			"code_challenge_method": code_challenge_method,
			"issued_at": issued_at,
			"expires_in": client.authorization_code_lifetime_s
		}

		active_until = auth_code["issued_at"] + auth_code["expires_in"]
		conn = None
		c = None
		try:
			conn = self.connect()
			c = conn.cursor()
			c.execute("INSERT INTO authorization_codes (code, client_id, active_until, json) VALUES (?,?,?,?)", (
				auth_code["code"],
				auth_code["client_id"],
				active_until,
				json.dumps(auth_code)
			))
			conn.commit()
			return AuthCode(auth_code)
			
		finally:
			if c: c.close(); c=None
			if conn: conn.close(); conn=None
			

	def query_authorization_code(self, code, client_id):
		conn = None
		c = None
		try:
			conn = self.connect()
			c = conn.cursor()
			c.execute("SELECT json FROM authorization_codes WHERE code=? AND client_id=?", (code, client_id))
			auth_code = c.fetchone()
			if auth_code:
				auth_code = AuthCode(json.loads(auth_code[0]))
				if not auth_code.is_expired():
					return auth_code
		finally:
			if c: c.close(); c=None
			if conn: conn.close(); conn=None
			

	def delete_authorization_code(self, auth_code):
		conn = None
		c = None
		rowcount = 0
		try:
			conn = self.connect()
			c = conn.cursor()
			c.execute("DELETE FROM authorization_codes WHERE code=? AND client_id=?", (auth_code.code, auth_code.client_id))
			rowcount = c.rowcount
			if rowcount == 0:
				log.debug("delete_authorization_code: no matching rows found for code=%s client_id=%s" % (auth_code.code, auth_code.client_id))
			conn.commit()
			
		finally:
			if c: c.close(); c=None
			if conn: conn.close(); conn=None

		return rowcount > 0
	

	#
	# tokens
	#

	def save_token(self, old_token, token):
		if old_token:
			# old token must have a refresh_token
			if not old_token.refresh_token:
				raise ValueError("refresh_token required")

			# carry forward the refresh_token if the new token has none
			if not token.refresh_token:
				token.refresh_token = old_token.refresh_token
				token.refresh_expires_in = old_token.refresh_expires_in
			
		active_until = max(token.get_expires_at(),
						   token.get_refresh_expires_at())
		conn = None
		c = None
		try:
			conn = self.connect()
			c = conn.cursor()
			json = token.stringify()
			c.execute("INSERT INTO tokens (access_token, refresh_token, active_until, json) VALUES (?,?,?,?)", (
				token.access_token,
				token.refresh_token,
				active_until,
				json
			))
			conn.commit()
			log.debug("SAVED: %s" % json)
			
		finally:
			if c: c.close(); c=None
			if conn: conn.close(); conn=None

		self.gc()

		
	def revoke_token(self, token, delay_s=0):
		''' revoke the access token and associated refresh token
		if delay_s is greater than 0, then expire the old token
		in delay_s seconds instead of eliminiating the token from
		the database

		'''
		rowcount = 0
		conn = None
		c = None
		try:
			conn = self.connect()
			c = conn.cursor()

			if delay_s <= 0:
				token.revoked = True
				c.execute("DELETE FROM tokens WHERE access_token=?", (token.access_token,))
			else:
				token.expire_from_now(delay_s)
				active_until = token.get_expires_at()
				c.execute("UPDATE tokens set active_until=?, json=? WHERE access_token=?", (active_until, token.stringify(), token.access_token))

			rowcount = c.rowcount
			if rowcount == 0:
				log.debug("revoke_token: no matching rows found for access_token==%s" % token.access_token)
			else:
				log.debug('REVOKED: "%s"%s' % (token.access_token, " (delayed by %ss)" % delay_s if delay_s > 0 else ''))
				
			conn.commit()

		finally:
			if c: c.close(); c=None
			if conn: conn.close(); conn=None

		return rowcount > 0

	
	def authenticate_access_token(self, token_string):
		conn = None
		c = None
		try:
			conn = self.connect()
			c = conn.cursor()
			c.execute("SELECT json FROM tokens WHERE access_token=?", (token_string,))
			token = c.fetchone()
			if token:
				token = Token(json.loads(token[0]))
				if token.is_active():
					return token
				else:
					log.debug("access_token is not active!!")
			else:
				log.debug('access_token not found! %s' % token_string)
			
		finally:
			if c: c.close(); c=None
			if conn: conn.close(); conn=None
			

	def authenticate_refresh_token(self, refresh_token_string):
		conn = None
		c = None
		try:
			conn = self.connect()
			c = conn.cursor()
			c.execute("SELECT json FROM tokens WHERE refresh_token=?", (refresh_token_string,))
			token = c.fetchone()
			if token:
				token = Token(json.loads(token[0]))
				if token.is_refresh_active():
					return token
				else:
					log.debug("refresh_token is not active!!")
			else:
				log.debug("refresh_token not found! %s" % refresh_token_string)
			
		finally:
			if c: c.close(); c=None
			if conn: conn.close(); conn=None
			

        
	def gc(self):
		if time.time() - self.last_gc_time < self.GC_FREQUENCY_S:
			return
		
		now = int(time.time())
		conn = None
		c = None
		try:
			conn = self.connect()
			c = conn.cursor()
			c.execute("DELETE FROM authorization_codes WHERE active_until<?", (now,))
			log.debug("GC: deleted %s rows from authorization_codes table" % c.rowcount)
			conn.commit()
			
			c.execute("DELETE FROM tokens WHERE active_until<?", (now,))
			log.debug("GC: deleted %s rows from tokens table" % c.rowcount)
			conn.commit()
			
		finally:
			self.last_gc_time = time.time()
			if c: c.close(); c=None
			if conn: conn.close(); conn=None
