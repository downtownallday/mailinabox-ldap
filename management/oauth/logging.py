# -*- indent-tabs-mode: t; tab-width: 4; python-indent-offset: 4; -*-

import logging

# keep a separate logger from app.logger, which only logs WARNING and
# above, doesn't include the module name, or authentication
# details

class textcolor:
	DANGER = '\033[31m'
	WARN = '\033[93m'
	SUCCESS = '\033[32m'
	BOLD = '\033[1m'
	FADED= '\033[37m'
	RESET = '\033[0m'



class AuthLogFormatter(logging.Formatter):
	def __init__(self):
		fmt='%(name)s:%(lineno)d(%(username)s/%(client)s): %(levelname)s[%(thread)d]: %(color)s%(message)s%(color_reset)s'
		super(AuthLogFormatter, self).__init__(fmt=fmt)


#
# logging in oauth requires that this filter to be active
#

class AuthLogFilter(logging.Filter):
	def __init__(self, color_output, get_session_username_function):
		self.color_output = color_output
		self.get_session_username = get_session_username_function
		super(AuthLogFilter, self).__init__()
	
	''' add `username` and `client` context info the the LogRecord '''
	def filter(self, record):
		record.color = ''
		if self.color_output:
			if record.levelno == logging.DEBUG:
				record.color=textcolor.FADED
			elif record.levelno == logging.INFO:
				record.color=textcolor.BOLD
			elif record.levelno == logging.WARNING:
				record.color=textcolor.WARN
			elif record.levelno in [logging.ERROR, logging.CRITICAL]:
				record.color=textcolor.DANGER
				
		record.color_reset = textcolor.RESET if record.color else ''
		record.client = '-'
		record.username = '-'
		record.thread = record.thread % 10000

		opts = None
		args_len = len(record.args)
		if type(record.args) == dict:
			opts = record.args
			record.args = ()
		elif args_len>0 and type(record.args[args_len-1]) == dict:
			opts = record.args[args_len-1]
			record.args = record.args[0:args_len-1]

		if opts:
			record.client = opts.get('client', '-')
			record.username = opts.get('username', '-')

		if record.username == '-':
			try:
				record.username = self.get_session_username()
			except (RuntimeError, KeyError):
				# not in an HTTP request context or not logged in
				pass

		return True

