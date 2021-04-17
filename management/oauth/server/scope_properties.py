# -*- indent-tabs-mode: t; tab-width: 4; python-indent-offset: 4; -*-

'''

static properties of scopes

'''

properties = {
	'introspect': {
		'id': 'introspect',
		'desc': 'Retrieve information about a Bearer token',
		'hidden': True,  # hidden from end users
		'danger': False
	},

	'mailbox': {
		'id': 'mailbox',
		'desc': 'Unrestricted access to your mail',
		'hidden': False, # not hidden from end users
		'danger': True
	},

	'miabldap-console': {
		'id': 'miabldap-console',
		'desc': 'Unrestricted rights to change the server configuration',
		'hidden': False,
		'danger': True
	}
}

def get(scope, for_end_user=True):
	result = {}
	for id in scope.split():
		if id in properties:
			p = properties[id]
			if not p['hidden'] or not for_end_user:
				result[id] = p.copy()
	return result
