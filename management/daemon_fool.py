import base64
import logging
from daemon_sessions import (
    admin_login_required
)
from flask import (
    request,
)
from werkzeug.datastructures import (
    Headers
)

log = logging.getLogger(__name__)


def encode_authorization_basic(user_id, pw):
    b = base64.b64encode( (user_id + ':' + pw).encode('utf-8') )
    return 'Basic ' + b.decode('ascii')

def attach_old_authorization(user, env, auth_service):
    if 'api_key' in user and 'Authorization' not in request.headers:
        user_id = user['user_id']
        api_key = user['api_key']
        headers = Headers(request.headers)
        headers['Authorization'] = \
            encode_authorization_basic( user_id, api_key )
        request.headers = headers


def add_daemon_fool(app, env, auth_service, handlers):
    '''call this to add session-based login (including 2FA) for existing
    routes (currently just munin).

    '''

    @app.route('/admin/munin/')
    @app.route('/admin/munin/<path:filename>')
    @admin_login_required(login_redirect=True)
    def admin_munin(user, filename=""):
        attach_old_authorization(user, env, auth_service)
        return handlers['munin'](filename)
    
    @app.route('/admin/munin/cgi-graph/<path:filename>')
    @admin_login_required(login_redirect=True)
    def admin_munin_cgi(user, filename):
        attach_old_authorization(user, env, auth_service)
        return handlers['munin_cgi'](filename)
    
