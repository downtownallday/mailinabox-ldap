#####
##### This file is part of Mail-in-a-Box-LDAP which is released under the
##### terms of the GNU Affero General Public License as published by the
##### Free Software Foundation, either version 3 of the License, or (at
##### your option) any later version. See file LICENSE or go to
##### https://github.com/downtownallday/mailinabox-ldap for full license
##### details.
#####


#
# This is a web_update management hook for the remote-nextcloud setup
# mod.
#
# When management/web_update.py creates a new nginx configuration file
# "local.conf", this mod will ensure that .well-known/caldav and
# .well-known/carddav urls are redirected to the remote nextcloud.
#
# The hook is enabled by placing the file in directory
# LOCAL_MODS_DIR/managment_hooks_d.
#

import os
import logging

log = logging.getLogger(__name__)


def do_hook(hook_name, hook_data, mods_env):
    if hook_name != 'web_update':
        # we only care about hooking web_update
        log.debug('hook - ignoring hook %s', hook_name)
        return False
    
    if hook_data['op'] != 'pre-save':
        log.debug('hook - ignoring hook op %s:%s', hook_name, hook_data['op'])
        return False

    if 'NC_HOST' not in mods_env or mods_env['NC_HOST'].strip() == '':
        # not configured for a remote nextcloud
        log.debug('hook - not configured for a remote nextcloud')
        return False
    
    # get the remote nextcloud url and ensure no tailing /
    
    nc_url = "%s://%s:%s%s" % (
        mods_env['NC_PROTO'],
        mods_env['NC_HOST'],
        mods_env['NC_PORT'],
        mods_env['NC_PREFIX'][0:-1] if mods_env['NC_PREFIX'].endswith('/') else mods_env['NC_PREFIX']
    )


    # find start and end of Nextcloud configuration section
    
    str = hook_data['nginx_conf']
    start = str.find('# Nextcloud configuration.')
    if start==-1:
        log.error("no Nextcloud configuration found in nginx conf")
        return False
    
    end = str.find('\n\t# ', start) # this should match comment "# ssl files sha1:...", which is dynamically added by web_update.py:make_domain_config()
    if end==0:
        log.error("couldn't determine end of Nextcloud configuration")
        return False
    
    if str[end+4:end+4+9] != 'ssl files':
        log.error("expected end replacement block comment to start with 'ssl files', but got '%s'", str[end+4:end+4+9])
        return False

    # ensure we're not eliminating lines that are not nextcloud
    # related in the event that the conf/nginx-* templates change
    #
    # check that every main directive in the proposed section
    # (excluding block directives) should contains the text "cloud",
    # "carddav", or "caldav"
    
    for line in str[start:end].split('\n'):
        if line.startswith("\t\t"): continue
        line_stripped = line.strip()
        if line_stripped == "" or \
           line_stripped.startswith("#") or \
           line_stripped.startswith("}"):
            continue
        if line_stripped.find('cloud')==-1 and \
           line_stripped.find('carddav')==-1 and \
           line_stripped.find('caldav')==-1:
            log.error("nextcloud replacement block directive did not contain 'cloud', 'carddav' or 'caldav'. line=%s", line_stripped)
            return False

    
    # ok, do the replacement
    
    template = """# Nextcloud configuration.
	rewrite ^/cloud$ /cloud/ redirect;
	rewrite ^/cloud/(contacts|calendar|files)$ {nc_url}/index.php/apps/$1/ redirect;
	rewrite ^/cloud/(.*)$ {nc_url}/$1 redirect;
	
	rewrite ^/.well-known/carddav {nc_url}/remote.php/dav/ redirect;
	rewrite ^/.well-known/caldav {nc_url}/remote.php/dav/ redirect;
"""

    hook_data['nginx_conf'] = str[0:start] + template.format(nc_url=nc_url) + str[end:]
    return True
