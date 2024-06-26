[![build](https://github.com/downtownallday/mailinabox-ldap/actions/workflows/commit-tests.yml/badge.svg)](https://github.com/downtownallday/mailinabox-ldap/actions)

# Mail-in-a-Box LDAP
This is a version of [Mail-in-a-Box](https://mailinabox.email) with LDAP used as the user account database instead of sqlite.

It allows use of a remote Nextcloud that authenticate users against Mail-in-a-Box using [Nextcloud's official LDAP support](https://nextcloud.com/usermanagement/). A single user account database shared with Nextcloud was originally the goal of the project which would simplify deploying a private mail and cloud service for a home or small business.

To add a new account to Nextcloud, simply add a new email account with MiaB-LDAP's management web interface. Quotas and other account settings are made within Nextcloud.

**Also see companion project [Cloud-in-a-Box](https://github.com/downtownallday/cloudinabox)**

## Additional features above what Mail-in-a-Box (upstream) provides:

  1. Encryption-at-rest of user-data using a LUKS partition (optional)
  1. Log capture daemon and graphical UI for reporting on system activity
  1. Display names for users (not just a user id), and comments for aliases to better keep track of what their intended use is
  1. Ability to modify/update Postgrey's whitelist from the management console

Upstream changes are merged as they become available, and releases are numbered the same as upstream.

## How to install

Decide what features to enable and add the corresponding values to bash:

### Encryption-at-rest: add `ENCRYPTION_AT_REST=true`.

Enable encryption-at-rest the very first time setup is run on a new system to create a fresh user-data area (where mail is stored) on an encrypted drive. To enable encryption-at-rest for an existing server and retain the current user-data, manually create an encrypted drive with ehdd/create_hdd.sh, rename the old user-data directory so it won't conflict with the mounted encrypted drive at /home/user-data, then mount it with ehdd/mount.sh, and finally copy everything into it.

### Remote Nextcloud: add `REMOTE_NEXTCLOUD=true`.

This enables remote Nextcloud support. See the instructions below for more detail on using a remote Nextcloud.

### Some examples:

#### A typical installation. No encryption-at-rest. No remote Nextcloud.

`curl -s https://raw.githubusercontent.com/downtownallday/mailinabox-ldap/master/setup/bootstrap.sh | sudo bash`

#### Installation with encryption-at-rest.

`curl -s https://raw.githubusercontent.com/downtownallday/mailinabox-ldap/master/setup/bootstrap.sh | sudo ENCRYPTION_AT_REST=true bash`

#### Installation with a remote Nextcloud.

To integrate Mail-in-a-Box w/LDAP (MiaB-LDAP) with Nextcloud, changes must be made on both sides. These changes are mostly automated.

**1. On MiaB-LDAP**

`curl -s https://raw.githubusercontent.com/downtownallday/mailinabox-ldap/master/setup/bootstrap.sh | sudo REMOTE_NEXTCLOUD=true bash`

During setup you will be prompted for the hostname and web prefix of your remote Nextcloud box.

When remote Nextcloud is enabled, Roundcube and Z-Push (ActiveSync) will use the remote Nextcloud for contacts and calendar. The local Nextcloud is disabled. If you upgraded, old contacts will still be available in Roundcube, but will be read-only. Users can drag them into the remote Nextcloud from Roundcube.

**2. On the remote Nextcloud**

Copy the file `setup/mods.available/connect-nextcloud-to-miab.sh` to the Nextcloud box and run it as root (if you installed Cloud-in-a-Box, this script is already available in the setup directory). This will configure Nextcloud's "LDAP user and group backend" with the MiaB-LDAP details and ensure the contacts and calendar apps are installed. *This does not replace or alter your ability to log into Nextcloud with any existing local Nextcloud accounts. It only allows MiaB-LDAP users to log into Nextcloud using their MiaB-LDAP credentials.*

## Under-the-Hood

**Additional directory in user-data**

A new ldap directory is created by setup under STORAGE_ROOT (/home/user-data/ldap) that holds the LDAP database, so that it gets backed up by the normal backup process. In there, you will also find all LDAP service account credentials created by setup in `/home/user-data/ldap/miab_ldap.conf`, such as those for Nextcloud. Service accounts have limited rights to make changes and should be preferred over the use of the LDAP admin account.

**LDAP schema for postfix and dovecot**

See `conf/postfix.schema` and `conf/mta-totp.schema` for more details on the LDAP schema.

**LDAP logs**

LDAP server logs are stored in `/var/log/ldap/slapd.log` and rotated daily.

**Command line queries**

To perform general command-line searches against your LDAP database, run `setup/ldap -search "\<query\>"` as root, where _query_ can be a distinguished name to show all attributes of that dn, or an LDAP search enclosed in parenthesis. Some examples:
  * `setup/ldap.sh -search "(mail=alice@mydomain.com)"` (show alice)
  * `setup/ldap.sh -search "(|(mail=alice.*)(mail=bruce.*))"` (show all alices and bruces)
  * `setup/ldap.sh -search "(objectClass=mailuser)"` (show all users)
  * etc.

This is a convenient way to run ldapsearch having all the correct command line arguments, but any LDAP tool will also work.

*Direct LDAP database manipulation is not recommended for things like adding users or groups using ldapmodify or other LDAP database tools. Instead, use the MiaB admin interface or REST API. Adding or removing a user or group with the admin interface will trigger additional database and system changes by the management daemon, such as updating DNS zones for new email domains, updating group memberships, etc, that would not be performed with a direct change.*


## Migration

Running any of the setup scripts to install MiaB-LDAP (`miab`, `setup/bootstrap.sh`, `setup/start.sh`, etc) will automatically migrate your current installation from sqlite to LDAP. Ensure you've backed up user-data before running.
