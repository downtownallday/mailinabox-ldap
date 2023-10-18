#!/usr/bin/env php
<?php
#####
##### This file is part of Mail-in-a-Box-LDAP which is released under the
##### terms of the GNU Affero General Public License as published by the
##### Free Software Foundation, either version 3 of the License, or (at
##### your option) any later version. See file LICENSE or go to
##### https://github.com/downtownallday/mailinabox-ldap for full license
##### details.
#####


define('INSTALL_PATH', realpath(__DIR__ . '/..') . '/' );

require_once INSTALL_PATH.'program/include/clisetup.php';
ini_set('memory_limit', -1);



function usage()
{
    print "Usage: carddav_refresh.sh [-id <number>] username password\n";
    print "Force a sync of a user's addressbook with the remote server\n";
    print "Place this script in /path/to/roundcubemail/bin, then change the working directory to /path/to/roundcubemail, then run ./bin/cardav_refresh.sh"; 
    exit(1);
}

function _die($msg)
{
    fwrite(STDERR, $msg . "\n");
    exit(1);
}

$args = rcube_utils::get_opt(array('id' => 'dbid'));

$dbid = 0;
if (!empty($args['dbid'])) {
    $dbid = intval($args['dbid']);
}
   
$username = trim($args[0]);
if (empty($username)) {
    print "Missing username";
    usage();
}
$password = trim($args[1]);
if (empty($password)) {
    usage();
}


// -----
// From index.php -- initialization and login
// -----

// init application, start session, init output class, etc.
$RCMAIL = rcmail::get_instance(0, isset($GLOBALS['env']) ? $GLOBALS['env'] : null);

// trigger startup plugin hook
$startup = $RCMAIL->plugins->exec_hook('startup', array('task' => $RCMAIL->task, 'action' => $RCMAIL->action));
$RCMAIL->set_task($startup['task']);
$RCMAIL->action = $startup['action'];
$auth = $RCMAIL->plugins->exec_hook('authenticate', array(
            'host'  => $RCMAIL->autoselect_host(),
            'user'  => $username,
            'pass'  => $password,
            'valid' => true,
            'cookiecheck' => false,));

// Login
if ($auth['valid'] && !$auth['abort']
    && $RCMAIL->login($auth['user'], $auth['pass'], $auth['host'], $auth['cookiecheck']))
  {
    print "login ok\n";
  }
 else
   {
     _die("login failed");
   }


// ----------------------------------------------------
// Get the roundcube user id (see deluser.sh)
// ----------------------------------------------------
$host = $auth['host']; # can be a url (eg: ssl://localhost)
$host_url = parse_url($host);
if ($host_url['host']) {
       $host = $host_url['host'];
}
$user = rcube_user::query($auth['user'], $host);
if (!$user) {
       _die("User not found auth[host]=" . $auth['host'] . " host=" . $host . "\n");
}
printf("roundcube user id: %s\n", $user->ID);
   

// ----------------------------------------------------
// ensure the carddav tables are created and populated
// ----------------------------------------------------

require_once('plugins/carddav/carddav.php');
require_once('plugins/carddav/src/Frontend/AddressbookManager.php');

try {
   $c = new carddav(rcube_plugin_api::get_instance());
   $c->task .= "|cli";
   $c->init();
   print "done: init\n";
   // this ensures the carddav tables are created or migrated
   $c->afterLogin();
   print "done: afterLogin (init tables)\n";
} catch(exception $e) {
    print $e . "\n";
    _die("failed");
}


// -------------------------------------------------------------
// Connect to the roundcube database
// -------------------------------------------------------------
$db = $rcmail->get_dbh();
$db->db_connect('w');
if (!$db->is_connected() || $db->is_error()) {
  _die("No DB connection\n" . $db->is_error());
}
print "db connected\n";


// ------------------------------------------------------
// Update/sync all out-of-date address books
// ------------------------------------------------------

// first get all addressbook ids
// asserting (flags 0x21)=1 is checking that 'active' is true

$dbid=array();
$sql_result = $db->query(
    'SELECT carddav_addressbooks.id FROM ' . $db->table_name('carddav_addressbooks') .
    ' JOIN carddav_accounts ON carddav_addressbooks.account_id = carddav_accounts.id' .
    ' WHERE (carddav_addressbooks.flags & 0x21)=1 AND user_id='.$user->ID );
if ($db->is_error()) {
  _die("DB error occurred: " . $db->is_error());
}
   
while ($row = $db->fetch_assoc($sql_result)) {
  array_push($dbid, intval($row['id']));
  print "carddav_addressbooks id: " . $row['id'] . "\n";
}

// sync the addressbooks
// we have to re-instantiate to wipe out the addressbook cache
// see: carddav::abooksDB
$c = new carddav(rcube_plugin_api::get_instance());
$c->init();
$c->afterLogin();

$abMgr = new MStilkerich\RCMCardDAV\Frontend\AddressbookManager();

foreach($dbid as $id) {
  try {
    $abook = $abMgr->getAddressbook($id);
    $abMgr->resyncAddressbook($abook);
    printf("success: %s\n", $id);
  } catch (Exception $e) {
      printf("failed: %s: %s\n", $id, $e->getMessage());
  }
}

