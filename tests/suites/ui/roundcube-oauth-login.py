from qapy.browser_automation import (
    TestDriver,
    TimeoutException,
    NoSuchElementException
)
import auth
import user_profile
import sys

login = sys.argv[1]
pw = sys.argv[2]

d = TestDriver()


def rcm_login(d, login, pw, totp_secret):
    '''login to roundcube via oauth'''
    d.start("Login to roudcube via oauth with user/pass/totp")
    try:
        el = d.find_el('#rcmloginoauth', throws=True)
        el.click()
    except NoSuchElementException as e:
        d.say_verbose("no roundcube login screen - assuming it redirected to oauth server")
    return auth.user_login(d, login, pw, totp_secret)

def rcm_login_via_grant_access(d):
    '''log into roundcube when we're already logged into the authorization
       server

    '''
    d.start('Login to roundcube via oauth (grant access only)')
    el = d.find_el('#rcmloginoauth', throws=False)
    if el: el.click()
    el = d.wait_for_text('Grant Access', tag='button', exact=True)

    d.start('Click grant access')
    el = el.click()

def wait_for_inbox(d):
    d.start("Wait for INBOX")
    d.wait_for_el('a.logout', must_be_enabled=True, secs=60)

def rcm_logout(d):
    ''' logout of roundcube '''
    d.start("Logout of roundcube")
    el = d.wait_for_el('a.logout', must_be_enabled=True)
    el.click()
    if d.wait_for_el('#rcmloginoauth', throws=False) is None:
        el.click()
        d.wait_for_el('#rcmloginoauth')




try:
    #
    # open the browser to roundcube
    #
    d.start("Opening roundcube")
    d.get("/mail/")
    el = d.wait_for_el('input[type=password]')

    #
    # 1. first-time authorization: requires a login
    #
    d.say("1. First-time authorization")
    rcm_login(d, login, pw, None)
    wait_for_inbox(d)
    rcm_logout(d)
    
    #
    # 2. second authorization: no login required
    #
    d.say("2. Second authorization - server remembers your session")
    rcm_login_via_grant_access(d)
    wait_for_inbox(d)
    rcm_logout(d)

    #
    # 3. enable TOTP: user is already logged into authorization
    # server. After enabled, ensure user is logged out so a TOTP token
    # is required for the next login
    #
    d.say("3. Fresh login, then Enable TOTP")
    user_profile.open_profile_page(d, login, pw, None)
    secret = user_profile.enable_totp(d)
    auth.user_logout(d)

    # 4. re-open roundcube and login with user/pass/totp
    d.start("Open roundcube")
    d.get('/mail/')
    d.wait_for_el('#rcmloginoauth, input[type=password]')

    totp_last_code = rcm_login(d, login, pw, secret)
    wait_for_inbox(d)
    rcm_logout(d)

    # 5. disable TOTP
    d.say("4. Disable TOTP")
    user_profile.open_profile_page(d, None, None, None)
    user_profile.disable_totp(d, login, pw, secret, totp_last_code)
    auth.user_logout(d)

    #
    # done
    #
    d.say("Success!")

except Exception as e:
    d.raise_error(e)
    
finally:
    d.quit()
