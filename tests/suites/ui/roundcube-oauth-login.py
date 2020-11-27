from qapy.browser_automation import TestDriver
import sys
import pyotp

login = sys.argv[1]
pw = sys.argv[2]

d = TestDriver()


def rcm_login(d, login, pw, totp_secret):
    '''login to roundcube via oauth'''
    d.start("Login to roudcube via oauth with user/pass/totp")
    el = d.find_el('#rcmloginoauth')
    el.click() \
      .wait_for_el('input[type=password]')

    d.start("Login %s", login)
    d.find_el('input[type=email]').send_text(login)
    d.find_el('input[type=password]').send_text(pw)
    d.find_text('Login', tag='button', exact=True) \
     .click()

    if totp_secret:
        d.wait_for_text('enter the six-digit code', exact=False)
        el = d.find_el('input[type=text]') 
        totp=pyotp.TOTP(totp_secret);
        code = totp.now()
        el.send_text(code)
        d.find_text('Login', tag='button', exact=True) \
         .click()  

def rcm_login_via_grant_access(d):
    '''log into roundcube when we're already logged into the authorization
       server

    '''
    d.start('Login to roundcube via oauth (grant access only)')
    el = d.find_el('#rcmloginoauth')
    el = el.click() \
           .wait_for_text('Grant Access', tag='button', exact=True)

    d.start('Click grant access')
    el = el.click()

def wait_for_inbox(d):
    d.start("Wait for INBOX")
    d.wait_for_el('a.logout')

def rcm_logout(d):
    ''' logout of roundcube '''
    d.start("Logout of roundcube")
    el = d.find_el('a.logout')
    el = el.click() \
           .wait_for_el('#rcmloginoauth')

def enable_totp(d):
    '''browser must be at the profile page (already logged in)

       returns the TOTP secret
    '''

    d.start("Enable TOTP")
    # open two-factor accordion
    el = d.find_text('two-factor authentication',exact=False, tag='button') \
          .click()
    # extract the secret
    secret = d.find_text('Secret:', exact=False).content().split(':')[1].strip()
    d.say("got totp secret: %s", secret)

    # enable
    totp=pyotp.TOTP(secret);
    code = totp.now()
    d.find_el("input[placeholder='6-digit code']") \
     .send_text(code)
    el.find_text('Enable', tag='button', exact=True) \
      .click() \
      .wait_for_text('two-factor authentication is active', exact=False)

    return secret
    

try:
    #
    # open the browser to roundcube
    #
    d.start("Opening roundcube")
    d.get("/mail/")
    el = d.wait_for_el('#rcmloginoauth')

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
    # 3. enable TOTP, user is already logged into authorization server
    #
    d.say("3. Enable TOTP, then fresh login")
    d.start("Click oauth link")
    el = d.find_el('#rcmloginoauth') \
          .click() \
          .wait_for_el('a[target=profile]')

    d.start("Click user profile link") # opens new tab
    handle = d.get_current_window_handle()
    el = el.click()
    handles = d.get_window_handles()
    assert len(handles) == 2
    d.switch_to_window(handles[1])
    d.wait_for_text('two-factor authentication',exact=False, tag='button')
    
    secret = enable_totp(d)
    d.start("Logout user at authorization server")
    d.find_el('a[href=logout]') \
     .click() \
     .wait_for_el('input[type=password]')

    #d.close() # user-profile tab
    d.switch_to_window(handle)

    # 4. re-open roundcube and login with user/pass/totp
    d.start("Open roundcube")
    d.get('/mail/') \
     .wait_for_el('#rcmloginoauth')

    rcm_login(d, login, pw, secret)
    wait_for_inbox(d)
    rcm_logout(d)
    

    #
    # done
    #
    d.say("Success!")

except Exception as e:
    d.raise_error(e)
    
finally:
    d.quit()
