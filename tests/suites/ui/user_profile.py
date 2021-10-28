import pyotp
import auth

def open_profile_page(d, login, pw, totp_secret):
    '''open the user profile page and log in the user. if a user is
    already logged in they are logged out first unless `login` is None
    in which case it is assumed the login has already occurred and no
    login or logout is performed

    '''
    
    d.start("Open the user profile page")
    d.get('/auth/user/profile')
    if login:
        # if a user is already logged in, log them out
        if  d.wait_for_el("a[href='user/logout']", throws=False):
            auth.user_logout(d)
            d.get('/auth/user/profile')
            
        # login the user
        auth.user_login(d, login, pw, totp_secret)

    d.wait_for_text('Profile of ', exact=False, case_sensitive=True)

    
def enable_totp(d):
    '''browser must be at the profile page (already logged in)

       returns the TOTP secret

    '''

    d.start("Enable TOTP")
    # open two-factor accordion
    d.find_el("button[aria-label='expand enable 2fa']").click()

    # extract the secret
    secret = d.find_text('Secret:', exact=False).content().split(':')[1].strip()
    d.say("got totp secret: %s", secret)

    # enable
    code = auth.get_totp_code(secret)
    d.find_el("input[placeholder='6-digit code']") \
     .send_text(code)
    d.find_el("button[aria-label='enable 2fa']") \
     .click() \
     .wait_for_text('two-factor authentication is active', exact=False)

    return secret
    

def disable_totp(d, login, pw, secret, last_totp_code):
    '''browser must be at the profile page (already logged in)

    '''
    d.start("Disable TOTP")
    # open two-factor accordion
    d.find_el("button[aria-label='expand disable 2fa']")\
     .click()
    d.find_els("input[type=password]", displayed=True)[0] \
     .send_text(pw)
    code = auth.get_totp_code(secret, last_totp_code)
    d.find_els("input[placeholder='6-digit code']", displayed=True)[0] \
     .send_text(code)
    d.find_el("button[aria-label='disable 2fa']") \
     .click()
    d.wait_for_text('Enable two-factor authentication')
    
