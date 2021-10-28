import pyotp
import time

def get_totp_code(totp_secret, last_code=None):
    totp=pyotp.TOTP(totp_secret);
    code = totp.now()
    while code == last_code:
        time.sleep(1)
        code = totp.now()
    return code

def user_login(d, login, pw, totp_secret, last_totp_code=None):
    ''' `d` is a qapy.browser_automation TestDriver object '''
    d.start("Login %s at authorization server", login)
    d.wait_for_el('input[type=password]')
    d.find_el('input[type=email]').send_text(login)
    d.find_el('input[type=password]').send_text(pw)
    d.find_text('Login', tag='button', exact=True) \
     .click()

    if totp_secret:
        d.wait_for_text('enter the six-digit code', exact=False)
        el = d.find_el('input[type=text]')
        code = get_totp_code(totp_secret, last_totp_code)
        el.send_text(code)
        d.find_text('Login', tag='button', exact=True) \
         .click()
        return code

def user_logout(d):
    ''' `d` is a qapy.browser_automation TestDriver object '''
    d.start("Logout user at authorization server")
    d.find_el('a[href="user/logout"]') \
     .click() \
     .wait_for_text('Goodbye')
