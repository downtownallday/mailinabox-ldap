from selenium.webdriver import (
    Chrome,
    ChromeOptions,
    Firefox,
    FirefoxOptions
)
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.remote.webelement import WebElement
from selenium.webdriver.common.by import By
from selenium.common.exceptions import (
    NoSuchElementException,
    TimeoutException
)

import os
import subprocess


#
# chrome:
#    snap install chromium
#
# firefox:
#    apt-get install firefox
#    get the latest compiled geckodriver from:
#        https://github.com/mozilla/geckodriver/releases
#    copy into /usr/local/bin
#
# all:
#    pip3 install selenium (python 3.7 is required by selenium)
#

# OLD: for headless firefox (before firefox supported headless)
#    apt-get -y install xorg xvfb gtk2-engines-pixbuf
#    apt-get -y install dbus-x11 xfonts-base xfonts-100dpi xfonts-75dpi xfonts-cyrillic xfonts-scalable
#    apt-get -y install imagemagick x11-apps
#
#    before running tests, create an X frame buffer display:
#       Xvfb -ac :99 -screen 0 1280x1024x16 & export DISPLAY=:99
#


class ChromeTestDriver(Chrome):
    def __init__(self, options=None):
        '''Initialze headless chrome. If problems arise, try running from the
           command line: `chromium --headless http://localhost/mail/`

        '''
        if not options:
            options = ChromeOptions()
            options.headless = True
            
            # set a window size
            options.add_argument("--window-size=1200x600")
            
            # deal with ssl certificates since chrome has its own
            # trusted ca list and does not use the system's
            options.add_argument('--allow-insecure-localhost')
            options.add_argument('--ignore-certificate-errors')

            # required to run chromium as root
            options.add_argument('--no-sandbox')
            
        super(ChromeTestDriver, self).__init__(
            executable_path='/snap/bin/chromium.chromedriver',
            options=options
        )

        self.delete_all_cookies()


class FirefoxTestDriver(Firefox):
    ''' TODO: untested '''
    def __init__(self, options=None):
        if not options:
            options = FirefoxOptions()
            options.headless = True
            
        super(FirefoxTestDriver, self).__init__(
            executable_path='/usr/local/bin/geckodriver',
            options=options
        )

        self.delete_all_cookies()


class TestDriver(object):
    def __init__(self, driver=None, verbose=None, base_url=None, output_path=None):
        self.start_msg = ''
        
        if driver is None:
            if 'BROWSER_TESTS_BROWSER' in os.environ:
                driver = os.environ['BROWSER_TESTS_BROWSER']
            else:
                driver = 'chrome'
        if isinstance(driver, str):
            driver = TestDriver.createByName(driver)
        self.driver = driver
        
        if verbose is None:
            if 'BROWSER_TESTS_VERBOSITY' in os.environ:
                verbose = int(os.environ['BROWSER_TESTS_VERBOSITY'])
            else:
                verbose = 1
        self.verbose = verbose
        
        if base_url is None:
            if 'BROWSER_TESTS_BASE_URL' in os.environ:
                base_url = os.environ['BROWSER_TESTS_BASE_URL']
            else:
                hostname = subprocess.check_output(['/bin/hostname','--fqdn'])
                base_url = "https://%s" % hostname.decode('utf-8').strip()
        self.base_url = base_url

        if output_path is None:
            if 'BROWSER_TESTS_OUTPUT_PATH' in os.environ:
                output_path = os.environ['BROWSER_TESTS_OUTPUT_PATH']
            else:
                output_path= "./"
        self.output_path = output_path

        

    @staticmethod
    def createByName(name):
        if name == 'chrome':
            return ChromeTestDriver()
        elif name == 'firefox':
            return FirefoxTestDriver()
        raise ValueError('no such driver named "%s"' % name)

    
    def _say(self, level, *args):
        if self.verbose >= level:
            print('  '*(level-1) + (args[0] % (args[1:])))
            
    def is_verbose(self):
        return self.verbose >= 2
        
    def say_verbose(self, *args):
        self._say(2, *args)

    def say(self, *args):
        self._say(1, *args)

    def start(self, *args):
        self._say(1, *args)
        self.start_msg = args[0] % (args[1:])
    
    def last_start(self):
        return self.start_msg

    
    def get(self, url):
        ''' load a web page in the current browser session '''
        if not url.startswith('http'):
            url = self.base_url + url
        self.say_verbose('opening %s', url)
        self.driver.get(url)
        return self

    def title(self):
        return self.driver.title

    def refresh(self):
        self.driver.refresh()
        return self

    def get_current_window_handle(self):
        ''' returns the string id of the current window/tab '''
        return self.driver.current_window_handle
    
    def get_window_handles(self):
        ''' returns an array of strings, one for each window or tab open '''
        return self.driver.window_handles

    def switch_to_window(self, handle):
        ''' returns the current window handle '''
        cur = self.get_current_window_handle()
        self.driver.switch_to.window(handle)
        return cur

    def save_screenshot(self, where, ignore_errors=False):
        if not where.startswith('/'):
            where = self.output_path + '/' + where
        try:
            if not os.path.exists(os.path.dirname(where)):
                os.mkdir(os.path.dirname(where))
            self.say_verbose("save screenshot: '%s'", where)
            self.driver.save_screenshot(where)
        except Exception as e:
            if not ignore_errors:
                raise e

    def delete_cookie(self, name):
        self.driver.delete_cookie(name)
            
    def wait_for_id(self, id, secs=5, throws=True):
        return self.wait_for_el('#' + id, secs=secs, throws=throws)

    def wait_for_el(self, css_selector, secs=5, throws=True, must_be_enabled=False):
        if not must_be_enabled:
            self.say_verbose("wait for selector '%s' (%ss)",
                             css_selector, secs)
        else:
            self.say_verbose("wait for selector '%s' to be enabled (%ss)",
                             css_selector, secs)
        def test_fn(driver):
            found_el = driver.find_element(By.CSS_SELECTOR, css_selector)
            if must_be_enabled and not found_el.is_enabled():
                raise NoSuchElementException()
            return found_el
        wait = WebDriverWait(self.driver, secs, ignored_exceptions= (
            NoSuchElementException
        ))
        try:
            rtn = wait.until(test_fn)
            return ElWrapper(self, rtn)
        except TimeoutException as e:
            if throws: raise e
            else: return None

    def wait_for_text(self, text, tag='*', secs=5, exact=False, throws=True, case_sensitive=False):
        self.say_verbose("wait for text '%s'", text)
        def test_fn(driver):
            return self.find_text(text, tag=tag, exact=exact, throws=False, quiet=True, case_sensitive=case_sensitive)
        wait = WebDriverWait(self.driver, secs, ignored_exceptions= (
            NoSuchElementException
        ))
        try:
            rtn = wait.until(test_fn)
            return rtn
        except TimeoutException as e:
            if throws: raise e
            else: return None

    def find_el(self, css_selector, nth=0, throws=True):
        self.say_verbose("find element: '%s'", css_selector)
        try:
            els = self.driver.find_elements(By.CSS_SELECTOR, css_selector)
            if len(els)==0:
                raise NoSuchElementException("selector=%s" % css_selector)
            return ElWrapper(self, els[nth])
        except (IndexError, NoSuchElementException) as e:
            if throws: raise e
            else: return None

    def find_els(self, css_selector, throws=True, displayed=False):
        self.say_verbose("find elements: '%s'", css_selector)
        try:
            els = self.driver.find_elements(By.CSS_SELECTOR, css_selector)
            return [ ElWrapper(self, el) for el in els if not displayed or el.is_displayed() ]
        except (IndexError, NoSuchElementException) as e:
            if throws: raise e
            else: return None

    def find_text(self, text, tag='*', exact=False, throws=True, quiet=False, case_sensitive=False):
        if not quiet:
            self.say_verbose("find text: '%s' tag=%s exact=%s",
                             text, tag, exact)
        try:
            if exact:
                if case_sensitive:
                    xpath = "//%s[normalize-space(text()) = '%s']" % (tag, text)
                else:
                    uc = text.upper()
                    lc = text.lower()
                    xpath = "//%s[normalize-space(translate(text(), '%s', '%s')) = '%s']" % (tag, lc, uc, uc)
            else:
                if case_sensitive:
                    xpath = "//%s[contains(text(),'%s')]" % (tag, text)
                else:
                    uc = text.upper()
                    lc = text.lower()
                    xpath = "//%s[contains(translate(text(),'%s','%s'),'%s')]" % (tag, lc, uc, uc)

            el = self.driver.find_element(by=By.XPATH, value=xpath)
            return ElWrapper(self, el)
        except NoSuchElementException as e:
            if throws: raise e
            else: return None

    def execute_script(self, script, *args):
        ''' Synchronously Executes JavaScript in the current window/frame '''
        self.driver.execute_script(script, *args)

    def execute_async_script(self, script, secs=5, *args):
        ''' Asynchronously Executes JavaScript in the current window/frame '''
        self.driver.set_script_timeout(secs)
        self.driver.execute_async_script(script, *args)

    def close(self):
        ''' close the window/tab '''
        self.say_verbose("closing %s", self.driver.current_url)
        self.driver.close()

    def quit(self):
        ''' closes the browser and shuts down the chromedriver executable '''
        self.driver.quit()

    def raise_error(self, exception):
        self.say("Failure!")
        self.save_screenshot('screenshot.png', ignore_errors=False)
        if hasattr(exception, 'msg'):
            exception.msg = "Error during '%s': %s" % (self.last_start(), exception.msg)
        else:
            exception.msg = "Error during '%s'" % self.last_start()
        raise exception

    


class ElWrapper(object):
    '''see:
        https://github.com/SeleniumHQ/selenium/blob/trunk/py/selenium/webdriver/remote/webelement.py

    '''
    def __init__(self, driver, el):
        self.driver = driver
        self.el = el

    def find_el(self, css_selector, nth=0, throws=True):
        self.say_verbose("find element: '%s'", css_selector)
        try:
            els = self.el.find_elements(By.CSS_SELECTOR, css_selector)
            if len(els)==0:
                raise NoSuchElementException("selector=%s" % css_selector)
            return ElWrapper(self.driver, els[nth])
        except (IndexError, NoSuchElementException) as e:
            if throws: raise e
            else: return None

    def find_els(self, css_selector, throws=True, displayed=False):
        self.say_verbose("find elements: '%s'", css_selector)
        try:
            els = self.el.find_elements(By.CSS_SELECTOR, css_selector)
            return [ ElWrapper(self.driver, el) for el in els if not displayed or el.is_displayed() ]
        except (IndexError, NoSuchElementException) as e:
            if throws: raise e
            else: return None
    
    def is_enabled(self):
        return self.el.is_enabled()

    def is_checked(self):
        """ a checkbox or radio button is checked """
        return self.el.is_selected()

    def is_displayed(self):
        """Whether the self.element is visible to a user."""
        return self.el.is_displayed()
    
    def get_attribute(self, name):
        return self.el.get_attribute(name)

    def content(self, max_length=None, ellipses=True):
        txt = self.el.text
        if not max_length or len(txt)<max_length:
            return txt
        if ellipses:
            return txt[0:max_length] + '...'
        return txt[0:max_length]

    def tag(self):
        return self.el.tag_name

    def location(self):
        """ returns dictionary {x:N, y:N} """
        return self.el.location()

    def rect(self):
        return self.el.rect()

    
    def send_text(self, *value):
        self.driver.say_verbose("send text '%s'", "/".join(value))
        self.send_keys(*value)
        
    def send_keys(self, *value):
        self.el.send_keys(*value)

    def clear_text(self):
        self.el.clear()

    def click(self):
        if self.driver.is_verbose():
            content = self.content(max_length=40)
            tag = self.tag()
            if tag=='a': tag='link'
            self.driver.say_verbose("click %s '%s'", tag, content)
            
        self.el.click()
        return self.driver

        

    
        
#dir(driver)
# ['__class__', '__delattr__', '__dict__', '__dir__', '__doc__', '__enter__', '__eq__', '__exit__', '__format__', '__ge__', '__getattribute__', '__gt__', '__hash__', '__init__', '__init_subclass__', '__le__', '__lt__', '__module__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', '__weakref__', '_file_detector', '_is_remote', '_mobile', '_switch_to', '_unwrap_value', '_web_element_cls', '_wrap_value', 'add_cookie', 'application_cache', 'back', 'capabilities', 'close', 'command_executor', 'create_options', 'create_web_element', 'current_url', 'current_window_handle', 'delete_all_cookies', 'delete_cookie', 'desired_capabilities', 'error_handler', 'execute', 'execute_async_script', 'execute_cdp_cmd', 'execute_script', 'file_detector', 'file_detector_context', 'find_element', 'find_element_by_class_name', 'find_element_by_css_selector', 'find_element_by_id', 'find_element_by_link_text', 'find_element_by_name', 'find_element_by_partial_link_text', 'find_element_by_tag_name', 'find_element_by_xpath', 'find_elements', 'find_elements_by_class_name', 'find_elements_by_css_selector', 'find_elements_by_id', 'find_elements_by_link_text', 'find_elements_by_name', 'find_elements_by_partial_link_text', 'find_elements_by_tag_name', 'find_elements_by_xpath', 'forward', 'fullscreen_window', 'get', 'get_cookie', 'get_cookies', 'get_log', 'get_network_conditions', 'get_screenshot_as_base64', 'get_screenshot_as_file', 'get_screenshot_as_png', 'get_window_position', 'get_window_rect', 'get_window_size', 'implicitly_wait', 'launch_app', 'log_types', 'maximize_window', 'minimize_window', 'mobile', 'name', 'orientation', 'page_source', 'quit', 'refresh', 'save_screenshot', 'service', 'session_id', 'set_network_conditions', 'set_page_load_timeout', 'set_script_timeout', 'set_window_position', 'set_window_rect', 'set_window_size', 'start_client', 'start_session', 'stop_client', 'switch_to', 'switch_to_active_element', 'switch_to_alert', 'switch_to_default_content', 'switch_to_frame', 'switch_to_window', 'title', 'w3c', 'window_handles']


