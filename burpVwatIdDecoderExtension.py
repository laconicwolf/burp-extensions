from burp import IBurpExtender
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
import base64
import sys
import re

# for debugging. https://github.com/securityMB/burp-exceptions
try:
    from exceptions_fix import FixBurpExceptions
except:
    pass


__author__ = 'Jake Miller (@LaconicWolf)'
__date__ = '20180323'
__version__ = '0.01'
__description__ = ''' Decodes a VWAT_ID cookie and displays the decoded result 
                      in a HTTP request tab.   
                  '''

COOKIE_REGEX = "VWAT_ID(.*)"

class ProcessCookie:
    ''' Extracts and returns a specified cookie. If no cookie is found, returns
    an empty string.
    '''
    def extractCookie(self, cookie, pattern):
        ''' Extracts the cookie from the cookies in the Cookie header.
        '''
        cookies = re.search(pattern, cookie)
        if cookies:
            if len(cookies.group().split()) > 1:
                c = cookies.group().split()[0].strip(';')
            else:
                c = cookies.group()
        else:
            c = ''
        return c

    def decodeBase64(self, cookie):
        ''' Removes the names of the cookie and returns the base64 decoded value.
        '''
        encCookieValue = cookie[8:]
        try:
            decCookieValue = base64.b64decode(encCookieValue)
            return decCookieValue
        except Exception as e:
            print e


class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
    ''' Implements IBurpExtender for hook into burp. Implement IMessageEditorTabFactory
    to access createNewInstance.
    '''
    def registerExtenderCallbacks(self, callbacks):

        # required for debugger: https://github.com/securityMB/burp-exceptions
        sys.stdout = callbacks.getStdout()
    
        # keep a reference to our callbacks object
        self._callbacks = callbacks

        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        # set our extension name
        callbacks.setExtensionName("Display a decoded VWAT_ID")

        # register ourselves as a message editor tab factory
        callbacks.registerMessageEditorTabFactory(self)

        return
        
    def createNewInstance(self, controller, editable):
        ''' Allows us to create a tab in the http tabs. Returns 
        an instance of a class that implements the iMessageEditorTab class
        '''
        return DisplayCookie(self, controller, editable)


class DisplayCookie(IMessageEditorTab):
    ''' Creates a message tab, which will display a specified cookie.
    '''
    def __init__(self, extender, controller, editable):
        ''' Extender is a instance of IBurpExtender class.
        Controller is a instance of the IMessageController class.
        Editable is boolean value which determines if the text editor is editable.
        '''
        self._txtInput = extender._callbacks.createTextEditor()
        self._cookie_processor = ProcessCookie()
        self._extender = extender
    
    def getUiComponent(self):
        ''' Must be invoked before the editor displays the new HTTP message,
        so that the custom tab can indicate whether it should be enabled for
        that message.
        '''
        return self._txtInput.getComponent()
    
    def getTabCaption(self):
        ''' Returns the name of the custom tab
        '''
        return "Decoded VWAT_ID"
        
    def isEnabled(self, content, isRequest):
        ''' Determines whether a tab shows up as a HTTP message
        '''
        if isRequest == True:
            requestInfo = self._extender._helpers.analyzeRequest(content)
            headers = requestInfo.getHeaders();
            self._cookie = ""
            for i, val in enumerate(headers):
                if val.find("Cookie") != -1:

                    # extracts the cookie
                    cookie_str = self._cookie_processor.extractCookie(val, COOKIE_REGEX)

                    # decodes the cookie value
                    self._cookie = self._cookie_processor.decodeBase64(cookie_str)
        return isRequest and self._cookie
        
    def setMessage(self, content, isRequest):
        ''' Shows the message in the tab if not none
        '''
        if (content is None):
            self._txtInput.setText(None)
            self._txtInput.setEditable(False)
        else:
            self._txtInput.setText(self._cookie)
        return


# for debugging. https://github.com/securityMB/burp-exceptions
try:
    FixBurpExceptions()
except:
    pass