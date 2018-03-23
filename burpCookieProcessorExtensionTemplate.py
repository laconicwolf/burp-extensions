from burp import IBurpExtender
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
import sys
import re

# for debugging. https://github.com/securityMB/burp-exceptions
try:
    from exceptions_fix import FixBurpExceptions
except:
    pass


__author__ = 'Jake Miller (@LaconicWolf)'
__date__ = '20180322'
__version__ = '0.01'
__description__ = ''' Processes a specific cookie. Currently displays the cookie in a
                  separate HTTP request tab.

                  A lot of the code inspired by an nVisium extender tutorial
                  (https://www.youtube.com/watch?v=4f05lNULX1I)    
                  '''

# the cookie you want to process
COOKIE_REGEX = "INSERT string or regex here"
# Example
# COOKIE_REGEX = 'ASP.NET_SessionId(.*)'

class ProcessCookie:
    ''' Extracts and returns a specified cookie. If no cookie is found, returns
    an empty string.
    '''
    def extract_cookie(self, cookie, pattern):
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
        callbacks.setExtensionName("Display a specified Cookie")

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
        return "ASP.Net_SessionId"
        
    def isEnabled(self, content, isRequest):
        ''' Determines whether a tab shows up on an HTTP message
        '''
        if isRequest == True:
            requestInfo = self._extender._helpers.analyzeRequest(content)
            headers = requestInfo.getHeaders();
            self._cookie = ""
            for i, val in enumerate(headers):
                if val.find("Cookie") != -1:
                    cookie_str = self._cookie_processor.extract_cookie(val, COOKIE_REGEX)
                    self._cookie = self._cookie_processor.extract_cookie(cookie_str, COOKIE_REGEX)
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