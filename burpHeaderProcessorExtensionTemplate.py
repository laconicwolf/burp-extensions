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
__description__ = ''' Just displays the HTTP headers in a new message tab
                  as a sort of a template. 
                  '''
    

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
        callbacks.setExtensionName("Just testing")

        # register ourselves as a message editor tab factory
        callbacks.registerMessageEditorTabFactory(self)

        return
        
    def createNewInstance(self, controller, editable):
        ''' Allows us to create a tab in the http tabs. Returns 
        an instance of a class that implements the iMessageEditorTab class
        '''
        return DisplayValues(self, controller, editable)


class DisplayValues(IMessageEditorTab):
    ''' Creates a message tab, and controls the logic of which portion
    of the HTTP message is processed.
    '''
    def __init__(self, extender, controller, editable):
        ''' Extender is a instance of IBurpExtender class.
        Controller is a instance of the IMessageController class.
        Editable is boolean value which determines if the text editor is editable.
        '''
        self._txtInput = extender._callbacks.createTextEditor()
        #self._cookie_processor = ProcessCookie()
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
        return "My Headers"
        
    def isEnabled(self, content, isRequest):
        ''' Determines whether a tab shows up on an HTTP message
        '''
        if isRequest == True:
            requestInfo = self._extender._helpers.analyzeRequest(content)
            headers = requestInfo.getHeaders();
            self._headers = ""
            for i, header in enumerate(headers):
                self._headers += header + '\n'

        return isRequest and self._headers
        
    def setMessage(self, content, isRequest):
        ''' Shows the message in the tab if not none
        '''
        if (content is None):
            self._txtInput.setText(None)
            self._txtInput.setEditable(False)
        else:
            self._txtInput.setText(self._headers)
        return


# for debugging. https://github.com/securityMB/burp-exceptions
try:
    FixBurpExceptions()
except:
    pass