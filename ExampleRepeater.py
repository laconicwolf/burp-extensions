__author__ = 'Jake Miller (@LaconicWolf)'
__date__ = '20190215'
__version__ = '0.01'
__description__ = """\
Burp Extension that allows a user to right click on a request
and send to the extension, and then replay the request and
view the response. Like repeater, only hastily thrown together
with much less features and elegance. Really just for learning.
"""

# Burp imports
from burp import IBurpExtender, ITab, IContextMenuFactory

# Jython specific imports for the GUI
from javax import swing
from java.awt import BorderLayout
from java.util import ArrayList

# stdlib
import sys
import threading

# For easier debugging, if you want.
# https://github.com/securityMB/burp-exceptions
try:
    from exceptions_fix import FixBurpExceptions
except ImportError:
    pass

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        
        # Required for easier debugging: 
        sys.stdout = callbacks.getStdout()

        # Keep a reference to our callbacks object
        self.callbacks = callbacks

        # Obtain an extension helpers object
        self.helpers = callbacks.getHelpers()

        # Set our extension name
        self.callbacks.setExtensionName("ExampleRepeaterExtension")

        # Create a context menu
        callbacks.registerContextMenuFactory(self)
        
        # Create the tab
        self.tab = swing.JPanel(BorderLayout())

        # Create a split panel
        splitPane = swing.JSplitPane(swing.JSplitPane.VERTICAL_SPLIT)

        # Create the top panel containing the text area
        box = swing.Box.createVerticalBox()

        # Make the text area
        row = swing.Box.createHorizontalBox()
        textPanel = swing.JPanel()
        self.textArea = swing.JTextArea('', 15, 100)
        self.textArea.setLineWrap(True)
        scroll = swing.JScrollPane(self.textArea)
        row.add(scroll)
        box.add(row)

         # Make a button
        row = swing.Box.createHorizontalBox()
        row.add(swing.JButton('Go!', 
                          actionPerformed=self.handleButtonClick))
        box.add(row)

        # Set the top pane
        splitPane.setTopComponent(box)

        # Bottom panel for the response. 
        box = swing.Box.createVerticalBox()

        # Make the text box for the HTTP response
        row = swing.Box.createHorizontalBox()
        self.responseTextArea = swing.JTextArea('', 15, 100)
        self.responseTextArea.setLineWrap(True)
        scroll = swing.JScrollPane(self.responseTextArea)
        row.add(scroll)
        box.add(row)

        # Set the bottom pane
        splitPane.setBottomComponent(box)

        # Start the divider roughly in the middle
        splitPane.setDividerLocation(250)

        # Add everything to the custom tab
        self.tab.add(splitPane)

        # Add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)
        return

    # Implement ITab
    def getTabCaption(self):
        """Return the text to be displayed on the tab"""
        return "Example Repeater"
    
    def getUiComponent(self):
        """Passes the UI to burp"""
        return self.tab

    # Implement IContextMenuFactory
    def createMenuItems(self, invocation):
        """Adds the extension to the context menu that 
        appears when you right-click an object.
        """
        self.context = invocation
        itemContext = invocation.getSelectedMessages()
        
        # Only return a menu item if right clicking on a 
        # HTTP object
        if itemContext > 0:
        
            # Must return a Java list 
            menuList = ArrayList()
            menuItem = swing.JMenuItem("Send to Example Repeater",
                                        actionPerformed=self.handleHttpTraffic)
            menuList.add(menuItem)
            return menuList
        return None

    def handleHttpTraffic(self, event):
        """Calls the function to write the HTTP object to 
        the request text area, and then begins to parse
        the HTTP traffic for use in other functions.
        """

        # Writes to the top pane text box
        self.writeRequestToTextBox()
        httpTraffic = self.context.getSelectedMessages()
        for item in httpTraffic:
            self.httpService = item.getHttpService()

    def writeRequestToTextBox(self):
        """Writes HTTP context item to RequestTransformer 
        tab text box.
        """
        httpTraffic = self.context.getSelectedMessages()
        httpRequest = [item.request.tostring() for item in httpTraffic]
        request = ''.join(httpRequest)
        self.textArea.text = request

    def handleButtonClick(self, event):
        """Attempts to make an HTTP request for the
        object in the text area.
        """

        # Get data about the request that was right clicked
        host = self.httpService.host 
        port = self.httpService.port
        protocol = self.httpService.protocol
        protoChoice = True if protocol.lower() == 'https' else False

        # Parse the text area that should contain an HTTP
        # request.
        requestInfo = self.helpers.analyzeRequest(self.textArea.text)
        headers = requestInfo.getHeaders()
        bodyOffset = requestInfo.bodyOffset 
        body = self.textArea.text[bodyOffset:]

        # Build the request to be sent
        request = self.helpers.buildHttpMessage(headers, body)

        # Need to make the HTTP request in new thread to
        # prevent the GUI from locking up while the 
        # request is being made.
        t = threading.Thread(
            target=self.makeRequest,
            args=[host, port, protoChoice, request]
        )
        t.daemon = True
        t.start()

    def makeRequest(self, host, port, protoChoice, request):
        """Makes an HTTP request and writes the response to
        the response text area.
        """
        resp = self.callbacks.makeHttpRequest(
            host,           # string
            port,           # int
            protoChoice,    # bool
            request         # bytes
        )
        self.responseTextArea.text = resp.tostring()

try:
    FixBurpExceptions()
except:
    pass