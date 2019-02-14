__author__ = 'Jake Miller (@LaconicWolf)'
__date__ = '20190214'
__version__ = '0.01'
__description__ = """Burp Extension that changes HTTP requests
                  into Python and PowerShell formats.
                  """

from burp import IBurpExtender, ITab, IContextMenuFactory
from javax import swing
from java.awt import BorderLayout
from java.util import ArrayList
import sys
import urllib
import urlparse
from BaseHTTPServer import BaseHTTPRequestHandler
from StringIO import StringIO
try:
    from exceptions_fix import FixBurpExceptions
except ImportError:
    pass

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        
        # Required for easier debugging: 
        # https://github.com/securityMB/burp-exceptions
        sys.stdout = callbacks.getStdout()

        # Keep a reference to our callbacks object
        self.callbacks = callbacks

        # Set our extension name
        self.callbacks.setExtensionName("Request-as-Python-or-PowerShell")

        # Create a context menu
        callbacks.registerContextMenuFactory(self)
        
        # Create the tab
        self.tab = swing.JPanel(BorderLayout())

        # Create a split panel where you can manually 
        # adjust the panel size.
        splitPane = swing.JSplitPane(swing.JSplitPane.VERTICAL_SPLIT)

        # Create the top panel containing the text area
        textPanel = swing.JPanel()

        # An empty text area 12 columns deep and 
        # full screen length.
        self.textArea = swing.JTextArea('', 12, 100)

        # Wrap the lines in the text area
        self.textArea.setLineWrap(True)

        # When the lines get bigger than the area
        # implement a scroll pane and put the text area
        # in the pane.
        scroll = swing.JScrollPane(self.textArea)

        # Set this scroll pane as the top of our split panel
        splitPane.setTopComponent(scroll)
        

        # Create the bottom panel for the transformed request. 
        # Each label and text field will go in horizontal 
        # boxes (rows) which will then go in a bigger box (box)        
        
        # The big box
        box = swing.Box.createVerticalBox()
        
        # Row containing the button that calls transformRequestsAs
        row = swing.Box.createHorizontalBox()
        row.add(swing.JButton('Transform', 
                          actionPerformed=self.transformRequestsAs))
        
        # Add the row to the big box
        box.add(row)

        # Row containing label and text area
        row = swing.Box.createHorizontalBox()
        self.pythonRequests = swing.JTextArea('', 2, 100)
        self.pythonRequests.setLineWrap(True)
        scroll = swing.JScrollPane(self.pythonRequests)
        row.add(swing.JLabel("<html><pre>  Python<br/>  Requests   </pre></html>"))
        row.add(scroll)
        box.add(row)

        # Row containing label and text area
        row = swing.Box.createHorizontalBox()
        self.pythonUrlLib = swing.JTextArea('', 2, 100)
        self.pythonUrlLib.setLineWrap(True)
        scroll = swing.JScrollPane(self.pythonUrlLib)
        row.add(swing.JLabel("<html><pre>  Python<br/>  Urllib2    </pre></html>"))
        row.add(scroll)
        box.add(row)

        # Row containing label and text area
        row = swing.Box.createHorizontalBox()
        self.powershellIwr = swing.JTextArea('', 2, 100)
        self.powershellIwr.setLineWrap(True)
        scroll = swing.JScrollPane(self.powershellIwr)
        row.add(swing.JLabel("<html><pre>  PowerShell<br/>  IWR        </pre></html>"))
        row.add(scroll)
        box.add(row)

        # Add this Panel to the bottom of the split panel
        splitPane.setBottomComponent(box)
        splitPane.setDividerLocation(150)

        self.tab.add(splitPane)

        # Add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)
        return

    # Implement ITab
    def getTabCaption(self):
        """Return the text to be displayed on the tab"""
        return "Request as Python/PowerShell"
    
    def getUiComponent(self):
        """Passes the UI to burp"""
        return self.tab

    # Implement IContextMenuFactory
    def createMenuItems(self, invocation):
        '''Adds the extension to the context menu that 
        appears when you right-click an object.
        '''
        self.context = invocation
        itemContext = invocation.getSelectedMessages()
        
        # Only return a menu item if right clicking on a 
        # HTTP object
        if itemContext > 0:
        
            # Must return a Java list 
            menuList = ArrayList()
            menuItem = swing.JMenuItem("Send to Request as Python/PowerShell",
                                        actionPerformed=self.handleHttpTraffic)
            menuList.add(menuItem)
            return menuList
        return None


    def handleHttpTraffic(self, event):
        """Calls the function to write the HTTP object to 
        the extensions text area, and then begins to parse
        the HTTP traffic for use in other functions.
        """
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

    def transformRequestsAs(self, event):
        """Calls functions that transform the HTTP object
        text area into a python or powershell request if
        applicable.
        """
        self.pythonRequests.text = self.parseAsPythonRequests()
        self.pythonUrlLib.text = self.parseAsPythonUrlLib()
        self.powershellIwr.text = self.parseAsPowershellIwr()

    def parseAsPythonRequests(self):
        """Uses BaseHttpRequestHandler to parse an HTTP
        request and print a command to make the same request
        using the Python requests library.
        """
        request = HTTPRequest(self.textArea.text)
        url = self.httpService.toString()
        url += request.path
        headerValuesSplit = str(request.headers.values).split('\n')[1:]
        headerNames = [header.split(':')[0] for header in headerValuesSplit]
        headerValues = []
        for value in headerValuesSplit:
            if value.count(':') > 1:
                headerValues.append(':'.join(value.split(':')[1:]).strip())
            else:
                headerValues.append(''.join(value.split(':')[1:]).strip())
    
        url = ''.join(url)
        header_dict = dict(zip(headerNames, headerValues))
        headers = {k: v for k, v in header_dict.items() if v}
        verb = request.command.lower()
        data = ''

        dataVerbs = ["PUT, POST, DELETE"]
        if request.command in dataVerbs or int(request.headers.getheader('content-length')):
            length = int(request.headers.getheader('content-length'))
            body = request.rfile.read(length)
            data = urlparse.parse_qsl(body)

        if data:
            command = \
"""import requests

s=requests.Session()

s.headers = {}

data = {}

resp = s.{}('{}', data)""".format(headers, data, verb, url)
        else:
            command =\
"""import requests

s = requests.Session()

s.headers = {}

resp = s.{}('{}'')""".format(headers, verb, url)

        return command

    def parseAsPythonUrlLib(self):
        """Uses BaseHttpRequestHandler to parse an HTTP
        request and print a command to make the same request
        using the Python urllib2 library.
        """
        request = HTTPRequest(self.textArea.text)
        verbs = ['GET', 'POST']
        if request.command not in verbs:
            return "Only GET and POST requests currently implemented."
        url = self.httpService.toString()
        url += request.path
        headerValuesSplit = str(request.headers.values).split('\n')[1:]
        headerNames = [header.split(':')[0] for header in headerValuesSplit]
        headerValues = []
        for value in headerValuesSplit:
            if value.count(':') > 1:
                headerValues.append(':'.join(value.split(':')[1:]).strip())
            else:
                headerValues.append(''.join(value.split(':')[1:]).strip())
    
        url = ''.join(url)
        header_dict = dict(zip(headerNames, headerValues))
        headers = {k: v for k, v in header_dict.items() if v}
        verb = request.command.lower()
        data = ''

        if request.command == 'POST':
            length = int(request.headers.getheader('content-length'))
            body = request.rfile.read(length)
            data = urlparse.parse_qsl(body)

        if data:
            command = \
"""import urllib2
import urllib

data = urllib.urlencode({})

headers = {}

req = urllib2.Request('{}')

req.headers = headers

resp = urllib2.urlopen(req, data)""".format(data, headers, url)
        
        else:
            command =\
"""import urllib2

headers = {}

req = urllib2.Request('{}')

req.headers = headers

resp = urllib2.urlopen(req,)""".format(headers, url)
        
        return command

    def parseAsPowershellIwr(self):
        """Uses BaseHttpRequestHandler to parse an HTTP
        request and print a command to make the same request
        using the Invoke-WebRequest powershell Cmdlet.
        """
        request = HTTPRequest(self.textArea.text)
        url = self.httpService.toString()
        url += request.path
        headerValuesSplit = str(request.headers.values).split('\n')[1:]
        headerNames = [header.split(':')[0] for header in headerValuesSplit]
        headerValues = []
        for value in headerValuesSplit:
            if value.count(':') > 1:
                headerValues.append(':'.join(value.split(':')[1:]).strip())
            else:
                headerValues.append(''.join(value.split(':')[1:]).strip())
    
        url = ''.join(url)
        header_dict = dict(zip(headerNames, headerValues))
        headers = {k: v for k, v in header_dict.items() if v}
        headers.pop('connection', None)
        iwrHeaderHashTable = '@{'
        for item in headers:
            iwrHeaderHashTable += "'{}'='{}';".format(item, headers[item])
        iwrHeaderHashTable = iwrHeaderHashTable[:-1] + '}'
        verb = request.command.lower()
        data = ''

        dataVerbs = ["PUT, POST, DELETE"]
        if request.command in dataVerbs or int(request.headers.getheader('content-length')):
            length = int(request.headers.getheader('content-length'))
            body = request.rfile.read(length)
            data = urlparse.parse_qsl(body)

        iwrData = '@{'
        for item in data:
            try:
                iwrData += "'{}'='{}';".format(item[0], item[1])
            except Exception as e:
                print e
        iwrData = iwrData[:-1] + '}'
        if iwrData:
            command = \
"""\

$Method = '{}'
$Uri = '{}'
$Headers = {}
$Body = {}

Invoke-WebRequest \
-Method $Method \
-Uri $Uri \
-Headers $Headers \
-Body $Body
""".format(request.command, url, iwrHeaderHashTable, iwrData)
        
        else:
            command =\
"""\
$Method = '{}'
$Uri = '{}'
$Headers = {}

Invoke-WebRequest \
-Method $Method \
-Uri $Uri \
-Headers $Headers \
""".format(request.command, url, iwrHeaderHashTable)
        
        return command

class HTTPRequest(BaseHTTPRequestHandler):
    '''Parses an HTTP request
    #https://stackoverflow.com/questions/4685217/parse-raw-http-headers
    '''
    def __init__(self, request_text):
        self.rfile = StringIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()

    def send_error(self, code, message):
        self.error_code = code
        self.error_message = message

try:
    FixBurpExceptions()
except:
    pass