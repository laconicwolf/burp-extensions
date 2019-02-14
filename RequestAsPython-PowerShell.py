__author__ = 'Jake Miller (@LaconicWolf)'
__date__ = '20190220'
__version__ = '0.01'
__description__ = """Burp Extension that changes HTTP requests
                  into useful formats.
                  """

from burp import IBurpExtender, ITab, IContextMenuFactory
from javax import swing
from java.awt import BorderLayout
from java.util import ArrayList
import sys
import base64
import urllib
import binascii
import cgi
import json
import re
import hashlib
import urlparse
from HTMLParser import HTMLParser
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
        self.callbacks.setExtensionName("RequestAsPython/PowerShell")

        # Create a context menu
        callbacks.registerContextMenuFactory(self)
        
        # Create the tab
        self.tab = swing.JPanel(BorderLayout())

        # Create the text area at the top of the tab
        textPanel = swing.JPanel()
        self.textArea = swing.JTextArea('', 10, 100)
        self.textArea.setLineWrap(True)
        scroll = swing.JScrollPane(self.textArea)

        # Add the text area to the text panel
        textPanel.add(scroll)

        # Add the text panel to the top of the main tab
        self.tab.add(textPanel, BorderLayout.NORTH)

        # Created a tabbed pane to go in the center of the
        # main tab, below the text area
        tabbedPane = swing.JTabbedPane()
        #self.tab.add("Center", tabbedPane)
        self.tab.add(tabbedPane, BorderLayout.CENTER)

        # First tab
        firstTab = swing.JPanel()
        firstTab.layout = BorderLayout()
        tabbedPane.addTab("RequestAs", firstTab)

        # Button for first tab
        buttonPanel = swing.JPanel()
        buttonPanel.add(swing.JButton('Transform', actionPerformed=self.morphRequestsAs))
        firstTab.add(buttonPanel, "North")

        # Panel for the encoders. Each label and text field
        # will go in horizontal boxes which will then go in 
        # a vertical box
        encPanel = swing.JPanel()
        box = swing.Box.createVerticalBox()
        
        row = swing.Box.createHorizontalBox()
        self.pythonRequests = swing.JTextArea('', 2, 100)
        self.pythonRequests.setLineWrap(True)
        scroll = swing.JScrollPane(self.pythonRequests)
        row.add(swing.JLabel("<html><pre>  Python<br/>  Requests   </pre></html>"))
        row.add(scroll)
        box.add(row)

        row = swing.Box.createHorizontalBox()
        self.pythonUrlLib = swing.JTextArea('', 2, 100)
        self.pythonUrlLib.setLineWrap(True)
        scroll = swing.JScrollPane(self.pythonUrlLib)
        row.add(swing.JLabel("<html><pre>  Python<br/>  Urllib2    </pre></html>"))
        row.add(scroll)
        box.add(row)

        row = swing.Box.createHorizontalBox()
        self.powershellIwr = swing.JTextArea('', 2, 100)
        self.powershellIwr.setLineWrap(True)
        scroll = swing.JScrollPane(self.powershellIwr)
        row.add(swing.JLabel("<html><pre>  PowerShell<br/>  IWR        </pre></html>"))
        row.add(scroll)
        box.add(row)

        # Add the vertical box to the Encode tab
        firstTab.add(box, "Center")

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
        self.writeRequestToTextBox()
        httpTraffic = self.context.getSelectedMessages()
        #self.httpService = ''.join([item.getHttpService() for item in httpTraffic])
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

    def morphRequestsAs(self, event):
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
            print body
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

Invoke-WebRequests \
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

Invoke-WebRequests \
-Method $Method \
-Uri $Uri \
-Headers $Headers \
""".format(request.command, url, iwrHeaderHashTable)
        
        return command

class HTTPRequest(BaseHTTPRequestHandler):
    #https://stackoverflow.com/questions/4685217/parse-raw-http-headers
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