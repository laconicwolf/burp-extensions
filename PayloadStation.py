__author__ = 'Jake Miller (@LaconicWolf)'
__date__ = '20190312'
__version__ = '0.01'
__description__ = """\
Burp Extension that generates Intruder payloads to 
test HTTP headers.
"""

from burp import IBurpExtender, IIntruderPayloadGeneratorFactory, IIntruderPayloadGenerator, ITab
from javax import swing
from java.awt import BorderLayout, GridLayout, Toolkit
from java.awt.datatransfer import StringSelection
from java.awt.datatransfer import Clipboard
from java.util import ArrayList

import string
import random
import threading
import time
import sys
try:
    from exceptions_fix import FixBurpExceptions
except ImportError:
    pass

headersToTest = {
    'Authorization': True,
    'Connection': True, 
    'Host': True,
    'HTTP2-Settings': True,
    'Origin': True,
    'Proxy-Authorization': True,
    'Referer': True, 
    'User-Agent': True,
    'X-Forwarded-For': True,
    'X-Forwarded-Host': True, 
    'X-Method-Override': True,
    'X-Wap-Profile': True    
}

headerTests = {
    "Random string reflection": True,
    "Error Invoking Characters": True,
    "Random long strings": True,
    "Out-of-band": True
}

class BurpExtender(IBurpExtender, ITab):
    def registerExtenderCallbacks(self, callbacks):
        
        # Required for easier debugging: 
        # https://github.com/securityMB/burp-exceptions
        sys.stdout = callbacks.getStdout()

        # Keep a reference to our callbacks object
        self.callbacks = callbacks

        # Set our extension name
        self.callbacks.setExtensionName("Payload Station")

        # Initialize the collaborator
        self.collab = ''
        
        # Create the tab
        self.tab = swing.JPanel(BorderLayout())
        tabbedPane = swing.JTabbedPane()
        self.tab.add(tabbedPane, BorderLayout.CENTER)

        # First tab ############ START XSS TAB ############
        firstTab = swing.JPanel()
        firstTab.layout = BorderLayout()
        tabbedPane.addTab("XSS", firstTab)

        # Top of Headers Panel
        tmpPanel = swing.JPanel()
        tmpPanel.layout = GridLayout(3, 5)
        tmpPanel.border = swing.BorderFactory.createTitledBorder("Tags to test")
        
        # First row
        tmpPanel.add(swing.JCheckBox("script", True, actionPerformed=self.handleXssSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("details", True, actionPerformed=self.handleXssSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("img", True, actionPerformed=self.handleXssSelectCheckBox))
        tmpPanel.add(swing.JLabel(""))
        
        # Second row
        tmpPanel.add(swing.JCheckBox("button", True, actionPerformed=self.handleXssSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("math", True, actionPerformed=self.handleXssSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("body", True, actionPerformed=self.handleXssSelectCheckBox))
        tmpPanel.add(swing.JLabel(""))
        
        # Third row
        tmpPanel.add(swing.JCheckBox("video", True, actionPerformed=self.handleXssSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("audio", True, actionPerformed=self.handleXssSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("object", True, actionPerformed=self.handleXssSelectCheckBox))
        tmpPanel.add(swing.JButton('Toggle All (TODO)', actionPerformed=self.handleXssButtonClick))
        
        firstTab.add(tmpPanel, BorderLayout.NORTH)

        # Middle of XSS Panel
        tmpPanel = swing.JPanel()
        tmpPanel.layout = BorderLayout()
        tmpPanel.border = swing.BorderFactory.createTitledBorder("Payloads")
        self.xssPayloadTextArea = swing.JTextArea('', 15, 100)
        self.xssPayloadTextArea.setLineWrap(False)
        scrollTextArea = swing.JScrollPane(self.xssPayloadTextArea)
        tmpPanel.add(scrollTextArea)
        firstTab.add(tmpPanel, BorderLayout.CENTER)

        # Right/Middle of XSS Panel
        tmpPanel = swing.JPanel()
        tmpPanel.layout = GridLayout(6,1)
        tmpPanel.border = swing.BorderFactory.createTitledBorder("Output options")
        tmpPanel.add(swing.JButton('Generate Payloads', actionPerformed=self.handleXssButtonClick))
        tmpPanel.add(swing.JButton('Copy Payloads to Clipboard', actionPerformed=self.handleXssButtonClick))
        tmpPanel.add(swing.JButton('Clear Payloads', actionPerformed=self.handleXssButtonClick))
        tmpPanel.add(swing.JButton('Save to File (TODO)', actionPerformed=self.handleXssButtonClick))
        tmpPanel.add(swing.JButton('Poll Collaborator Server', actionPerformed=self.handleXssButtonClick))
        tmpPanel.add(swing.JButton('TBD', actionPerformed=self.handleXssButtonClick))
        firstTab.add(tmpPanel, BorderLayout.EAST)

        # Bottom of XSS Panel
        tmpPanel = swing.JPanel()
        tmpPanel.layout = GridLayout(3, 5)
        tmpPanel.border = swing.BorderFactory.createTitledBorder("Config")
        
        # First row
        tmpPanel.add(swing.JCheckBox("onerror", True, actionPerformed=self.handleXssConfigCheckBox))
        tmpPanel.add(swing.JCheckBox("ontoggle", True, actionPerformed=self.handleXssConfigCheckBox))
        tmpPanel.add(swing.JLabel(""))
        tmpPanel.add(swing.JLabel(""))
        tmpPanel.add(swing.JLabel(""))
        
        # Second row
        tmpPanel.add(swing.JCheckBox("onmouseover", True, actionPerformed=self.handleXssConfigCheckBox))
        tmpPanel.add(swing.JCheckBox("onmouseclick", True, actionPerformed=self.handleXssConfigCheckBox))
        tmpPanel.add(swing.JLabel(""))
        tmpPanel.add(swing.JLabel(""))
        tmpPanel.add(swing.JLabel(""))

        # Third row
        tmpPanel.add(swing.JLabel(""))
        tmpPanel.add(swing.JLabel(""))
        tmpPanel.add(swing.JLabel(""))
        tmpPanel.add(swing.JLabel(""))
        tmpPanel.add(swing.JButton('Toggle All (TODO)', actionPerformed=self.handleXssButtonClick))     
        
        firstTab.add(tmpPanel, BorderLayout.SOUTH)
        ############ END XSS TAB ############

        # Second tab
        secondTab = swing.JPanel()
        secondTab.layout = BorderLayout()
        tabbedPane.addTab("SQLi", secondTab)

        ############ START HEADERS TAB ############
        # Third tab 
        thirdTab = swing.JPanel()
        thirdTab.layout = BorderLayout()
        tabbedPane.addTab("Headers", thirdTab)

        # Top of Headers Panel
        tmpPanel = swing.JPanel()
        tmpPanel.layout = GridLayout(3, 5)
        tmpPanel.border = swing.BorderFactory.createTitledBorder("Headers to test")
        
        # First row
        tmpPanel.add(swing.JCheckBox("Authorization", True, actionPerformed=self.handleHeadersSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("Connection", True, actionPerformed=self.handleHeadersSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("Host", True, actionPerformed=self.handleHeadersSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("HTTP2-Settings", True, actionPerformed=self.handleHeadersSelectCheckBox))
        tmpPanel.add(swing.JLabel(""))
        
        # Second row
        tmpPanel.add(swing.JCheckBox("Origin", True, actionPerformed=self.handleHeadersSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("Proxy-Authorization", True, actionPerformed=self.handleHeadersSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("Referer", True, actionPerformed=self.handleHeadersSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("User-Agent", True, actionPerformed=self.handleHeadersSelectCheckBox))
        tmpPanel.add(swing.JLabel(""))
        
        # Third row
        tmpPanel.add(swing.JCheckBox("X-Forwarded-For", True, actionPerformed=self.handleHeadersSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("X-Forwarded-Host", True, actionPerformed=self.handleHeadersSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("X-Method-Override", True, actionPerformed=self.handleHeadersSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("X-Wap-Profile", True, actionPerformed=self.handleHeadersSelectCheckBox))
        tmpPanel.add(swing.JButton('Toggle All (TODO)', actionPerformed=self.handleHeadersButtonClick))
        
        thirdTab.add(tmpPanel, BorderLayout.NORTH)

        # Middle of Headers Panel
        tmpPanel = swing.JPanel()
        tmpPanel.layout = BorderLayout()
        tmpPanel.border = swing.BorderFactory.createTitledBorder("Payloads")
        self.headerPayloadTextArea = swing.JTextArea('', 15, 100)
        self.headerPayloadTextArea.setLineWrap(False)
        scrollTextArea = swing.JScrollPane(self.headerPayloadTextArea)
        tmpPanel.add(scrollTextArea)
        thirdTab.add(tmpPanel, BorderLayout.CENTER)

        # Right/Middle of Headers Panel
        tmpPanel = swing.JPanel()
        tmpPanel.layout = GridLayout(6,1)
        tmpPanel.border = swing.BorderFactory.createTitledBorder("Output options")
        tmpPanel.add(swing.JButton('Generate Payloads', actionPerformed=self.handleHeadersButtonClick))
        tmpPanel.add(swing.JButton('Copy Payloads to Clipboard', actionPerformed=self.handleHeadersButtonClick))
        tmpPanel.add(swing.JButton('Clear Payloads', actionPerformed=self.handleHeadersButtonClick))
        tmpPanel.add(swing.JButton('Save to File (TODO)', actionPerformed=self.handleHeadersButtonClick))
        tmpPanel.add(swing.JButton('Poll Collaborator Server', actionPerformed=self.handleHeadersButtonClick))
        tmpPanel.add(swing.JButton('TBD', actionPerformed=self.handleHeadersButtonClick))
        thirdTab.add(tmpPanel, BorderLayout.EAST)

        # Bottom of Headers Panel
        tmpPanel = swing.JPanel()
        tmpPanel.layout = GridLayout(3, 5)
        tmpPanel.border = swing.BorderFactory.createTitledBorder("Config")
        
        # First row
        tmpPanel.add(swing.JCheckBox("Random string reflection", True, actionPerformed=self.handleHeadersConfigCheckBox))
        tmpPanel.add(swing.JCheckBox("Error Invoking Characters", True, actionPerformed=self.handleHeadersConfigCheckBox))
        tmpPanel.add(swing.JLabel(""))
        tmpPanel.add(swing.JLabel(""))
        tmpPanel.add(swing.JLabel(""))
        
        # Second row
        tmpPanel.add(swing.JCheckBox("Random long strings", True, actionPerformed=self.handleHeadersConfigCheckBox))
        tmpPanel.add(swing.JCheckBox("Out-of-band", True, actionPerformed=self.handleHeadersConfigCheckBox))
        tmpPanel.add(swing.JLabel(""))
        tmpPanel.add(swing.JLabel(""))
        tmpPanel.add(swing.JLabel(""))

        # Third row
        tmpPanel.add(swing.JLabel(""))
        tmpPanel.add(swing.JLabel(""))
        tmpPanel.add(swing.JLabel(""))
        tmpPanel.add(swing.JLabel(""))
        tmpPanel.add(swing.JButton('Toggle All (TODO)', actionPerformed=self.handleHeadersButtonClick))     
        
        thirdTab.add(tmpPanel, BorderLayout.SOUTH)
        ############ END HEADERS TAB ############

        # Fourth tab
        fourthTab = swing.JPanel()
        fourthTab.layout = BorderLayout()
        tabbedPane.addTab("Web Shells", fourthTab)

        # Fifth tab
        fifthTab = swing.JPanel()
        fifthTab.layout = BorderLayout()
        tabbedPane.addTab("Path Traversal", fifthTab)

        # Sixth tab
        sixthTab = swing.JPanel()
        sixthTab.layout = BorderLayout()
        tabbedPane.addTab("OS Injection", sixthTab)

        callbacks.addSuiteTab(self)
        return

    def getTabCaption(self):
        """Return the text to be displayed on the tab"""
        return "Payload Station"
    
    def getUiComponent(self):
        """Passes the UI to burp"""
        return self.tab

    def handleXssSelectCheckBox(self, event):
        """Handles checkbox clicks from the XSS menu 
        header selection to ensure only payloads for 
        specified headers are generated.
        """
        if event.source.selected:
            print event.source.selected, 'selected'
        else:
            print event.source.selected, 'not selected'

    def handleXssConfigCheckBox(self, event):
        """Handles heckbox clicks from the XSS menu config 
        selection to ensure only payloads are generated with 
        or without any specified options.
        """
        if event.source.selected:
            print event.source.selected, 'selected'
        else:
            print event.source.selected, 'not selected'

    def handleXssButtonClick(self, event):
        """Handles button clicks from header menu."""
        print 'button clicked'

    def generateXssPayloads(self):
        """Write payloads to the text area"""
        self.xssPayloadTextArea.text = 'test'

    def handleHeadersSelectCheckBox(self, event):
        """Handles checkbox clicks from the Headers menu 
        header selection to ensure only payloads for 
        specified headers are generated.
        """
        if event.source.selected:
            headersToTest[event.source.text] = True
        else:
            headersToTest[event.source.text] = False

    def handleHeadersConfigCheckBox(self, event):
        """Handles heckbox clicks from the Headers menu config 
        selection to ensure only payloads are generated with 
        or without any specified options.
        """
        if event.source.selected:
            headerTests[event.source.text] = True
        else:
            headerTests[event.source.text] = False

    def handleHeadersButtonClick(self, event):
        """Handles button clicks from header menu."""
        buttonText = event.source.text
        if buttonText == "Generate Payloads":
            t = threading.Thread(target=self.generateHeaderPayloads())
            t.daemon = True
            t.start()
        elif buttonText == "Copy Payloads to Clipboard":
            toolkit = Toolkit.getDefaultToolkit()
            clipboard = toolkit.getSystemClipboard()
            clipboard.setContents(StringSelection(self.headerPayloadTextArea.text), None)
        elif buttonText == 'Clear Payloads':
            self.headerPayloadTextArea.text = ''
        elif buttonText == "Reset to default":
            pass
        elif buttonText == "Poll Collaborator Server":
            t = threading.Thread(target=self.pollCollabServer())
            t.daemon = True
            t.start()
        else:
            pass

    def generateHeaderPayloads(self):
        """Write payloads to the text area"""
        payloads = []
        headers = [header for header in headersToTest if headersToTest[header]]
        tests = [test for test in headerTests if headerTests[test]]

        for header in headers:
            for test in tests:
                if test == "Random string reflection":
                    payloads.append(header + ': ' + getRandomString(10))
                if test == "Random long strings":
                    payloads.append(header + ': ' + getRandomString(25))
                    payloads.append(header + ': ' + getRandomString(50))
                    payloads.append(header + ': ' + getRandomString(100))
                    payloads.append(header + ': ' + getRandomString(500))
                    payloads.append(header + ': ' + getRandomString(1000))
                if test == "Error Invoking Characters":
                    payloads += [header + ': ' + char for char in list(string.punctuation)]
                if test == "Out-of-band":
                    self.collab = self.callbacks.createBurpCollaboratorClientContext()
                    collabPayload = self.collab.generatePayload(True)
                    payloads.append(header + ': ' + 'https://' + collabPayload)
            if header == "Authorization":
                payloads.append(header + ': Basic dGVzdHVzZXI6dGVzdHBhc3N3b3Jk')
                payloads.append(header + ': Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c')
                payloads.append(header + ': Digest username="Mufasa"')
        self.headerPayloadTextArea.text = '\n'.join(payloads)

    def pollCollabServer(self):
        """Polls the collaborator server."""
        if self.collab:
            interactions = self.collab.fetchAllCollaboratorInteractions()
            if interactions:
                for i in interactions:
                    props = i.properties
                    print "Received interaction '{}' from {} at {} via {}".format(props['interaction_id'], props['client_ip'], props['time_stamp'], props['type'])

def getRandomString(length):
    """Returns a random string of lowercase letters."""
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))

try:
    FixBurpExceptions()
except:
    pass