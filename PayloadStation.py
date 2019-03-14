__author__ = 'Jake Miller (@LaconicWolf)'
__date__ = '20190312'
__version__ = '0.01'
__description__ = """\
Burp Extension that generates payloads for 
various testing needs.
"""

from burp import IBurpExtender, ITab
from javax import swing
from javax.swing.filechooser import FileNameExtensionFilter
from java.awt import BorderLayout, GridLayout, Toolkit
from java.awt.datatransfer import StringSelection
from java.awt.datatransfer import Clipboard
from java.util import ArrayList

import string
import random
import threading
import time
import cgi
import urllib
import re
import sys
import os
import xml.etree.ElementTree as etree
try:
    from exceptions_fix import FixBurpExceptions
except ImportError:
    pass

xssTags = {
    'script': True,
    'button': True,
    'video': False,
    'details': True,
    'math': False,
    'audio': False,
    'img': True,
    'body': False,
    'object': False
}

xssEventHandlers = {
    'onclick': True,
    'onerror': True,
    'onkeypress': True,
    'onmouseover': True,
    'onsubmit': False,
    'ondblclick': False,
    'onmouseenter': False,
    'onscroll': False,
    'onwheel': False
}

xssConfig = {
    "URL encode special chars": False,
    "Replace () with ``": False,
    "Toggle case": False,
    "Capitalize": False,
    "HTML encode special chars": False,
    "Append random chars": False,
    "Non-standard percent encoding": False,
    "Non-standard slash encoding": False
}

sqliDbmsToTest = {
    "MySQL": True,
    "Oracle": True,
    "PostgreSQL": True,
    "Microsoft SQL Server": True,
    "Microsoft Access": False,
    "IBM DB2": False,
    "SQLite": False,
    "Firebird": False,
    "Sybase": False,
    "SAP MaxDB": False,
    "HSQLDB": False,
    "Informix": False,
}

sqliTechniques = {
    "Boolean-based blind": True,
    "Error-based": True,
    "Time-based blind": True,
    "UNION query-based": True,
    "Stacked queries": True
}

sqliConfig = {
    "URL encode special chars": False,
    "Replace () with ``": False,
    "Toggle case": False,
    "Capitalize": False,
    "HTML encode special chars": False,
    "Append random chars": False,
    "Non-standard percent encoding": False,
    "Non-standard slash encoding": False
}

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
    "Out-of-band": True,
}

class BurpExtender(IBurpExtender, ITab, swing.JFrame):
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

        tmpGridPanel = swing.JPanel()
        tmpGridPanel.layout = GridLayout(1, 2)

        # Top of XSS Panel
        tmpPanel = swing.JPanel()
        tmpPanel.layout = GridLayout(3, 5)
        tmpPanel.border = swing.BorderFactory.createTitledBorder("Tags to test")
        
        # First row
        tmpPanel.add(swing.JCheckBox("script", True, actionPerformed=self.handleXssTagsSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("details", True, actionPerformed=self.handleXssTagsSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("img", True, actionPerformed=self.handleXssTagsSelectCheckBox))
        tmpPanel.add(swing.JLabel(""))
        
        # Second row
        tmpPanel.add(swing.JCheckBox("button", True, actionPerformed=self.handleXssTagsSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("math", False, actionPerformed=self.handleXssTagsSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("body", False, actionPerformed=self.handleXssTagsSelectCheckBox))
        tmpPanel.add(swing.JLabel(""))
        
        # Third row
        tmpPanel.add(swing.JCheckBox("video", False, actionPerformed=self.handleXssTagsSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("audio", False, actionPerformed=self.handleXssTagsSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("object", False, actionPerformed=self.handleXssTagsSelectCheckBox))
        tmpPanel.add(swing.JLabel(""))

        # Top of XSS Panel
        tmpPanel1 = swing.JPanel()
        tmpPanel1.layout = GridLayout(3, 5)
        tmpPanel1.border = swing.BorderFactory.createTitledBorder("Event Handlers")
     
        # First row
        tmpPanel1.add(swing.JCheckBox("onclick", True, actionPerformed=self.handleXssEventCheckBox))
        tmpPanel1.add(swing.JCheckBox("onmouseover", True, actionPerformed=self.handleXssEventCheckBox))
        tmpPanel1.add(swing.JCheckBox("onmouseenter", True, actionPerformed=self.handleXssEventCheckBox))
        tmpPanel1.add(swing.JLabel(""))
        
        # Second row
        tmpPanel1.add(swing.JCheckBox("onerror", True, actionPerformed=self.handleXssEventCheckBox))
        tmpPanel1.add(swing.JCheckBox("onsubmit", False, actionPerformed=self.handleXssEventCheckBox))
        tmpPanel1.add(swing.JCheckBox("onscroll", False, actionPerformed=self.handleXssEventCheckBox))
        tmpPanel1.add(swing.JLabel(""))
        
        # Third row
        tmpPanel1.add(swing.JCheckBox("onkeypress", False, actionPerformed=self.handleXssEventCheckBox))
        tmpPanel1.add(swing.JCheckBox("ondblclick", False, actionPerformed=self.handleXssEventCheckBox))
        tmpPanel1.add(swing.JCheckBox("onwheel", False, actionPerformed=self.handleXssEventCheckBox))
        tmpPanel1.add(swing.JLabel(""))

        #firstTab.add(tmpPanel, BorderLayout.NORTH)
        tmpGridPanel.add(tmpPanel)
        tmpGridPanel.add(tmpPanel1)
        firstTab.add(tmpGridPanel, BorderLayout.NORTH)

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
        tmpPanel.add(swing.JButton('Save to File', actionPerformed=self.handleXssButtonClick))
        tmpPanel.add(swing.JButton('TBD', actionPerformed=self.handleXssButtonClick))
        tmpPanel.add(swing.JButton('TBD', actionPerformed=self.handleXssButtonClick))
        firstTab.add(tmpPanel, BorderLayout.EAST)

        # Bottom of XSS Panel
        tmpPanel = swing.JPanel()
        tmpPanel.layout = GridLayout(3, 5)
        tmpPanel.border = swing.BorderFactory.createTitledBorder("Config")

        # First row
        tmpPanel.add(swing.JCheckBox("Capitalize", False, actionPerformed=self.handleXssConfigCheckBox))
        tmpPanel.add(swing.JCheckBox("Append random chars", False, actionPerformed=self.handleXssConfigCheckBox))
        tmpPanel.add(swing.JCheckBox("Replace () with ``", False, actionPerformed=self.handleXssConfigCheckBox))
        tmpPanel.add(swing.JLabel("Add a prefix :     ", swing.SwingConstants.RIGHT))
        self.xssPrefixArea = swing.JTextField('', 15)
        tmpPanel.add(self.xssPrefixArea)
        
        # Second row
        tmpPanel.add(swing.JCheckBox("URL encode special chars", False, actionPerformed=self.handleXssConfigCheckBox))
        tmpPanel.add(swing.JCheckBox("Toggle case", False, actionPerformed=self.handleXssConfigCheckBox))
        tmpPanel.add(swing.JCheckBox("HTML encode special chars", False, actionPerformed=self.handleXssConfigCheckBox))
        tmpPanel.add(swing.JLabel("Add a suffix :     ", swing.SwingConstants.RIGHT))
        self.xssSuffixArea = swing.JTextField("", 15)
        tmpPanel.add(self.xssSuffixArea)

        # Third row
        tmpPanel.add(swing.JCheckBox("Non-standard percent encoding", False, actionPerformed=self.handleXssConfigCheckBox))
        tmpPanel.add(swing.JCheckBox("Non-standard slash encoding", False, actionPerformed=self.handleXssConfigCheckBox))
        tmpPanel.add(swing.JLabel(""))
        tmpPanel.add(swing.JLabel(""))
        tmpPanel.add(swing.JLabel(""))   
        
        firstTab.add(tmpPanel, BorderLayout.SOUTH)
        ############ END XSS TAB ############

        # Second tab 
        ############ START SQLi TAB ############
        secondTab = swing.JPanel()
        secondTab.layout = BorderLayout()
        tabbedPane.addTab("SQLi", secondTab)

        tmpGridPanel = swing.JPanel()
        tmpGridPanel.layout = GridLayout(1, 2)

        # Top of SQLi Panel
        tmpPanel = swing.JPanel()
        tmpPanel.layout = GridLayout(3, 5)
        tmpPanel.border = swing.BorderFactory.createTitledBorder("DBMS to test")
        
        # First row
        tmpPanel.add(swing.JCheckBox("MySQL", True, actionPerformed=self.handleSqliDbSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("Oracle", True, actionPerformed=self.handleSqliDbSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("PostgreSQL", True, actionPerformed=self.handleSqliDbSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("Microsoft SQL Server", True, actionPerformed=self.handleSqliDbSelectCheckBox))
        
        # Second row
        tmpPanel.add(swing.JCheckBox("Microsoft Access", False, actionPerformed=self.handleSqliDbSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("IBM DB2", False, actionPerformed=self.handleSqliDbSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("SQLite", False, actionPerformed=self.handleSqliDbSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("Firebird", False, actionPerformed=self.handleSqliDbSelectCheckBox))
        
        # Third row
        tmpPanel.add(swing.JCheckBox("Sybase", False, actionPerformed=self.handleSqliDbSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("SAP MaxDB", False, actionPerformed=self.handleSqliDbSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("HSQLDB", False, actionPerformed=self.handleSqliDbSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("Informix", False, actionPerformed=self.handleSqliDbSelectCheckBox))

        # Top of SQLi Panel
        tmpPanel1 = swing.JPanel()
        tmpPanel1.layout = GridLayout(3, 5)
        tmpPanel1.border = swing.BorderFactory.createTitledBorder("Techniques")
     
        # First row
        tmpPanel1.add(swing.JCheckBox("Boolean-based blind", True, actionPerformed=self.handleSqliTechniquesCheckBox))
        tmpPanel1.add(swing.JCheckBox("Time-based blind", True, actionPerformed=self.handleSqliTechniquesCheckBox))
        tmpPanel1.add(swing.JCheckBox("Error-based", True, actionPerformed=self.handleSqliTechniquesCheckBox))
        tmpPanel1.add(swing.JLabel(""))
        
        # Second row
        tmpPanel1.add(swing.JCheckBox("UNION query-based", True, actionPerformed=self.handleSqliTechniquesCheckBox))
        tmpPanel1.add(swing.JCheckBox("Stacked queries", True, actionPerformed=self.handleSqliTechniquesCheckBox))
        tmpPanel1.add(swing.JLabel(""))
        tmpPanel1.add(swing.JLabel(""))
        
        # Third row
        tmpPanel1.add(swing.JLabel(""))
        tmpPanel1.add(swing.JLabel(""))
        tmpPanel1.add(swing.JLabel(""))
        tmpPanel1.add(swing.JLabel(""))

        #firstTab.add(tmpPanel, BorderLayout.NORTH)
        tmpGridPanel.add(tmpPanel)
        tmpGridPanel.add(tmpPanel1)
        secondTab.add(tmpGridPanel, BorderLayout.NORTH)

        # Middle of SQLi Panel
        tmpPanel = swing.JPanel()
        tmpPanel.layout = BorderLayout()
        tmpPanel.border = swing.BorderFactory.createTitledBorder("Payloads")
        self.sqliPayloadTextArea = swing.JTextArea('', 15, 100)
        self.sqliPayloadTextArea.setLineWrap(False)
        scrollTextArea = swing.JScrollPane(self.sqliPayloadTextArea)
        tmpPanel.add(scrollTextArea)
        secondTab.add(tmpPanel, BorderLayout.CENTER)

        # Right/Middle of SQLi Panel
        tmpPanel = swing.JPanel()
        tmpPanel.layout = GridLayout(6,1)
        tmpPanel.border = swing.BorderFactory.createTitledBorder("Output options")
        tmpPanel.add(swing.JButton('Generate Payloads', actionPerformed=self.handleSqliButtonClick))
        tmpPanel.add(swing.JButton('Copy Payloads to Clipboard', actionPerformed=self.handleSqliButtonClick))
        tmpPanel.add(swing.JButton('Clear Payloads', actionPerformed=self.handleSqliButtonClick))
        tmpPanel.add(swing.JButton('Save to File', actionPerformed=self.handleSqliButtonClick))
        tmpPanel.add(swing.JButton('Poll Collaborator Server', actionPerformed=self.handleSqliButtonClick))
        tmpPanel.add(swing.JButton('TBD', actionPerformed=self.handleSqliButtonClick))
        secondTab.add(tmpPanel, BorderLayout.EAST)

        # Bottom of SQLi Panel
        tmpPanel = swing.JPanel()
        tmpPanel.layout = GridLayout(3, 5)
        tmpPanel.border = swing.BorderFactory.createTitledBorder("Config")

        # First row
        tmpPanel.add(swing.JCheckBox("Capitalize", False, actionPerformed=self.handleSqliConfigCheckBox))
        tmpPanel.add(swing.JCheckBox("Append random chars", False, actionPerformed=self.handleSqliConfigCheckBox))
        tmpPanel.add(swing.JCheckBox("Replace () with ``", False, actionPerformed=self.handleSqliConfigCheckBox))
        tmpPanel.add(swing.JLabel("Add a prefix :     ", swing.SwingConstants.RIGHT))
        self.sqliPrefixArea = swing.JTextField("", 15)
        tmpPanel.add(self.sqliPrefixArea)
        
        # Second row
        tmpPanel.add(swing.JCheckBox("URL encode special chars", False, actionPerformed=self.handleSqliConfigCheckBox))
        tmpPanel.add(swing.JCheckBox("Toggle case", False, actionPerformed=self.handleSqliConfigCheckBox))
        tmpPanel.add(swing.JCheckBox("HTML encode special chars", False, actionPerformed=self.handleSqliConfigCheckBox))
        tmpPanel.add(swing.JLabel("Add a suffix :     ", swing.SwingConstants.RIGHT))
        self.sqliSuffixArea = swing.JTextField("", 15)
        tmpPanel.add(self.sqliSuffixArea)

        # Third row
        tmpPanel.add(swing.JCheckBox("Non-standard percent encoding", False, actionPerformed=self.handleSqliConfigCheckBox))
        tmpPanel.add(swing.JCheckBox("Non-standard slash encoding", False, actionPerformed=self.handleSqliConfigCheckBox))
        tmpPanel.add(swing.JLabel(""))
        tmpPanel.add(swing.JLabel(""))
        tmpPanel.add(swing.JLabel(""))   
        
        secondTab.add(tmpPanel, BorderLayout.SOUTH)
        ############ END SQLi TAB ############

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
        tmpPanel.add(swing.JLabel(""))
        
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
        tmpPanel.add(swing.JButton('Save to File', actionPerformed=self.handleHeadersButtonClick))
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
        tmpPanel.add(swing.JLabel(""))     
        
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
        
        # Set up space for save dialogue
        self.savePanel = swing.JPanel()
        self.savePanel.setLayout(BorderLayout())
        
        self.saveArea = swing.JTextArea()
        self.saveArea.setBorder(swing.BorderFactory.createEmptyBorder(10, 10, 10, 10))

        pane = swing.JScrollPane()
        pane.getViewport().add(self.saveArea)

        self.savePanel.setBorder(swing.BorderFactory.createEmptyBorder(10, 10, 10, 10))
        self.savePanel.add(pane)
        self.add(self.savePanel)

        self.setTitle("File chooser")
        self.setSize(300, 250)
        self.setDefaultCloseOperation(swing.JFrame.EXIT_ON_CLOSE)
        self.setLocationRelativeTo(None)
        
        # Provides a place for the save box
        # no need for it to be visible on start
        self.setVisible(False)
        return

    def getTabCaption(self):
        """Return the text to be displayed on the tab"""
        return "Payload Station"
    
    def getUiComponent(self):
        """Passes the UI to burp"""
        return self.tab

    def handleXssTagsSelectCheckBox(self, event):
        """Handles checkbox clicks from the XSS menu 
        header selection to ensure only payloads for 
        specified headers are generated.
        """
        if event.source.selected:
            xssTags[event.source.text] = True
        else:
            xssTags[event.source.text] = False

    def handleXssEventCheckBox(self, event):
        """Handles checkbox clicks from the XSS evenk handler menu 
        header selection to ensure only payloads for 
        specified headers are generated.
        """
        if event.source.selected:
            xssEventHandlers[event.source.text] = True
        else:
            xssEventHandlers[event.source.text] = False

    def handleXssConfigCheckBox(self, event):
        """Handles heckbox clicks from the XSS menu config 
        selection to ensure only payloads are generated with 
        or without any specified options.
        """
        if event.source.selected:
            xssConfig[event.source.text] = True
        else:
            xssConfig[event.source.text] = False

    def handleXssButtonClick(self, event):
        """Handles button clicks from header menu."""
        buttonText = event.source.text
        if buttonText == "Generate Payloads":
            self.launchThread(self.generateXssPayloads())
        elif buttonText == "Copy Payloads to Clipboard":
            self.copyToClipboard(self.xssPayloadTextArea.text)
        elif buttonText == 'Clear Payloads':
            self.clearTextArea(self.xssPayloadTextArea)
        elif buttonText == "Save to File":
            self.launchThread(self.saveTextToFile, [self.xssPayloadTextArea])
        else:
            print buttonText

    def generateXssSamplePayload(self):
        samplePayloads = [
            "prompt({})".format(random.randint(1,1000)), 
            "confirm({})".format(random.randint(1,1000))
        ]
        return samplePayloads[random.randrange(0, 2)]

    def generateXssPayloads(self):
        """Write payloads to the XSS text area"""
        tags = [tag for tag in xssTags if xssTags[tag]]
        handlers = [handler for handler in xssEventHandlers if xssEventHandlers[handler]]
        payloads = []
        for tag in tags:
            if xssConfig['Capitalize']:
                tag = tag.upper()
            if xssConfig['Toggle case']:
                tag = capsEveryOtherChar(tag)
            if tag.lower() == 'script':
                xssSamplePayload = self.generateXssSamplePayload()
                payloads.append("<{0}>{1}</{0}>".format(tag, xssSamplePayload))
                continue
            if tag.lower() == 'math':
                payloads.append('<math href="javascript:alert(1)">CLICKME</math>')
                payloads.append('<math><maction actiontype="statusline#http://google.com" xlink:href="javascript:alert(2)">CLICKME</maction></math>')
                payloads.append('<math><maction actiontype="statusline" xlink:href="javascript:alert(3)">CLICKME<mtext>http://http://google.com</mtext></maction></math>')
                continue
            if tag.lower() == 'details':
                xssSamplePayload = self.generateXssSamplePayload()
                payloads.append('<details open ontoggle={}>'.format(xssSamplePayload))
            for handler in handlers:
                xssSamplePayload = self.generateXssSamplePayload()
                if tag.lower() == 'details':
                    payloads.append("<{} open {}={}>".format(tag, handler, xssSamplePayload))
                elif tag.lower() in ['video', 'audio', 'img']:
                    if tag.lower() in ['video', 'audio']:
                        payloads.append("<{0} controls src=0 {1}={2}></{0}>".format(tag, handler, xssSamplePayload))
                    else:
                        payloads.append("<{} src=0 {}={}>".format(tag, handler, xssSamplePayload))
                else:
                    payloads.append("<{} {}={}>".format(tag, handler, xssSamplePayload))

        if xssConfig['Replace () with ``']:
            payloads = [payload.replace('(','`').replace(')','`') for payload in payloads]
        if self.xssPrefixArea.text:
            payloads = [self.xssPrefixArea.text + payload for payload in payloads]
        if self.xssSuffixArea.text:
            payloads = [payload + self.xssSuffixArea.text for payload in payloads]
        if xssConfig['Append random chars']:
            payloads = [getRandomString(5) + payload for payload in payloads]
        if xssConfig['Non-standard percent encoding']:
            payloads = [percentNonStandardEncode(payload) for payload in payloads]
        if xssConfig['Non-standard slash encoding']:
            payloads = [slashNonStandardEncode(payload) for payload in payloads]
        if xssConfig['URL encode special chars']:
            payloads = [urlEncode(payload) for payload in payloads]
        if xssConfig['HTML encode special chars']:
            payloads = [cgi.escape(payload) for payload in payloads]

        self.xssPayloadTextArea.text = '\n'.join(payloads)
    
    def handleSqliDbSelectCheckBox(self, event):
        if event.source.selected:
            sqliDbmsToTest[event.source.text] = True
        else:
            sqliDbmsToTest[event.source.text] = False

    def handleSqliTechniquesCheckBox(self, event):
        if event.source.selected:
            sqliConfig[event.source.text] = True
        else:
            sqliConfig[event.source.text] = False

    def handleSqliConfigCheckBox(self, event):
        """Handles heckbox clicks from the XSS menu config 
        selection to ensure only payloads are generated with 
        or without any specified options.
        """
        if event.source.selected:
            xssConfig[event.source.text] = True
        else:
            xssConfig[event.source.text] = False

    def handleSqliButtonClick(self, event):
        """Handles button clicks from SQLi menu."""
        buttonText = event.source.text
        if buttonText == "Generate Payloads":
            self.launchThread(self.generateSqliPayloads())
        elif buttonText == "Copy Payloads to Clipboard":
            self.copyToClipboard(self.sqliPayloadTextArea.text)
        elif buttonText == 'Clear Payloads':
            self.clearTextArea(self.sqliPayloadTextArea)
        elif buttonText == "Poll Collaborator Server":
            self.launchThread(self.pollCollabServer())            
        elif buttonText == "Save to File":
            self.launchThread(self.saveTextToFile, [self.sqliPayloadTextArea])
        else:
            print buttonText

    def generateSqliPayloads(self):
        """Write payloads to the text area"""
        payloadData = getSqlMapPayloads()
        dbms = [db for db in sqliDbmsToTest if sqliDbmsToTest[db]]
        tests = [test for test in sqliTechniques if sqliTechniques[test]]
        sqliPayloads = []

        for payload in payloadData:
            for db in dbms:
                for test in tests:
                    if db.lower() in payload[0].lower() and test.lower() in payload[0].lower():
                        sqliPayloads.append(payload[1])

        self.sqliPayloadTextArea.text = '\n'.join(sqliPayloads)

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
            self.launchThread(self.generateHeaderPayloads())
        elif buttonText == "Copy Payloads to Clipboard":
            self.copyToClipboard(self.headerPayloadTextArea.text)
        elif buttonText == 'Clear Payloads':
            self.clearTextArea(self.headerPayloadTextArea)
        elif buttonText == "Poll Collaborator Server":
            self.launchThread(self.pollCollabServer())            
        elif buttonText == "Save to File":
            self.launchThread(self.saveTextToFile, [self.headerPayloadTextArea])
        else:
            print buttonText

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

    def copyToClipboard(self, text):
        """Copies text to clipboard"""
        toolkit = Toolkit.getDefaultToolkit()
        clipboard = toolkit.getSystemClipboard()
        clipboard.setContents(StringSelection(text), None)

    def clearTextArea(self, obj):
        """Clears the text area of a specified object"""
        obj.text = ''

    def launchThread(self, targetFunction, arguments=None):
        """Launches a thread against a specified target function"""
        if arguments:
            t = threading.Thread(target=targetFunction, args=arguments)
        else:
            t = threading.Thread(target=targetFunction)
        t.daemon = True
        t.start()

    def saveTextToFile(self, obj):
        """Save the text of an obj to a file.
        Adapted from: https://github.com/PortSwigger/wordlist-extractor/blob/master/burpList.py
        """
        fileChooser = swing.JFileChooser()
        filter = FileNameExtensionFilter("Text Files",["txt"])
        fileChooser.setFileFilter(filter)
        choice = fileChooser.showSaveDialog(self.savePanel)
        if choice == swing.JFileChooser.APPROVE_OPTION:
            file = fileChooser.getSelectedFile()
            filepath = str(file.getCanonicalPath())
            with open(filepath, 'w') as fh:
                fh.write(obj.text)


def urlEncode(string):
    """Returns a string where any reserved URL characters
    are percent encoded. 
    For example, <script> --> %3Cscript%3E"""
    return urllib.quote(string)

def percentNonStandardEncode(string):
    """Returns a string where any reserved URL characters
    are percent encoded using non standard encoding. 
    For example, <script> --> %u003Cscript%u003E"""
    urlEncString = urllib.quote(string)
    return re.sub(r'(%)([0-9a-fA-F]{2})', r'\g<1>u00\g<2>', urlEncString, flags=re.IGNORECASE)

def slashNonStandardEncode(string):
    """Returns a string where any reserved URL characters
    are percent encoded using non standard encoding. 
    For example, <script> --> %u003Cscript%u003E"""
    urlEncString = urllib.quote(string)
    nonStandardPercent = re.sub(r'(%)([0-9a-fA-F]{2})', r'\g<1>u00\g<2>', urlEncString, flags=re.IGNORECASE)
    return nonStandardPercent.replace('%', '\\')

def getRandomString(length):
    """Returns a random string of lowercase letters."""
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))

def capsEveryOtherChar(word):
    """Returns a string with every other letter
    capitalized.
    https://stackoverflow.com/questions/17865563/capitalise-every-other-letter-in-a-string-in-python
    """
    ret = ""
    i = True  # capitalize
    for char in word:
        if i:
            ret += char.upper()
        else:
            ret += char.lower()
        if char != ' ':
            i = not i
    return ret

def getSqlMapPayloads():
    """Reads in a ::: delimited file containing sqlmap payloads 
    and descriptions. Returns the data as a list of tuples.
    """
    filename = 'PayloadStationData' + os.sep + 'sqlmap_payloads-03142019.txt'
    with open(filename) as fh:
        contents = fh.read().splitlines()
    payload_data = []
    for line in contents:
        payload_data.append((line.split(':::')[0], line.split(':::')[1]))

    return sorted(payload_data, key=lambda x: x[0])

try:
    FixBurpExceptions()
except:
    pass