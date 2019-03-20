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
    "Capitalize": False,
    "HTML encode special chars": False,
    "Append random chars": False,
    "Non-standard percent encoding": False,
    "Non-standard slash encoding": False,
    "Close tags": False
}

# Copy of default settings so can eventually reset to default

xssTagsDefault = xssTags
xssEventHandlersDefault = xssEventHandlers 
xssConfigDefault = xssConfig

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

sqliDbmsToTestDefault = sqliDbmsToTest
sqliTechniquesDefault = sqliTechniques
sqliConfigDefault = sqliConfig

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

headerTests = {
    "Random string reflection": False,
    "Error Invoking Characters": False,
    "Random long strings": False,
    "Out-of-band": False,
    "Path Traversal": False,
    "OS Injection": False
}

headersToTestDefault = headersToTest
headerTestsDefault = headerTests

shellLangToTest = {
    "NetCat": False,
    "Perl": False,
    "Python": False,
    "/dev/tcp": False,
    "Bash": False,
    "Java": False,
    "PHP": False,
    "Ruby": False,
    "PowerShell": False,
    "AWK": False,
    "Lua": False,
    "NodeJS": False,
    "Groovy": False,
    "ASP": False 
}

shellTypes = {
    "One-liner WebShell": False,
    "Full WebShell": False,
    "Reverse": False,
    "Bind": False,
}

shellConfig = {
    "URL encode special chars": False,
    "Toggle case": False,
    "Lower case": False,
    "Non-standard percent encoding": False,
    "Non-standard slash encoding": False
}

shellLangToTestDefault = shellLangToTest
shellTypesDefault = shellTypes
shellConfigDefault = shellConfig

otherVulnToTest = {
    "OS Injection": False,
    "Path Traversal": False,
    "XXE": False,
    "LDAP Injection": False,
}

otherTbd = {
    "TBD": False,
    "TBD": False,
    "TBD": False,
    "TBD": False,
}

otherConfig = {
    "URL encode special chars": False,
    "Toggle case": False,
    "Lower case": False,
    "Non-standard percent encoding": False,
    "Non-standard slash encoding": False
}

otherVulnToTestDefault = otherVulnToTest
otherTbdDefault = otherTbd
otherConfigDefault = otherConfig


# Interact with Burp. Required
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
        tmpPanel.add(swing.JCheckBox("TBD", False, actionPerformed=self.handleSqliConfigCheckBox))
        tmpPanel.add(swing.JLabel("Add a prefix :     ", swing.SwingConstants.RIGHT))
        self.sqliPrefixArea = swing.JTextField("", 15)
        tmpPanel.add(self.sqliPrefixArea)
        
        # Second row
        tmpPanel.add(swing.JCheckBox("URL encode special chars", False, actionPerformed=self.handleSqliConfigCheckBox))
        tmpPanel.add(swing.JCheckBox("TBD", False, actionPerformed=self.handleSqliConfigCheckBox))
        tmpPanel.add(swing.JCheckBox("TBD", False, actionPerformed=self.handleSqliConfigCheckBox))
        tmpPanel.add(swing.JLabel("Add a suffix :     ", swing.SwingConstants.RIGHT))
        self.sqliSuffixArea = swing.JTextField("", 15)
        tmpPanel.add(self.sqliSuffixArea)

        # Third row
        tmpPanel.add(swing.JCheckBox("Non-standard percent encoding", False, actionPerformed=self.handleSqliConfigCheckBox))
        tmpPanel.add(swing.JCheckBox("Non-standard slash encoding", False, actionPerformed=self.handleSqliConfigCheckBox))
        tmpPanel.add(swing.JCheckBox("TBD", False, actionPerformed=self.handleSqliConfigCheckBox))
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
        tmpPanel1.add(swing.JCheckBox("Error Invoking Characters", False, actionPerformed=self.handleHeadersConfigCheckBox))
        tmpPanel1.add(swing.JCheckBox("Random string reflection", False, actionPerformed=self.handleHeadersConfigCheckBox))
        tmpPanel1.add(swing.JLabel("Custom header value:  ", swing.SwingConstants.RIGHT))
        self.headersCustomValue1Area = swing.JTextField("", 15)  
        tmpPanel1.add(self.headersCustomValue1Area)
        
        # Second row
        tmpPanel1.add(swing.JCheckBox("Path Traversal", False, actionPerformed=self.handleHeadersConfigCheckBox))
        tmpPanel1.add(swing.JCheckBox("Random long strings", False, actionPerformed=self.handleHeadersConfigCheckBox))
        tmpPanel1.add(swing.JLabel("Custom header value:  ", swing.SwingConstants.RIGHT))
        self.headersCustomValue2Area = swing.JTextField("", 15)  
        tmpPanel1.add(self.headersCustomValue2Area)
        
        # Third row
        tmpPanel1.add(swing.JCheckBox("Out-of-band", False, actionPerformed=self.handleHeadersConfigCheckBox))
        tmpPanel1.add(swing.JCheckBox("OS Injection", False, actionPerformed=self.handleHeadersConfigCheckBox))
        tmpPanel1.add(swing.JLabel("Callback server address:  ", swing.SwingConstants.RIGHT))
        self.headersCallbackAddressArea = swing.JTextField("", 15)  
        tmpPanel1.add(self.headersCallbackAddressArea)

        tmpGridPanel.add(tmpPanel)
        tmpGridPanel.add(tmpPanel1)
        
        thirdTab.add(tmpGridPanel, BorderLayout.SOUTH)
        ############ END HEADERS TAB ############

        # Fourth tab
        ############ START SHELLS TAB ############
        fourthTab = swing.JPanel()
        fourthTab.layout = BorderLayout()
        tabbedPane.addTab("Shells", fourthTab)

        tmpGridPanel = swing.JPanel()
        tmpGridPanel.layout = GridLayout(1, 2)

        # Top of Shell Panel
        tmpPanel = swing.JPanel()
        tmpPanel.layout = GridLayout(3, 5)
        tmpPanel.border = swing.BorderFactory.createTitledBorder("Language/Tool")
        
        # First row
        tmpPanel.add(swing.JCheckBox("NetCat", False, actionPerformed=self.handleShellLangSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("Perl", False, actionPerformed=self.handleShellLangSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("Python", False, actionPerformed=self.handleShellLangSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("/dev/tcp", False, actionPerformed=self.handleShellLangSelectCheckBox))
        
        # Second row
        tmpPanel.add(swing.JCheckBox("Bash", False, actionPerformed=self.handleShellLangSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("Java", False, actionPerformed=self.handleShellLangSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("PHP", False, actionPerformed=self.handleShellLangSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("Ruby", False, actionPerformed=self.handleShellLangSelectCheckBox))
        
        # Third row
        tmpPanel.add(swing.JCheckBox("PowerShell", False, actionPerformed=self.handleShellLangSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("AWK", False, actionPerformed=self.handleShellLangSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("Lua", False, actionPerformed=self.handleShellLangSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("NodeJS", False, actionPerformed=self.handleShellLangSelectCheckBox))

        # Fourth row
        tmpPanel.add(swing.JCheckBox("Groovy", False, actionPerformed=self.handleShellLangSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("ASP", False, actionPerformed=self.handleShellLangSelectCheckBox))
        tmpPanel.add(swing.JLabel(""))
        tmpPanel.add(swing.JLabel(""))

        # Top of Shell Panel
        tmpPanel1 = swing.JPanel()
        tmpPanel1.layout = GridLayout(3, 5)
        tmpPanel1.border = swing.BorderFactory.createTitledBorder("Type")
     
        # First row
        tmpPanel1.add(swing.JCheckBox("One-liner WebShell", False, actionPerformed=self.handleShellTypeCheckBox))
        tmpPanel1.add(swing.JCheckBox("Full WebShell", False, actionPerformed=self.handleShellTypeCheckBox))
        tmpPanel1.add(swing.JLabel(""))
        tmpPanel1.add(swing.JLabel(""))
        tmpPanel1.add(swing.JLabel(""))
        
        # Second row
        tmpPanel1.add(swing.JCheckBox("Reverse", False, actionPerformed=self.handleShellTypeCheckBox))
        tmpPanel1.add(swing.JCheckBox("Bind", False, actionPerformed=self.handleShellTypeCheckBox))
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
        fourthTab.add(tmpGridPanel, BorderLayout.NORTH)

        # Middle of Shell Panel
        tmpPanel = swing.JPanel()
        tmpPanel.layout = BorderLayout()
        tmpPanel.border = swing.BorderFactory.createTitledBorder("Payloads")
        self.shellPayloadTextArea = swing.JTextArea('', 15, 100)
        self.shellPayloadTextArea.setLineWrap(False)
        scrollTextArea = swing.JScrollPane(self.shellPayloadTextArea)
        tmpPanel.add(scrollTextArea)
        fourthTab.add(tmpPanel, BorderLayout.CENTER)

        # Right/Middle of Shell Panel
        tmpPanel = swing.JPanel()
        tmpPanel.layout = GridLayout(6,1)
        tmpPanel.border = swing.BorderFactory.createTitledBorder("Output options")
        tmpPanel.add(swing.JButton('Generate Payloads', actionPerformed=self.handleShellButtonClick))
        tmpPanel.add(swing.JButton('Copy Payloads to Clipboard', actionPerformed=self.handleShellButtonClick))
        tmpPanel.add(swing.JButton('Clear Payloads', actionPerformed=self.handleShellButtonClick))
        tmpPanel.add(swing.JButton('Save to File', actionPerformed=self.handleShellButtonClick))
        tmpPanel.add(swing.JButton('Poll Collaborator Server', actionPerformed=self.handleShellButtonClick))
        tmpPanel.add(swing.JLabel(""))
        fourthTab.add(tmpPanel, BorderLayout.EAST)

        # Bottom of Shell Panel
        tmpPanel = swing.JPanel()
        tmpPanel.layout = GridLayout(3, 5)
        tmpPanel.border = swing.BorderFactory.createTitledBorder("Config")

        # First row
        tmpPanel.add(swing.JCheckBox("Lower case", False, actionPerformed=self.handleShellConfigCheckBox))
        tmpPanel.add(swing.JCheckBox("Toggle case", False, actionPerformed=self.handleShellConfigCheckBox))
        tmpPanel.add(swing.JCheckBox("TBD", False, actionPerformed=self.handleShellConfigCheckBox))
        tmpPanel.add(swing.JLabel("Callback server address :     ", swing.SwingConstants.RIGHT))
        self.shellCallbackAddressArea = swing.JTextField("", 15)  
        tmpPanel.add(self.shellCallbackAddressArea)
        
        # Second row
        tmpPanel.add(swing.JCheckBox("URL encode special chars", False, actionPerformed=self.handleShellConfigCheckBox))
        tmpPanel.add(swing.JCheckBox("TBD", False, actionPerformed=self.handleShellConfigCheckBox))
        tmpPanel.add(swing.JCheckBox("TBD", False, actionPerformed=self.handleShellConfigCheckBox))
        tmpPanel.add(swing.JLabel(""))
        tmpPanel.add(swing.JLabel(""))

        # Third row
        tmpPanel.add(swing.JCheckBox("Non-standard percent encoding", False, actionPerformed=self.handleShellConfigCheckBox))
        tmpPanel.add(swing.JCheckBox("Non-standard slash encoding", False, actionPerformed=self.handleShellConfigCheckBox))
        tmpPanel.add(swing.JCheckBox("TBD", False, actionPerformed=self.handleShellConfigCheckBox))
        tmpPanel.add(swing.JLabel(""))
        tmpPanel.add(swing.JLabel(""))

        fourthTab.add(tmpPanel, BorderLayout.SOUTH)
        ############ END SHELLS TAB ############

        # Fifth tab
        ############ OTHER PAYLOADS TAB #############
        fifthTab = swing.JPanel()
        fifthTab.layout = BorderLayout()
        tabbedPane.addTab("Other", fifthTab)

        tmpGridPanel = swing.JPanel()
        tmpGridPanel.layout = GridLayout(1, 2)

        # Top of Other Panel
        tmpPanel = swing.JPanel()
        tmpPanel.layout = GridLayout(3, 5)
        tmpPanel.border = swing.BorderFactory.createTitledBorder("Vulnerability")
        
        # First row
        tmpPanel.add(swing.JCheckBox("OS Injection", False, actionPerformed=self.handleOtherVulnSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("XXE", False, actionPerformed=self.handleOtherVulnSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("Path Traversal", False, actionPerformed=self.handleOtherVulnSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("LDAP Injection", False, actionPerformed=self.handleOtherVulnSelectCheckBox))
        
        # Second row
        tmpPanel.add(swing.JCheckBox("TBD", False, actionPerformed=self.handleOtherVulnSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("TBD", False, actionPerformed=self.handleOtherVulnSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("TBD", False, actionPerformed=self.handleOtherVulnSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("TBD", False, actionPerformed=self.handleOtherVulnSelectCheckBox))
        
        # Third row
        tmpPanel.add(swing.JCheckBox("TBD", False, actionPerformed=self.handleOtherVulnSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("TBD", False, actionPerformed=self.handleOtherVulnSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("TBD", False, actionPerformed=self.handleOtherVulnSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("TBD", False, actionPerformed=self.handleOtherVulnSelectCheckBox))

        # Fourth row
        tmpPanel.add(swing.JCheckBox("TBD", False, actionPerformed=self.handleOtherVulnSelectCheckBox))
        tmpPanel.add(swing.JCheckBox("TBD", False, actionPerformed=self.handleOtherVulnSelectCheckBox))
        tmpPanel1.add(swing.JLabel(""))
        tmpPanel1.add(swing.JLabel(""))

        # Top of Other Panel
        tmpPanel1 = swing.JPanel()
        tmpPanel1.layout = GridLayout(3, 5)
        tmpPanel1.border = swing.BorderFactory.createTitledBorder("TBD")
     
        # First row
        tmpPanel1.add(swing.JCheckBox("TBD", False, actionPerformed=self.handleOtherTbdSelectCheckBox))
        tmpPanel1.add(swing.JCheckBox("TBD", False, actionPerformed=self.handleOtherTbdSelectCheckBox))
        tmpPanel1.add(swing.JLabel(""))
        tmpPanel1.add(swing.JLabel(""))
        
        # Second row
        tmpPanel1.add(swing.JCheckBox("TBD", False, actionPerformed=self.handleOtherTbdSelectCheckBox))
        tmpPanel1.add(swing.JCheckBox("TBD", False, actionPerformed=self.handleOtherTbdSelectCheckBox))
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
        fifthTab.add(tmpGridPanel, BorderLayout.NORTH)

        # Middle of Other Panel
        tmpPanel = swing.JPanel()
        tmpPanel.layout = BorderLayout()
        tmpPanel.border = swing.BorderFactory.createTitledBorder("Payloads")
        self.otherPayloadTextArea = swing.JTextArea('', 15, 100)
        self.otherPayloadTextArea.setLineWrap(False)
        scrollTextArea = swing.JScrollPane(self.otherPayloadTextArea)
        tmpPanel.add(scrollTextArea)
        fifthTab.add(tmpPanel, BorderLayout.CENTER)

        # Right/Middle of Other Panel
        tmpPanel = swing.JPanel()
        tmpPanel.layout = GridLayout(6,1)
        tmpPanel.border = swing.BorderFactory.createTitledBorder("Output options")
        tmpPanel.add(swing.JButton('Generate Payloads', actionPerformed=self.handleOtherButtonClick))
        tmpPanel.add(swing.JButton('Copy Payloads to Clipboard', actionPerformed=self.handleOtherButtonClick))
        tmpPanel.add(swing.JButton('Clear Payloads', actionPerformed=self.handleOtherButtonClick))
        tmpPanel.add(swing.JButton('Save to File', actionPerformed=self.handleOtherButtonClick))
        tmpPanel.add(swing.JButton('Poll Collaborator Server', actionPerformed=self.handleOtherButtonClick))
        tmpPanel.add(swing.JLabel(""))
        fifthTab.add(tmpPanel, BorderLayout.EAST)

        # Bottom of Other Panel
        tmpPanel = swing.JPanel()
        tmpPanel.layout = GridLayout(3, 5)
        tmpPanel.border = swing.BorderFactory.createTitledBorder("Config")

        # First row
        tmpPanel.add(swing.JCheckBox("Lower case", False, actionPerformed=self.handleOtherConfigCheckBox))
        tmpPanel.add(swing.JCheckBox("Toggle case", False, actionPerformed=self.handleOtherConfigCheckBox))
        tmpPanel.add(swing.JCheckBox("TBD", False, actionPerformed=self.handleOtherConfigCheckBox))
        tmpPanel.add(swing.JLabel("Callback server address :     ", swing.SwingConstants.RIGHT))
        self.shellCallbackAddressArea = swing.JTextField("", 15)  
        tmpPanel.add(self.shellCallbackAddressArea)
        
        # Second row
        tmpPanel.add(swing.JCheckBox("URL encode special chars", False, actionPerformed=self.handleOtherConfigCheckBox))
        tmpPanel.add(swing.JCheckBox("TBD", False, actionPerformed=self.handleOtherConfigCheckBox))
        tmpPanel.add(swing.JCheckBox("TBD", False, actionPerformed=self.handleOtherConfigCheckBox))
        tmpPanel.add(swing.JLabel(""))
        tmpPanel.add(swing.JLabel(""))

        # Third row
        tmpPanel.add(swing.JCheckBox("Non-standard percent encoding", False, actionPerformed=self.handleOtherConfigCheckBox))
        tmpPanel.add(swing.JCheckBox("Non-standard slash encoding", False, actionPerformed=self.handleOtherConfigCheckBox))
        tmpPanel.add(swing.JCheckBox("TBD", False, actionPerformed=self.handleOtherConfigCheckBox))
        tmpPanel.add(swing.JLabel(""))
        tmpPanel.add(swing.JLabel(""))

        fifthTab.add(tmpPanel, BorderLayout.SOUTH)

        ############ END OTHER PAYLOAD TAB #############


        ######### PLACE HOLDER FOR SIXTH TAB #############
        ######### PLACE HOLDER FOR SIXTH TAB #############


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
        return "Payload Station"
    
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
            if xssConfig['Capitalize']:
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
                            payloads.append("<{} src={3} {}={}>".format(tag, handler, xssSamplePayload, random.randint(1,1000)))
                else:
                    if xssConfig['Close tags']:
                        payloads.append("<{0} {1}={2}>{3}</{0}>".format(tag, handler, xssSamplePayload, self.xssTagTextArea.text))
                    else:
                        payloads.append("<{} {}={}>{3}".format(tag, handler, xssSamplePayload, self.xssTagTextArea.text))

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
                if test == "Path Traversal":
                    payloads += [header + ': ' + pathPayload for pathPayload in PATH_TRAVERSAL_PAYLOADS]
                if test == "OS Injection":
                    payloads += [header + ': ' + osIPayload for osIPayload in OS_INJECTION_PAYLOADS]
            if self.headersCustomValue1Area.text:
                payloads.append(header + ': ' + self.headersCustomValue1Area.text)
            if self.headersCustomValue2Area.text:
                payloads.append(header + ': ' + self.headersCustomValue2Area.text)
            if header == "Authorization":
                payloads.append(header + ': Basic dGVzdHVzZXI6dGVzdHBhc3N3b3Jk')
                payloads.append(header + ': Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c')
                payloads.append(header + ': Digest username="Mufasa"')
        self.headerPayloadTextArea.text = '\n'.join(payloads)

    def handleShellLangSelectCheckBox(self, event):
        """Handles clicks in the Shell 
        """
        if event.source.selected:
            shellLangToTest[event.source.text] = True
        else:
            shellLangToTest[event.source.text] = False

    def handleShellTypeCheckBox(self, event):
        if event.source.selected:
            shellTypes[event.source.text] = True
        else:
            shellTypes[event.source.text] = False

    def handleShellConfigCheckBox(self, event):
        """Handles checkbox clicks from the Shell menu config 
        selection to ensure only payloads are generated with 
        or without any specified options.
        """
        if event.source.selected:
            shellConfig[event.source.text] = True
        else:
            shellConfig[event.source.text] = False

    def handleShellButtonClick(self, event):
        """Handles button clicks from Shell menu."""
        buttonText = event.source.text
        if buttonText == "Generate Payloads":
            self.launchThread(self.generateShellPayloads())
        elif buttonText == "Copy Payloads to Clipboard":
            self.copyToClipboard(self.shellPayloadTextArea.text)
        elif buttonText == 'Clear Payloads':
            self.clearTextArea(self.shellPayloadTextArea)
        elif buttonText == "Poll Collaborator Server":
            self.launchThread(self.pollCollabServer())            
        elif buttonText == "Save to File":
            self.launchThread(self.saveTextToFile, [self.shellPayloadTextArea])
        else:
            print buttonText

    def generateShellPayloads(self):
        print "Generating shell Payloads"

    def handleOtherVulnSelectCheckBox(self, event):
        """Handles Other tab vulnerability box."""
        if event.source.selected:
            otherVulnToTest[event.source.text] = True
        else:
            otherVulnToTest[event.source.text] = False

    def handleOtherTbdSelectCheckBox(self, event):
        """Handles Other tab TBD check boxes."""
        if event.source.selected:
            otherTbd[event.source.text] = True
        else:
            otherTbd[event.source.text] = False

    def handleOtherConfigCheckBox(self, event):
        """Handles checkbox clicks from the Other menu config 
        selection to ensure only payloads are generated with 
        or without any specified options.
        """
        if event.source.selected:
            otherConfig[event.source.text] = True
        else:
            otherConfig[event.source.text] = False

    def handleOtherButtonClick(self, event):
        """Handles button clicks from Other menu."""
        buttonText = event.source.text
        if buttonText == "Generate Payloads":
            self.launchThread(self.generateShellPayloads())
        elif buttonText == "Copy Payloads to Clipboard":
            self.copyToClipboard(self.otherPayloadTextArea.text)
        elif buttonText == 'Clear Payloads':
            self.clearTextArea(self.otherPayloadTextArea)
        elif buttonText == "Poll Collaborator Server":
            self.launchThread(self.pollCollabServer())            
        elif buttonText == "Save to File":
            self.launchThread(self.saveTextToFile, [self.otherPayloadTextArea])
        else:
            print buttonText

    def generateOtherPayloads(self):
        """Generates various payloads."""
        print "Generating other Payloads"

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
            print dir(self.collab)
            print len(self.collab)
            print
            print 11111
            for collab in self.collab:    
                interactions = collab.fetchAllCollaboratorInteractions()
                print len(interactions)
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

    def resetToDefault(self, obj):
        """Resets tab to default."""
        # TODO
        pass

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


PATH_TRAVERSAL_PAYLOADS = [
    '../../../../../etc/passwd',
    '..\\..\\..\\..\\..\\c:\\windows.ini'
]

OS_INJECTION_PAYLOADS = [
    'dir',
    'ping -c 5 127.0.0.1'
]