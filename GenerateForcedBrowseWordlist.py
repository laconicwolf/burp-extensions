__author__ = 'Jake Miller (@LaconicWolf)'
__date__ = '20190226'
__version__ = '0.01'
__description__ = """\
Burp Extension that extracts the filenames from URLs in 
scope or from a selected host. Just right click on the 
hosts pane in the sitemap and click 'Generate forced
browsing wordlist' for either selected items or all hosts
in scope. A prompt will appear that will let you save to a file.

Several concepts and code snippets taken from:
https://github.com/PortSwigger/wordlist-extractor/blob/master/burpList.py
"""

# Burp imports
from burp import IBurpExtender, IContextMenuFactory

# Jython specific imports for the GUI
from java.awt import BorderLayout
from java.util import List, ArrayList
from javax.swing.filechooser import FileNameExtensionFilter
from javax.swing import JPanel
from javax.swing import BorderFactory
from javax.swing import JScrollPane
from javax.swing import JFrame
from javax.swing import JTextArea
from javax.swing import JMenuItem
from javax.swing import JFileChooser

# stdlib
import sys

# For easier debugging, if you want.
# https://github.com/securityMB/burp-exceptions
try:
    from exceptions_fix import FixBurpExceptions
except ImportError:
    pass

class BurpExtender(IBurpExtender, IContextMenuFactory, JFrame):
    def registerExtenderCallbacks(self, callbacks):
        
        # Required for easier debugging: 
        sys.stdout = callbacks.getStdout()

        # Keep a reference to our callbacks object
        self.callbacks = callbacks

        # Obtain an extension helpers object
        self.helpers = callbacks.getHelpers()

        # Set our extension name
        self.callbacks.setExtensionName("Forced Browsing Wordlist Generator")

        # Create a context menu
        callbacks.registerContextMenuFactory(self)
        
        # Setup space for save dialogue to sit in.
        self.panel = JPanel()
        self.panel.setLayout(BorderLayout())

        self.area = JTextArea()
        self.area.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))

        pane = JScrollPane()
        pane.getViewport().add(self.area)

        self.panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        self.panel.add(pane)
        self.add(self.panel)

        self.setTitle("File chooser")
        self.setSize(300, 250)
        self.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE)
        self.setLocationRelativeTo(None)

        # This is just providing a place where the save box can sit in, 
        # so no need for it to be visible on start
        self.setVisible(False)
        
        return

    # Implement IContextMenuFactory
    def createMenuItems(self, invocation):
        """Adds the extension to the context menu that 
        appears when you right-click an object.
        """
        self.context = invocation

        # Must return a Java list 
        menuList = ArrayList()
        menuItem = JMenuItem("Generate forced browsing wordlist from selected items",
                                    actionPerformed=self.createWordlistFromSelected)
        menuList.add(menuItem)
        menuItem = JMenuItem("Generate forced browsing wordlist from all hosts in scope",
                                    actionPerformed=self.createWordlistFromScope)
        menuList.add(menuItem)
        return menuList

    def createWordlistFromSelected(self, event):
        """Calls the createWordlist method, which creates
        a wordlist from the host selected in the context menu.
        """
        self.fromScope = False
        self.createWordlist()

    def createWordlistFromScope(self, event):
        """Calls the createWordlist method and sets self.fromScope=True
        which creates a wordlist from the hosts in scope.
        """
        self.fromScope = True
        self.createWordlist()

    def createWordlist(self):
        """Gathers a list of urls from the specified host,
        and analyzes and creates a wordlist.
        """
        httpTraffic = self.context.getSelectedMessages()

        urllist = []
        self.filenamelist = []
    
        for traffic in httpTraffic:
            hostUrl = str(traffic.getUrl())

        # The argument to sitemap should be able to take a URL prefix,
        # and only return info from that host, but I couldn't get it
        # to work. 'None' returns the whole sitemap, and I filter later
        siteMapData = self.callbacks.getSiteMap(None)
        for entry in siteMapData:
            requestInfo = self.helpers.analyzeRequest(entry)
            url = requestInfo.getUrl()
            try:
                decodedUrl = self.helpers.urlDecode(str(url))
            except:
                continue

            # Append the URLs to the list if they are in scope
            # or just from a selected host.
            if self.fromScope and self.callbacks.isInScope(url):
                urllist.append(decodedUrl)
            else:
                if hostUrl in decodedUrl:
                    urllist.append(decodedUrl)
        
        # Get the filename and remove the querystring if any
        for entry in urllist:
            self.filenamelist.append(entry.split('/')[-1].split('?')[0])

        # Write the items to a file
        self.writeToFile()

    def writeToFile(self):
        """Writes the file wordlist to file."""
        fileChooser = JFileChooser()

        # Shows only text files in the save menu prompt
        filter = FileNameExtensionFilter("Text Files",["txt"])
        fileChooser.setFileFilter(filter)

        ret = fileChooser.showSaveDialog(self.panel)
        
        # If they have selected the save option
        if ret == JFileChooser.APPROVE_OPTION:
            file = fileChooser.getSelectedFile()
            
            # Get the path that the user selected
            filepath = str(file.getCanonicalPath())

            with open(filepath, 'a+') as fh:
                for word in sorted(set(self.filenamelist)):
                    if word:
                        fh.write(word +'\n')

            print '[+] Wordlist created at {}'.format(filepath)
        
try:
    FixBurpExceptions()
except:
    pass