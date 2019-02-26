__author__ = 'Jake Miller (@LaconicWolf)'
__date__ = '20190226'
__version__ = '0.01'
__description__ = """\
Burp Extension that extracts the filenames from URLs in 
scope or from a selected host. Just right click on the 
hosts pane in the sitemap and click 'Generate forced
browsing wordlist' for either selected items or all hosts
in scope. The output will appear in the extender tab, where 
you can set configure the extension to output to the system console,
save to a file, or show in the UI.
"""

# Burp imports
from burp import IBurpExtender, IContextMenuFactory

# Jython specific imports for the GUI
from java.util import ArrayList
from javax.swing import JMenuItem

# stdlib
import sys
import threading

# For easier debugging, if you want.
# https://github.com/securityMB/burp-exceptions
try:
    from exceptions_fix import FixBurpExceptions
except ImportError:
    pass

class BurpExtender(IBurpExtender, IContextMenuFactory):
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
        
        # Need to perform method in new thread to
        # prevent the GUI from locking up while the 
        # work is being done.
        t = threading.Thread(target=self.createWordlist)
        t.daemon = True
        t.start()

    def createWordlistFromScope(self, event):
        """Calls the createWordlist method and sets self.fromScope=True
        which creates a wordlist from the hosts in scope.
        """
        self.fromScope = True

        # Need to perform method in new thread to
        # prevent the GUI from locking up while the 
        # work is being done.
        t = threading.Thread(target=self.createWordlist)
        t.daemon = True
        t.start()

    def createWordlist(self):
        """Gathers a list of urls from the specified host,
        and analyzes and creates a wordlist.
        """
        httpTraffic = self.context.getSelectedMessages()

        urllist = []
        self.filenamelist = []
        hostUrls = []
    
        for traffic in httpTraffic:
            try:
                hostUrls.append(str(traffic.getUrl()))
            except UnicodeEncodeError:
                continue

        # The argument to sitemap should be able to take a URL prefix,
        # and only return info from that host, but I couldn't get it
        # to work. 'None' returns the whole sitemap, and I filter later.
        siteMapData = self.callbacks.getSiteMap(None)
        for entry in siteMapData:
            requestInfo = self.helpers.analyzeRequest(entry)
            url = requestInfo.getUrl()
            try:
                decodedUrl = self.helpers.urlDecode(str(url))
            except Exception as e:
                continue

            # Append the URLs to the list if they are in scope
            # or just from a selected host.
            if self.fromScope and self.callbacks.isInScope(url):
                urllist.append(decodedUrl)
            else:
                for url in hostUrls:
                    if decodedUrl.startswith(str(url)):
                        urllist.append(decodedUrl)
        
        # Get the filename and remove the querystring if any
        for entry in urllist:
            self.filenamelist.append(entry.split('/')[-1].split('?')[0])

        # Writes wordlist to the Extender Tab
        for word in sorted(set(self.filenamelist)):
            if word:
                try:
                    print word
                except UnicodeEncodeError:
                    continue        
try:
    FixBurpExceptions()
except:
    pass