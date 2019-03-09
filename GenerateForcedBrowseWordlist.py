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

Blog post explaining all the code in detail:
https://laconicwolf.com/2019/03/09/burp-extension-python-tutorial-generate-a-forced-browsing-wordlist/
"""

from burp import IBurpExtender, IContextMenuFactory
from java.util import ArrayList
from javax.swing import JMenuItem
import threading
import sys
try:
    from exceptions_fix import FixBurpExceptions
except ImportError:
    pass

class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        
        sys.stdout = callbacks.getStdout()
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.callbacks.setExtensionName("Forced Browsing Wordlist Generator")
        callbacks.registerContextMenuFactory(self)
        
        return

    def createMenuItems(self, invocation):
        self.context = invocation
        menuList = ArrayList()
        menuItem = JMenuItem("Generate forced browsing wordlist from selected items",
                              actionPerformed=self.createWordlistFromSelected)
        menuList.add(menuItem)
        menuItem = JMenuItem("Generate forced browsing wordlist from all hosts in scope",
                              actionPerformed=self.createWordlistFromScope)
        menuList.add(menuItem)
        return menuList

    def createWordlistFromSelected(self, event):
        self.fromScope = False
        t = threading.Thread(target=self.createWordlist)
        t.daemon = True
        t.start()

    def createWordlistFromScope(self, event):
        self.fromScope = True
        t = threading.Thread(target=self.createWordlist)
        t.daemon = True
        t.start()

    def createWordlist(self):
        httpTraffic = self.context.getSelectedMessages()        
        hostUrls = []
        for traffic in httpTraffic:
            try:
                hostUrls.append(str(traffic.getUrl()))
            except UnicodeEncodeError:
                continue

        urllist = []
        siteMapData = self.callbacks.getSiteMap(None)
        for entry in siteMapData:
            requestInfo = self.helpers.analyzeRequest(entry)
            url = requestInfo.getUrl()
            try:
                decodedUrl = self.helpers.urlDecode(str(url))
            except Exception as e:
                continue

            if self.fromScope and self.callbacks.isInScope(url):
                urllist.append(decodedUrl)
            else:
                for url in hostUrls:
                    if decodedUrl.startswith(str(url)):
                        urllist.append(decodedUrl)
        
        filenamelist = []
        for entry in urllist:
            filenamelist.append(entry.split('/')[-1].split('?')[0])

        for word in sorted(set(filenamelist)):
            if word:
                try:
                    print word
                except UnicodeEncodeError:
                    continue        
try:
    FixBurpExceptions()
except:
    pass
