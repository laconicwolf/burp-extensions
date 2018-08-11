
__author__ = 'Jake Miller (@LaconicWolf)'
__date__ = '20180322'
__version__ = '0.01'
__description__ = '''Creates a new Burp tab to upload a file containing
                     URLs which are added to the SiteMap.
                  '''


from burp import IBurpExtender               # Required for all extensions
from burp import ITab
from java.net import URL
from java.awt import Dimension
from javax import swing
from exceptions_fix import FixBurpExceptions # Used to make the error messages easier to debug
import sys                                   # Used to write exceptions for exceptions_fix.py debugging
import os
from java.lang import Runnable


# for debugging. https://github.com/securityMB/burp-exceptions
try:
    from exceptions_fix import FixBurpExceptions
except:
    pass


class BurpExtender(IBurpExtender, ITab):
    """Implements IBurpExtender"""
    def registerExtenderCallbacks(self, callbacks):
        # required for debugger: https://github.com/securityMB/burp-exceptions
        sys.stdout = callbacks.getStdout()
        
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # set our extension name
        callbacks.setExtensionName("Site Map Loader")

        # Build UI
        self._jPanel = swing.JPanel()
        boxVertical = swing.Box.createVerticalBox()
        boxHorizontal = swing.Box.createHorizontalBox()

        # Buid the file upload button
        getFileButton = swing.JButton('Select URL File', actionPerformed=self.getFile)
        self._fileText = swing.JTextArea("", 1, 50)
        boxHorizontal.add(getFileButton)
        boxHorizontal.add(self._fileText)

        # Buid the 'add to Site map button'
        addToSitemapButton = swing.JButton('Add URLs to Site Map',actionPerformed=self.addToSitemap)
        boxHorizontal.add(addToSitemapButton)

        boxVertical.add(boxHorizontal)
        boxHorizontal = swing.Box.createHorizontalBox()

        # Create the GUI tab structure
        self._jPanel.add(boxVertical)
        
        # Add a new tab to BurpSuite
        self._callbacks.addSuiteTab(self)
        return

    # Implement ITab
    def getTabCaption(self):
        return 'Site Map Loader'

    def getUiComponent(self):
        return self._jPanel

    def getFile(self, button):
        """Implements the functionality that allows a user to choose a
        file from the file system. 
        """
        chooser = swing.JFileChooser()
        c = chooser.showOpenDialog(None)
        if chooser is not None:
            if (chooser.currentDirectory and chooser.selectedFile.name) is not None:
                self._fileLocation = str(chooser.currentDirectory) + os.sep + str(chooser.selectedFile.name)
                self._fileText.setText(self._fileLocation)
            else:
                self._fileText.setText("File Not Valid, Try Again")

    def addToSitemap(self, button):
        """Need a docstring"""
        try:
            urls = open(self._fileLocation).read().splitlines()
        except Exception as e:
            print('An error occurred: ', e)
            return
        normalizedUrls = self.normalizeUrls(urls)
        for url in normalizedUrls:
            jUrl = URL(url)
            request = self._helpers.buildHttpRequest(jUrl)
            try:
                requestResponse = self._callbacks.makeHttpRequest(
                    self._helpers.buildHttpService(
                        str(uUrl.getHost()), int(list[1]), str(uUrl.getProtocol()) == "https"), newRequest)

    def normalizeUrls(self, urls):
        """Accepts a list of urls and formats them so they will be accepted.
        Returns a new list of the processed urls."""
        
        urlList = []
        httpPortList = ['80', '280', '81', '591', '593', '2080', '2480', '3080', 
                      '4080', '4567', '5080', '5104', '5800', '6080',
                      '7001', '7080', '7777', '8000', '8008', '8042', '8080',
                      '8081', '8082', '8088', '8180', '8222', '8280', '8281',
                      '8530', '8887', '9000', '9080', '9090', '16080']                    
        httpsPortList = ['832', '981', '1311', '7002', '7021', '7023', '7025',
                       '7777', '8333', '8531', '8888']
        for url in urls:
            if '*.' in url:
                url.replace('*.', '')
            if not url.startswith('http'):
                if ':' in url:
                    port = url.split(':')[-1]
                    if port in httpPortList:
                        urlList.append('http://' + url)
                    elif port in httpsPortList or port.endswith('43'):
                        urlList.append('https://' + url)
                    else:
                        url = url.strip()
                        url = url.strip('/') + '/'
                        urlList.append('http://' + url)
                        urlList.append('https://' + url)
                        continue
                else:
                        url = url.strip()
                        url = url.strip('/') + '/'
                        urlList.append('http://' + url)
                        urlList.append('https://' + url)
                        continue
            url = url.strip()
            url = url.strip('/') + '/'
            urlList.append(url)
        return urlList