#!/usr/bin/env python


__author__ = 'Jake Miller (@LaconicWolf), with some concepts taken from https://github.com/PortSwigger/nmap-parser/blob/master/NmapParser.py'
__date__ = '20180811'
__version__ = '0.01'
__description__ = '''Creates a new Burp tab to upload a file containing
                  URLs (separated by newlines) which are then requested
                  within Burp and added to the Sitemap if a response is 
                  received.
                  '''


from burp import IBurpExtender               # Required for all extensions
from burp import ITab                        # Used to create new tab in the UI
from java.net import URL                     # Transforms URL into Java URL required by Burp extension
from javax import Swing                      # Used to build UI in the tab
from exceptions_fix import FixBurpExceptions # Used to make the error messages easier to debug
import sys                                   # Used to write exceptions for exceptions_fix.py debugging
import os                                    # Used to check the file path
import threading                             # Used to launch new thread for making http requests


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
        """Launches a separate thread and calls the _addToSitemap function"""

        def _addToSitemap(filePath):
            """Opens a file and reads in URLs, passing them to a function that
            normalized them into proto://address:port format. The URLs are then
            passed to the Burp API and requested within Burp, populating the sitemap
            if the request is successful."""
            try:
                urls = open(self._fileLocation).read().splitlines()
            except Exception as e:
                print('An error occurred: ', e)
                return
            normalizedUrls = self.normalizeUrls(urls)
            for url in normalizedUrls:
                jUrl = URL(url)
                newRequest = self._helpers.buildHttpRequest(jUrl)
                port = int(url.split(':')[-1])
                try:
                    requestResponse = self._callbacks.makeHttpRequest(
                        self._helpers.buildHttpService(str(jUrl.getHost()), port, str(jUrl.getProtocol()) == "https"), newRequest
                        )
                    if not requestResponse.getResponse() == None:
                        self._callbacks.addToSiteMap(requestResponse)
                except Exception as e:
                    print(e)

        # Start a thread to run the above nested function
        # Without launching function in a new thread, the following exception occurs:
        # java.lang.RuntimeException: java.lang.RuntimeException: 
        # Extensions should not make HTTP requests in the Swing event dispatch thread
        t = threading.Thread(target=_addToSitemap, args=[self._fileLocation])
        t.daemon = True 
        t.start()

    def normalizeUrls(self, urls):
        """Accepts a list of urls and formats them so they will be accepted.
        Returns a new list of the processed urls.
        """
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
                        url = url.strip('/')
                        urlList.append('http://' + url + ':80')
                        urlList.append('https://' + url + ':443')
                        continue
                else:
                        url = url.strip()
                        url = url.strip('/')
                        urlList.append('http://' + url + ':80')
                        urlList.append('https://' + url + ':443')
                        continue
            if len(url.split(':')) != 3:
                if url[0:5] != 'https':    
                    url = url.strip()
                    url = url.strip('/')
                    urlList.append(url + ':80')
                    continue
                elif url[0:5] == 'https':
                    url = url.strip()
                    url = url.strip('/')
                    urlList.append(url + ':443')
                    continue
            url = url.strip()
            url = url.strip('/')
            urlList.append(url)
        return urlList
