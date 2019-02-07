__author__ = 'Jake Miller (@LaconicWolf)'
__date__ = '20190206'
__version__ = '0.01'
__description__ = """Burp Extension that encodes, decodes, 
                  and hashes user input. Inspired by a 
                  similar tool in OWASP's ZAP.
                  """

from burp import IBurpExtender, ITab 
from javax import swing
from java.awt import BorderLayout
import sys
import base64
import urllib
import binascii
import cgi
import json
import re
import hashlib
from HTMLParser import HTMLParser

try:
    from exceptions_fix import FixBurpExceptions
except ImportError:
    pass

class BurpExtender(IBurpExtender, ITab):
    def registerExtenderCallbacks(self, callbacks):
    
        # Required for easier debugging: 
        # https://github.com/securityMB/burp-exceptions
        sys.stdout = callbacks.getStdout()

        # Keep a reference to our callbacks object
        self.callbacks = callbacks

        # Set our extension name
        self.callbacks.setExtensionName("Encode/Decode/Hash")
        
        # Create the tab
        self.tab = swing.JPanel(BorderLayout())

        # Create the text area at the top of the tab
        textPanel = swing.JPanel()
        
        # Create the label for the text area
        boxVertical = swing.Box.createVerticalBox()
        boxHorizontal = swing.Box.createHorizontalBox()
        textLabel = swing.JLabel("Text to be encoded/decoded/hashed")
        boxHorizontal.add(textLabel)
        boxVertical.add(boxHorizontal)

        # Create the text area itself
        boxHorizontal = swing.Box.createHorizontalBox()
        self.textArea = swing.JTextArea('', 6, 100)
        self.textArea.setLineWrap(True)
        boxHorizontal.add(self.textArea)
        boxVertical.add(boxHorizontal)

        # Add the text label and area to the text panel
        textPanel.add(boxVertical)

        # Add the text panel to the top of the main tab
        self.tab.add(textPanel, BorderLayout.NORTH)

        # Created a tabbed pane to go in the center of the
        # main tab, below the text area
        tabbedPane = swing.JTabbedPane()
        self.tab.add("Center", tabbedPane);

        # First tab
        firstTab = swing.JPanel()
        firstTab.layout = BorderLayout()
        tabbedPane.addTab("Encode", firstTab)

        # Button for first tab
        buttonPanel = swing.JPanel()
        buttonPanel.add(swing.JButton('Encode', actionPerformed=self.encode))
        firstTab.add(buttonPanel, "North")

        # Panel for the encoders. Each label and text field
        # will go in horizontal boxes which will then go in 
        # a vertical box
        encPanel = swing.JPanel()
        boxVertical = swing.Box.createVerticalBox()
        
        boxHorizontal = swing.Box.createHorizontalBox()
        self.b64EncField = swing.JTextField('', 75)
        boxHorizontal.add(swing.JLabel("  Base64   :"))
        boxHorizontal.add(self.b64EncField)
        boxVertical.add(boxHorizontal)

        boxHorizontal = swing.Box.createHorizontalBox()
        self.urlEncField = swing.JTextField('', 75)
        boxHorizontal.add(swing.JLabel("  URL         :"))
        boxHorizontal.add(self.urlEncField)
        boxVertical.add(boxHorizontal)

        boxHorizontal = swing.Box.createHorizontalBox()
        self.asciiHexEncField = swing.JTextField('', 75)
        boxHorizontal.add(swing.JLabel("  Ascii Hex :"))
        boxHorizontal.add(self.asciiHexEncField)
        boxVertical.add(boxHorizontal)

        boxHorizontal = swing.Box.createHorizontalBox()
        self.htmlEncField = swing.JTextField('', 75)
        boxHorizontal.add(swing.JLabel("  HTML       :"))
        boxHorizontal.add(self.htmlEncField)
        boxVertical.add(boxHorizontal)

        boxHorizontal = swing.Box.createHorizontalBox()
        self.jsEncField = swing.JTextField('', 75)
        boxHorizontal.add(swing.JLabel("  JavaScript:"))
        boxHorizontal.add(self.jsEncField)
        boxVertical.add(boxHorizontal)

        # Add the vertical box to the Encode tab
        firstTab.add(boxVertical, "Center")

        # Repeat the same process for the remaining tabs
        secondTab = swing.JPanel()
        secondTab.layout = BorderLayout()
        tabbedPane.addTab("Decode", secondTab)

        buttonPanel = swing.JPanel()
        buttonPanel.add(swing.JButton('Decode', actionPerformed=self.decode))
        secondTab.add(buttonPanel, "North")

        decPanel = swing.JPanel()
        boxVertical = swing.Box.createVerticalBox()
        
        boxHorizontal = swing.Box.createHorizontalBox()
        self.b64DecField = swing.JTextField('', 75)
        boxHorizontal.add(swing.JLabel("  Base64   :"))
        boxHorizontal.add(self.b64DecField)
        boxVertical.add(boxHorizontal)

        boxHorizontal = swing.Box.createHorizontalBox()
        self.urlDecField = swing.JTextField('', 75)
        boxHorizontal.add(swing.JLabel("  URL         :"))
        boxHorizontal.add(self.urlDecField)
        boxVertical.add(boxHorizontal)

        boxHorizontal = swing.Box.createHorizontalBox()
        self.asciiHexDecField = swing.JTextField('', 75)
        boxHorizontal.add(swing.JLabel("  Ascii Hex :"))
        boxHorizontal.add(self.asciiHexDecField)
        boxVertical.add(boxHorizontal)

        boxHorizontal = swing.Box.createHorizontalBox()
        self.htmlDecField = swing.JTextField('', 75)
        boxHorizontal.add(swing.JLabel("  HTML       :"))
        boxHorizontal.add(self.htmlDecField)
        boxVertical.add(boxHorizontal)

        boxHorizontal = swing.Box.createHorizontalBox()
        self.jsDecField = swing.JTextField('', 75)
        boxHorizontal.add(swing.JLabel("  JavaScript:"))
        boxHorizontal.add(self.jsDecField)
        boxVertical.add(boxHorizontal)

        secondTab.add(boxVertical, "Center")

        thirdTab = swing.JPanel()
        thirdTab.layout = BorderLayout()
        tabbedPane.addTab("Hash", thirdTab)

        buttonPanel = swing.JPanel()
        buttonPanel.add(swing.JButton('Hash', actionPerformed=self.generateHashes))
        thirdTab.add(buttonPanel, "North")

        decPanel = swing.JPanel()
        boxVertical = swing.Box.createVerticalBox()
        
        boxHorizontal = swing.Box.createHorizontalBox()
        self.md5Field = swing.JTextField('', 75)
        boxHorizontal.add(swing.JLabel("  MD5        :"))
        boxHorizontal.add(self.md5Field)
        boxVertical.add(boxHorizontal)

        boxHorizontal = swing.Box.createHorizontalBox()
        self.sha1Field = swing.JTextField('', 75)
        boxHorizontal.add(swing.JLabel("  SHA-1     :"))
        boxHorizontal.add(self.sha1Field)
        boxVertical.add(boxHorizontal)

        boxHorizontal = swing.Box.createHorizontalBox()
        self.sha256Field = swing.JTextField('', 75)
        boxHorizontal.add(swing.JLabel("  SHA-256 :"))
        boxHorizontal.add(self.sha256Field)
        boxVertical.add(boxHorizontal)

        boxHorizontal = swing.Box.createHorizontalBox()
        self.sha512Field = swing.JTextField('', 75)
        boxHorizontal.add(swing.JLabel("  SHA-512 :"))
        boxHorizontal.add(self.sha512Field)
        boxVertical.add(boxHorizontal)

        boxHorizontal = swing.Box.createHorizontalBox()
        self.ntlmField = swing.JTextField('', 75)
        boxHorizontal.add(swing.JLabel("  NTLM       :"))
        boxHorizontal.add(self.ntlmField)
        boxVertical.add(boxHorizontal)

        thirdTab.add(boxVertical, "Center")

        # Add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)
        return

    # Implement ITab
    def getTabCaption(self):
        """Return the text to be displayed on the tab"""
        return "Encode/Decode/Hash"
    
    def getUiComponent(self):
        """Passes the UI to burp"""
        return self.tab

    # Implement the functions from the button clicks
    def encode(self, event):
        """Encodes the user input and writes the encoded 
        value to text fields.
        """
        self.b64EncField.text = base64.b64encode(self.textArea.text)
        self.urlEncField.text = urllib.quote(self.textArea.text)
        self.asciiHexEncField.text = binascii.hexlify(self.textArea.text)
        self.htmlEncField.text = cgi.escape(self.textArea.text)
        self.jsEncField.text = json.dumps(self.textArea.text)

    def decode(self, event):
        """Decodes the user input and writes the decoded 
        value to text fields."""
        try:
            self.b64DecField.text = base64.b64decode(self.textArea.text)
        except TypeError:
            pass
        self.urlDecField.text = urllib.unquote(self.textArea.text)
        try:
            self.asciiHexDecField.text = binascii.unhexlify(self.textArea.text)
        except TypeError:
            pass
        parser = HTMLParser()
        self.htmlDecField.text = parser.unescape(self.textArea.text)
        self.jsDecField.text = re.sub(r'%u([a-fA-F0-9]{4}|[a-fA-F0-9]{2})', lambda m: chr(int(m.group(1), 16)), self.textArea.text)

    def generateHashes(self, event):
        """Hashes the user input and writes the hashed 
        value to text fields.
        """
        self.md5Field.text = hashlib.md5(self.textArea.text).hexdigest()
        self.sha1Field.text = hashlib.sha1(self.textArea.text).hexdigest()
        self.sha256Field.text = hashlib.sha256(self.textArea.text).hexdigest()
        self.sha512Field.text = hashlib.sha512(self.textArea.text).hexdigest()
        self.ntlmField.text = binascii.hexlify(hashlib.new('md4', self.textArea.text.encode('utf-16le')).digest())

try:
    FixBurpExceptions()
except:
    pass
