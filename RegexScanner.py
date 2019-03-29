__author__ = 'Jake Miller (@LaconicWolf)'
__date__ = '20190215'
__version__ = '0.01'
__description__ = """\
Burp Extension that implements a passive scanner that looks
for a regular expression. 

Adapted from: https://github.com/OpenSecurityResearch/CustomPassiveScanner/blob/master/CustomPassiveScanner.py 
"""

'''
use of:
atob
eval
admin
role
document.location
document.referrer
comments
localstorage
'''

# Burp imports
from burp import IBurpExtender, IScannerCheck, IScanIssue

# Python imports
import re
from array import array

# For easier debugging, if you want.
# https://github.com/securityMB/burp-exceptions
import sys
try:
    from exceptions_fix import FixBurpExceptions
except ImportError:
    pass

class BurpExtender(IBurpExtender, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):
        
        # Required for easier debugging: 
        sys.stdout = callbacks.getStdout()

        # Keep a reference to our callbacks object
        self._callbacks = callbacks

        # Obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        # Set our extension name
        self._callbacks.setExtensionName("Regex Passive Scanner")

        # Register our extension as a custom scanner check, so Burp will use this extension
        # to perform active or passive scanning and report on scan issues returned
        self._callbacks.registerScannerCheck(self)

        return

    # This method is called when multiple issues are reported for the same URL
    # In this case we are checking if the issue detail is different, as the
    # issues from our scans include affected parameters/values in the detail,
    # which we will want to report as unique issue instances
    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if (existingIssue.getIssueDetail() == newIssue.getIssueDetail()):
            return -1
        else:
            return 0

    # Implement the doPassiveScan method of IScannerCheck interface
    # Burp Scanner invokes this method for each base request/response that is passively scanned.
    def doPassiveScan(self, baseRequestResponse):
        # Local variables used to store a list of ScanIssue objects
        scan_issues = []
        tmp_issues = []

        # Create an instance of our CustomScans object, passing the
        # base request and response, and out callbacks object
        self._CustomScans = CustomScans(baseRequestResponse, self._callbacks)

        # Call the findRegEx method of our CustomScans object to check
        # the response for anything matching a specified regular expression
        regex = r'"(/.*?)"'
        issuename = 'Regex Detected'
        issuelevel = 'Information'
        issuedetail = """The application response contains the following value
                <br><br><b>$value$</b><br><br> which matches the format of the 
                specified regex."""

        tmp_issues = self._CustomScans.findRegEx(regex, issuename, issuelevel, issuedetail)

        # Add the issues from findRegEx to the list of issues to be returned
        scan_issues = scan_issues + tmp_issues

        # Finally, per the interface contract, doPassiveScan needs to return a
        # list of scan issues, if any, and None otherwise
        if len(scan_issues) > 0:
            return scan_issues
        else:
            return None

class CustomScans:
    def __init__(self, requestResponse, callbacks):
        # Set class variables with the arguments passed to the constructor
        self._requestResponse = requestResponse
        self._callbacks = callbacks

        # Get an instance of IHelprs, which has lots of usefule methods, as a class
        # variable, so we have class-level scope to all the helper methods
        self._helpers = self._callbacks.getHelpers()

        # Put the parameters from the HTTP message in a class variable so we have class-level scope.
        self._params = self._helpers.analyzeRequest(requestResponse.getRequest()).getParameters()
        return

    # This is a custom scan method to Look for all occurrences in the response
    # that match the passed regular expression
    def findRegEx(self, regex, issuename, issuelevel, issuedetail):
        scan_issues = []
        offset = array('i', [0, 0])
        response = self._requestResponse.getResponse()
        responseLength = len(response)

        # Compile the regular expression, telling Python to ignore EOL/LF
        myre = re.compile(regex, re.DOTALL)

        # Using the regular expression, find all occurences in the base response
        match_vals = myre.findall(self._helpers.bytesToString(response))

        # For each matched value found, find its start position, so that we can create
        # the offset needed to apply appropriate markers in the resulting Scanner issue
        for ref in match_vals:
            print ref
            offsets = []
            start = self._helpers.indexOf(response, ref, True, 0, responseLength)
            offset[0] = start
            offset[1] = start + len(ref)
            offsets.append(offset)

            # Create a ScanIssue object and append it to our list of issues, marking
            # the matched value in the response.
            scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
                self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                [self._callbacks.applyMarkers(self._requestResponse, None, offsets)],
                    issuename, issuelevel, issuedetail.replace("$value$", ref)))

        return (scan_issues)

# Implementation of the IScanIssue interface with simple constructor and getter methods
class ScanIssue(IScanIssue):
    def __init__(self, httpservice, url, requestresponsearray, name, severity, detailmsg):
        self._url = url
        self._httpservice = httpservice
        self._requestresponsearray = requestresponsearray
        self._name = name
        self._severity = severity
        self._detailmsg = detailmsg

    def getUrl(self):
        return self._url

    def getHttpMessages(self):
        return self._requestresponsearray

    def getHttpService(self):
        return self._httpservice 

    def getRemediationDetail(self):
        return None

    def getIssueDetail(self):
        return self._detailmsg

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueType(self):
        return 0

    def getIssueName(self):
        return self._name

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

try:
    FixBurpExceptions()
except:
    pass