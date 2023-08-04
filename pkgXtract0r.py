#
#  PkgXtractor - Package Extractor within JS files.
#
#  Copyright (c) 2023 shk0x
#  https://github.com/shk0x/pkgXtract0r 
#

from burp import IBurpExtender, IScannerCheck, IScanIssue, ITab
from java.io import PrintWriter
from java.net import URL
from java.util import ArrayList, List
from java.util.regex import Matcher, Pattern
import binascii
import base64
import re
from javax import swing
from java.awt import Font, Color
from threading import Thread
from array import array
from java.awt import EventQueue
from java.lang import Runnable
from thread import start_new_thread
from javax.swing import JFileChooser

# Using the Runnable class for thread-safety with Swing
class Run(Runnable):
    def __init__(self, runner):
        self.runner = runner

    def run(self):
        self.runner()

# Needed params

JSExclusionList = ['jquery', 'google-analytics','gpt.js']

class BurpExtender(IBurpExtender, IScannerCheck, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("pkgXtract0r")

        callbacks.issueAlert("pkgXtract0r Passive Scanner enabled")

        stdout = PrintWriter(callbacks.getStdout(), True)
        stderr = PrintWriter(callbacks.getStderr(), True)
        callbacks.registerScannerCheck(self)
        self.initUI()
        self.callbacks.addSuiteTab(self)
        
        print ("Package eXtractor loaded.")
        print ("Copyright (c) 2023 shk0xx")
        self.outputTxtArea.setText("pkgXtract0r loaded." + "\n" + "Copyright (c) 2023 shk0x.\n")

    def initUI(self):
        self.tab = swing.JPanel()

        # UI for Output
        self.outputLabel = swing.JLabel("pkgXtract0r Log:")
        self.outputLabel.setFont(Font("Tahoma", Font.BOLD, 14))
        self.outputLabel.setForeground(Color(255,102,52))
        self.logPane = swing.JScrollPane()
        self.outputTxtArea = swing.JTextArea()
        self.outputTxtArea.setFont(Font("Consolas", Font.PLAIN, 12))
        self.outputTxtArea.setLineWrap(True)
        self.logPane.setViewportView(self.outputTxtArea)
        self.clearBtn = swing.JButton("Clear Log", actionPerformed=self.clearLog)
        self.exportBtn = swing.JButton("Export Log", actionPerformed=self.exportLog)
        self.parentFrm = swing.JFileChooser()



        # Layout
        layout = swing.GroupLayout(self.tab)
        layout.setAutoCreateGaps(True)
        layout.setAutoCreateContainerGaps(True)
        self.tab.setLayout(layout)
      
        layout.setHorizontalGroup(
            layout.createParallelGroup()
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup()
                    .addComponent(self.outputLabel)
                    .addComponent(self.logPane)
                    .addComponent(self.clearBtn)
                    .addComponent(self.exportBtn)
                )
            )
        )
        
        layout.setVerticalGroup(
            layout.createParallelGroup()
            .addGroup(layout.createParallelGroup()
                .addGroup(layout.createSequentialGroup()
                    .addComponent(self.outputLabel)
                    .addComponent(self.logPane)
                    .addComponent(self.clearBtn)
                    .addComponent(self.exportBtn)
                )
            )
        )

    def getTabCaption(self):
        return "pkgXtract0r"

    def getUiComponent(self):
        return self.tab

    def clearLog(self, event):
          self.outputTxtArea.setText("pkg xtract0r loaded.\n" )

    def exportLog(self, event):
        chooseFile = JFileChooser()
        ret = chooseFile.showDialog(self.logPane, "Choose file")
        filename = chooseFile.getSelectedFile().getCanonicalPath()
        print("\n" + "Export to : " + filename)
        open(filename, 'w', 0).write(self.outputTxtArea.text)

    
    def doPassiveScan(self, ihrr):
        try:
            urlReq = ihrr.getUrl()
            testString = str(urlReq)
            linkA = linkAnalyse(ihrr,self.helpers)
            # check if JS file
            if ".js" in str(urlReq):
                # Exclude casual JS files
                if any(x in testString for x in JSExclusionList):
                    print("\n" + "[-] URL excluded " + str(urlReq))
                else:
                    self.outputTxtArea.append("\n" + "[+] Module found: " + str(urlReq))
                    # Extract the response body
                    response = ihrr.getResponse()
                    analyzedResponse = self.helpers.analyzeResponse(response)
                    bodyOffset = analyzedResponse.getBodyOffset()
                    body = response[bodyOffset:]
                    body_string = body.tostring() # converts byte array to string
                    # Split the body into lines and check each line
                    lines = body_string.split('\n')
                    for line in lines:
                        if "node_modules/" in line:
                            self.outputTxtArea.append("\n" + "Line: " + line)
                    issueText = linkA.analyseURL()
                    for counter, issueText in enumerate(issueText):
                        self.outputTxtArea.append("\n" + "\t" + str(counter)+' - ' +issueText['link'])
                    
                    issues = ArrayList()
                    issues.add(SRI(ihrr, self.helpers))
                    return issues
        except UnicodeEncodeError:
            print ("Error in URL decode.")
        return None


    def consolidateDuplicateIssues(self, isb, isa):
        return -1

    def extensionUnloaded(self):
        print "package eXtract0r unloaded"
        return

class linkAnalyse():
    
    def __init__(self, reqres, helpers):
        self.helpers = helpers
        self.reqres = reqres
        

    regex_str = r"(node_modules)"

    def	parser_file(self, content, regex_str, mode=1, more_regex=None, no_dup=1):
        #print ("TEST parselfile #2")
        regex = re.compile(regex_str, re.VERBOSE)
        items = [{"link": m.group(0)} for m in re.finditer(regex, content)]

        if no_dup:
            # Remove duplication
            all_links = set()
            no_dup_items = []
            for item in items:
                if item["link"] not in all_links:
                    all_links.add(item["link"])
                    no_dup_items.append(item)
            items = no_dup_items

        # Match Regex
        filtered_items = []
        for item in items:
            # Remove other capture groups from regex results
            if more_regex:
                if re.search(more_regex, item["link"]):
                    #print ("TEST parselfile #3")
                    filtered_items.append(item)
            else:
                filtered_items.append(item)
        return filtered_items

    # Potential for use in the future...
    def threadAnalysis(self):
        thread = Thread(target=self.analyseURL(), args=(session,))
        thread.daemon = True
        thread.start()

    def analyseURL(self):
        
        endpoints = ""
        #print("TEST AnalyseURL #1")
        mime_type=self.helpers.analyzeResponse(self.reqres.getResponse()).getStatedMimeType()
        if mime_type.lower() == 'script':
                url = self.reqres.getUrl()
                encoded_resp=binascii.b2a_base64(self.reqres.getResponse())
                decoded_resp=base64.b64decode(encoded_resp)
                endpoints=self.parser_file(decoded_resp, self.regex_str)
                #print("TEST AnalyseURL #2")
                return endpoints
        return endpoints


class SRI(IScanIssue,ITab):
    def __init__(self, reqres, helpers):
        self.helpers = helpers
        self.reqres = reqres

    def getHost(self):
        return self.reqres.getHost()

    def getPort(self):
        return self.reqres.getPort()

    def getProtocol(self):
        return self.reqres.getProtocol()

    def getUrl(self):
        return self.reqres.getUrl()

    def getIssueName(self):
        return "pkgXtract0r Analysed JS files"

    def getIssueType(self):
        return 0x08000000  # See http:#portswigger.net/burp/help/scanner_issuetypes.html

    def getSeverity(self):
        return "Information"  # "High", "Medium", "Low", "Information" or "False positive"

    def getConfidence(self):
        return "Certain"  # "Certain", "Firm" or "Tentative"

    def getIssueBackground(self):
        return str("JS files holds links to other parts of web applications. Refer to TAB for results.")

    def getRemediationBackground(self):
        return "This is an <b>informational</b> finding only.<br>"

    def getIssueDetail(self):
        return str("Burpx Scanner has analysed the following JS file for links: <b>"
                      "%s</b><br><br>" % (self.reqres.getUrl().toString()))

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        #print ("................raising issue................")
        rra = [self.reqres]
        return rra
        
    def getHttpService(self):
        return self.reqres.getHttpService()
        
        
if __name__ in ('__main__', 'main'):
    EventQueue.invokeLater(Run(BurpExtender))