package burp;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

import burp.utility.Config;
import burp.utility.CookieUtils;
import burp.vulnerabilities.CriticalIssues;
import burp.vulnerabilities.HostIssues;
import burp.vulnerabilities.RequestIssues;
//import burp.vulnerabilities.SSTI;

/**
 *
 * @author AnoF
 */
public class BurpExtender implements IBurpExtender {
    private HostIssues HostScanner;
    private CriticalIssues criticalIssuesScanner;
    private RequestIssues requestbasedscanner;
    //private SSTI sstiIssuesScanner;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;
    private ConfigTab configTab;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        callbacks.setExtensionName("AlphaScan");
        callbacks.printOutput("Author: Sourav Kalal");
        callbacks.printOutput("Version 0.1");
        callbacks.printOutput("https://github.com/Anof-cyber/AlphaScan");
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
        helpers = callbacks.getHelpers();
        Config.setConfigValue("ChromeDriverPath", null);
        Config.setConfigValue("IsXSS", String.valueOf(false));

        HostScanner = new HostIssues(callbacks, helpers);
        criticalIssuesScanner = new CriticalIssues(callbacks, helpers);
        requestbasedscanner = new RequestIssues(callbacks,helpers);
        //sstiIssuesScanner = new SSTI(callbacks, helpers);

        // Register scanner checks
        callbacks.registerScannerCheck(HostScanner);
        callbacks.registerScannerCheck(criticalIssuesScanner);
        callbacks.registerScannerCheck(requestbasedscanner);
        //callbacks.registerScannerCheck(sstiIssuesScanner);
        callbacks.registerContextMenuFactory(new Menueditor(callbacks));
        String chromeDriverPath = callbacks.loadExtensionSetting("ChromeDriverPath");
        if (chromeDriverPath != null && !chromeDriverPath.isEmpty()) {
            Config.setConfigValue("ChromeDriverPath", chromeDriverPath); // Store in Config class
        }

        configTab = new ConfigTab(callbacks);

        // Add the custom tab to Burp UI
        callbacks.addSuiteTab(new ITab() {
            @Override
            public String getTabCaption() {
                return "AlphaScan";
            }

            @Override
            public java.awt.Component getUiComponent() {
                return configTab; // Display ConfigTab in the Burp UI
            }
        });


        /* No Longer required 
        /// Remove Session Cookie added my macro for forced browsing
        callbacks.registerHttpListener(new IHttpListener() {
            
            @Override
            public void processHttpMessage(int toolFlag,
            boolean messageIsRequest,
            IHttpRequestResponse messageInfo) {
                if (messageIsRequest) {
                    String cookieHeader = Config.getConfigValue("CookieHeader");
                    List<String> headers = helpers.analyzeRequest(messageInfo.getRequest()).getHeaders();
                    IRequestInfo analyzedRequest = helpers.analyzeRequest(messageInfo);
                    int request_body_offset = analyzedRequest.getBodyOffset();
                    byte[] request = messageInfo.getRequest();
                    String request_string = helpers.bytesToString(request);
                    String request_body = request_string.substring(request_body_offset);
                    
                    // If header as Scanner header, remove the cookies again incase added by macro
                    if (headers.contains("Scanner")) {
                        List<String> updated_headers = CookieUtils.areAllCookiesPresent(cookieHeader, headers);

                        if (!updated_headers.isEmpty()) {

                            updated_headers.remove("Scanner");
                            byte[] modifiedRequest = helpers.buildHttpMessage(updated_headers, helpers.stringToBytes(request_body));
                            messageInfo.setRequest(modifiedRequest);
                        }      
                    }
                }
            }
        });
        */
    }
    
}