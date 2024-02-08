package burp.vulnerabilities;

import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.IScannerCheck;
import burp.IScannerInsertionPoint;
import burp.utility.Config;
import burp.utility.RaiseVuln;

public class RequestIssues implements IScannerCheck {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helper;
    private static final List<String> DISALLOWED_EXTENSIONS = Arrays.asList(".js", ".css", ".jpg", ".jpeg", ".png", ".gif", ".svg");
    private Set<String> scannedHosts = new HashSet<>();


     public RequestIssues(IBurpExtenderCallbacks callbacks, IExtensionHelpers helper) {
        this.callbacks = callbacks;
        this.helper = helper;
    }


    @Override
    public List < IScanIssue > doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        ArrayList < IScanIssue > issues = new ArrayList < > ();

        return issues;
    }


     @Override
    public List < IScanIssue > doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        ArrayList < IScanIssue > issues = new ArrayList < > ();
        Set<String> scannedUrls = new HashSet<>();
        String url = helper.analyzeRequest(baseRequestResponse).getUrl().toString();
        if (scannedUrls.contains(url)) {
            return issues; // Skip scanning if URL has already been scanned
        }


        
        issues.addAll(Forced_Browsing(baseRequestResponse, insertionPoint));

        return issues;
    }


    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {

        if (existingIssue.getIssueName().equals(newIssue.getIssueName())) {
            return 1;

        } else {
            return 0;
        }
    }

    // Forced Browsing is experimental
    private ArrayList < IScanIssue > Forced_Browsing(IHttpRequestResponse base_pair, IScannerInsertionPoint insertionPoint) {

        ArrayList < IScanIssue > issues = new ArrayList < > ();

        String cookieHeader = Config.getConfigValue("CookieHeader");
        callbacks.printOutput(cookieHeader);
        if (cookieHeader != null) {
            Short orignal_status = helper.analyzeResponse(base_pair.getResponse()).getStatusCode();
            List<String> headers = helper.analyzeRequest(base_pair.getRequest()).getHeaders();
            int bodyOffset = helper.analyzeRequest(base_pair.getRequest()).getBodyOffset();
            byte[] request = base_pair.getRequest();
            String request_string = helper.bytesToString(request);
            String request_body = request_string.substring(bodyOffset);
            URL requestUrl = helper.analyzeRequest(base_pair).getUrl();
            


            if (isStaticResource(requestUrl)) {
                return issues;
            }
            if (!orignal_status.equals((short) 200) && !orignal_status.equals((short) 201)) {
                return issues;
            }


            headers.removeIf(header -> header.toLowerCase().startsWith("cookie:"));
            headers.add("Scanner: AlphaScan");

            byte[] modifiedRequest = helper.buildHttpMessage(headers, helper.stringToBytes(request_body));
            IHttpRequestResponse modifiedMessage = callbacks.makeHttpRequest(base_pair.getHttpService(), modifiedRequest);
            Short modified_status_code = helper.analyzeResponse(modifiedMessage.getResponse()).getStatusCode();

            if (orignal_status.equals(modified_status_code)) {

                issues.add(new RaiseVuln(
                base_pair.getHttpService(),
                callbacks.getHelpers().analyzeRequest(base_pair).getUrl(),
                new IHttpRequestResponse[] {
                    base_pair
                    //callbacks.applyMarkers(updated_request_response, requestHighlights, matches)
                },
                "AlphaScan - Forced Browsing",
                "The application is vulnerable to Forced Browsing, allowing unauthorized access to sensitive resources. Forced Browsing occurs when an attacker navigates to URLs or directories that are not intended to be directly accessible, potentially revealing sensitive information or functionality. This vulnerability was detected during an assessment, revealing unauthorized access to sensitive resources via forced URL manipulation.<br><br>The vulnerability was further confirmed by AlphaScan, which sent the updated request without session identifier and observed the same response both with and without session, indicating the absence of proper access controls.<br><br>This issue is prone to false positives, and manual verification is required.",
                "Tentative",
                "High"
            ));

            }
        }


        return issues;


    }

    public boolean isStaticResource(URL requestUrl) {
        // Check if the request URL contains any disallowed file extension
        String path = requestUrl.getPath();
        for (String extension : DISALLOWED_EXTENSIONS) {
            if (path.toLowerCase().endsWith(extension)) {
                return true; // Request is for a static resource
            }
        }
        return false; // Request is not for a static resource
    }

}
