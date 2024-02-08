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
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.IScanIssue;
import burp.IScannerCheck;
import burp.IScannerInsertionPoint;
import burp.utility.Config;
import burp.utility.MatchChecker;
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


        issues.addAll(Check_XML_ContentType(baseRequestResponse));
        issues.addAll(Forced_Browsing(baseRequestResponse, insertionPoint));
        scannedUrls.add(url);

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

    // Forced Browsing is experimental, High chances of false positive
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

            boolean allCookiesPresent = areAllCookiesPresent(cookieHeader, headers);

            if (!allCookiesPresent) {
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
                "The application is vulnerable to Forced Browsing, allowing unauthorized access to sensitive resources. Forced Browsing occurs when an attacker navigates to URLs or directories that are not intended to be directly accessible, potentially revealing sensitive information or functionality. This vulnerability was detected during an assessment, revealing unauthorized access to sensitive resources via forced URL accessing.<br><br>The vulnerability was further confirmed by AlphaScan, which sent the updated request without session identifier and observed the same response both with and without session, indicating the absence of proper access controls.<br><br>This issue is prone to false positives, and manual verification is required.",
                "Tentative",
                "High"
            ));

            }
        }
        return issues;
    }



    private ArrayList < IScanIssue > Check_XML_ContentType(IHttpRequestResponse base_pair) {
        ArrayList < IScanIssue > issues = new ArrayList < > ();
        boolean foundContentType = false;

        IRequestInfo analysis_request = helper.analyzeRequest(base_pair);
        IResponseInfo analysis_response = helper.analyzeResponse(base_pair.getResponse());
        List < String > list_of_headers = analysis_request.getHeaders();

        int request_body_offset = analysis_request.getBodyOffset();
        byte[] request = base_pair.getRequest();
        String request_string = helper.bytesToString(request);
        String request_body = request_string.substring(request_body_offset);

        List < String > updated_headers = new ArrayList < > ();

        for (String header: list_of_headers) {
            if (header.toLowerCase().startsWith("content-type")) {
                updated_headers.add("Content-Type: application/xml");
                foundContentType = true;

            } else {
                updated_headers.add(header);
            }
        }
        if (!foundContentType) {

            return issues;
        }

        byte[] updated_http_request = helper.buildHttpMessage(updated_headers, helper.stringToBytes(request_body));

        IHttpRequestResponse updated_request_response = callbacks.makeHttpRequest(base_pair.getHttpService(), updated_http_request);

        IResponseInfo updated_analysis_response = helper.analyzeResponse(updated_request_response.getResponse());

        short updated_status_code = updated_analysis_response.getStatusCode();

        if (updated_status_code == analysis_response.getStatusCode()) {

            //MatchChecker matchChecker = new MatchChecker();
            MatchChecker matchChecker = new MatchChecker(helper);
            List < int[] > matches = matchChecker.getMatches(updated_request_response.getRequest(), helper.stringToBytes("Content-Type: application/xml"), helper);


            byte[] updated_response = updated_request_response.getResponse();
            int bodyOffset = updated_analysis_response.getBodyOffset();
            String updated_response_body = helper.bytesToString(updated_response).substring(bodyOffset);

            byte[] orignal_response = base_pair.getResponse();

            int orignal_response_body_offset = analysis_response.getBodyOffset();

            String original_response_body = helper.bytesToString(orignal_response).substring(orignal_response_body_offset);

            if (updated_response_body.length() == original_response_body.length()) {
                String vulnerability_description = "The server acknowledges support for 'application/xml' content type in the HTTP request. This indicates that the server is potentially capable of processing XML-formatted requests. Supporting 'application/xml' content type suggests that the server may interpret XML data in requests.";

                issues.add(new RaiseVuln(
                    base_pair.getHttpService(),
                    callbacks.getHelpers().analyzeRequest(base_pair).getUrl(),
                    new IHttpRequestResponse[] {
                        base_pair,
                        callbacks.applyMarkers(updated_request_response, matches, null)
                    },
                    "AlphaScan - XML Content Type Supported",
                    vulnerability_description,
                    "Tentative",
                    "Information"
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

    public boolean areAllCookiesPresent(String cookieHeader, List<String> headers) {
        if (cookieHeader == null) {
            return false;
        }
    
        // Check if "Cookie" header is present
        boolean cookieHeaderPresent = false;
        for (String header : headers) {
            if (header.trim().startsWith("Cookie:")) {
                cookieHeaderPresent = true;
                break;
            }
        }
    
        // If "Cookie" header is not present, return false
        if (!cookieHeaderPresent) {
            return false;
        }
    
        // Split the cookieHeader into individual cookies
        String[] cookies = cookieHeader.split("; ");
    
        // Get request headers
        List<String> cookieValues = new ArrayList<>();
        for (String header : headers) {
            if (header.trim().startsWith("Cookie:")) {
                String[] cookieParts = header.trim().substring(7).split(";");
                for (String cookiePart : cookieParts) {
                    cookieValues.add(cookiePart.split("=")[0].trim());
                }
                break;
            }
        }
    
        // Check if all cookie names in cookieHeader are present in the request
        for (String cookie : cookies) {
            // Extract cookie name
            String cookieName = cookie.split("=")[0].trim();
    
            // Check if the cookie name is present in the request cookie values
            boolean cookiePresent = false;
            for (String value : cookieValues) {
                if (value.equals(cookieName)) {
                    cookiePresent = true;
                    break;
                }
            }
    
            // If any cookie is not present, return false
            if (!cookiePresent) {
                return false;
            }
        }
    
        // If all cookies are present, return true
        return true;
    }
    

}
