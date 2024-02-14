package burp.vulnerabilities;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.utility.Config;
import burp.utility.CookieUtils;
import burp.utility.MatchChecker;
import burp.utility.RaiseVuln;

public class ForcedBrowsing {
    private static final List<String> DISALLOWED_EXTENSIONS = Arrays.asList(".js", ".css", ".jpg", ".jpeg", ".png", ".gif", ".svg");



    // Forced Browsing is experimental, High chances of false positive
    public static ArrayList < IScanIssue > forced_browsing(IHttpRequestResponse base_pair, IBurpExtenderCallbacks callbacks, IExtensionHelpers helper) {

        ArrayList < IScanIssue > issues = new ArrayList < > ();

        String cookieHeader = Config.getConfigValue("CookieHeader");
        String authHeader = Config.getConfigValue("AuthHeader");
        if (cookieHeader != null) {
            issues.addAll(Cookie_Forced_Browsing(base_pair,cookieHeader,callbacks,helper));
        }
        else if (authHeader != null) {
            issues.addAll(Token_Forced_Browsing(base_pair,authHeader,callbacks,helper));
        }
        return issues;



    }


    
    public static ArrayList <IScanIssue > Token_Forced_Browsing(IHttpRequestResponse base_pair, String authHeader,IBurpExtenderCallbacks callbacks, IExtensionHelpers helper) {
        ArrayList < IScanIssue > issues = new ArrayList < > ();
        Short orignal_status = helper.analyzeResponse(base_pair.getResponse()).getStatusCode();
        List<String> headers = helper.analyzeRequest(base_pair.getRequest()).getHeaders();
        int bodyOffset = helper.analyzeRequest(base_pair.getRequest()).getBodyOffset();
        byte[] request = base_pair.getRequest();
        String request_string = helper.bytesToString(request);
        String request_body = request_string.substring(bodyOffset);
        URL requestUrl = helper.analyzeRequest(base_pair).getUrl();
        String headerNameAuthHeader = authHeader.split(":")[0].trim();
        List<String> duplicate_headers = helper.analyzeRequest(base_pair.getRequest()).getHeaders();
        boolean headerExists = false;
        

        if (isStaticResource(requestUrl)) {
            return issues;
        }

        if (!orignal_status.equals((short) 200) && !orignal_status.equals((short) 201)) {
            return issues;
        }

        for (String header : headers) {
            if (header.trim().toLowerCase().startsWith(headerNameAuthHeader.toLowerCase() + ":")) {
                
                headerExists = true;
                duplicate_headers.remove(header);
                break; 
            }
        }

        if (!headerExists) {
            return issues;
        }

        duplicate_headers.add("Scanner: AlphaScan");
        byte[] modifiedRequest = helper.buildHttpMessage(duplicate_headers, helper.stringToBytes(request_body));
        IHttpRequestResponse modifiedMessage = callbacks.makeHttpRequest(base_pair.getHttpService(), modifiedRequest);
        Short modified_status_code = helper.analyzeResponse(modifiedMessage.getResponse()).getStatusCode();

        if (orignal_status.equals(modified_status_code)) {
            MatchChecker matchChecker = new MatchChecker(helper);
            List < int[] > matches = matchChecker.getMatches(modifiedMessage.getResponse(), modified_status_code.toString().getBytes(StandardCharsets.UTF_8), helper);
                            

            issues.add(new RaiseVuln(
            base_pair.getHttpService(),
            callbacks.getHelpers().analyzeRequest(base_pair).getUrl(),
            new IHttpRequestResponse[] {
                base_pair,
                callbacks.applyMarkers(modifiedMessage, null, matches)
            },
            "AlphaScan - Forced Browsing",
            "The application is vulnerable to Forced Browsing, allowing unauthorized access to sensitive resources. Forced Browsing occurs when an attacker navigates to URLs or directories that are not intended to be directly accessible, potentially revealing sensitive information or functionality. This vulnerability was detected during an assessment, revealing unauthorized access to sensitive resources via forced URL accessing.<br><br>The vulnerability was further confirmed by AlphaScan, which sent the updated request without session identifier and observed the same response both with and without session, indicating the absence of proper access controls.<br><br>This issue is prone to false positives, and manual verification is required.",
            "Tentative",
            "High"
        ));

        }


        return issues;

    }



    public static ArrayList <IScanIssue > Cookie_Forced_Browsing(IHttpRequestResponse base_pair, String cookieHeader,IBurpExtenderCallbacks callbacks, IExtensionHelpers helper) {
        ArrayList < IScanIssue > issues = new ArrayList < > ();

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

            List<String> updated_headers = CookieUtils.areAllCookiesPresent(cookieHeader, headers);

            if (updated_headers.isEmpty()) {
                return issues;
            }

            //headers.removeIf(header -> header.toLowerCase().startsWith("cookie:"));
            updated_headers.add("Scanner: AlphaScan");

            byte[] modifiedRequest = helper.buildHttpMessage(updated_headers, helper.stringToBytes(request_body));
            IHttpRequestResponse modifiedMessage = callbacks.makeHttpRequest(base_pair.getHttpService(), modifiedRequest);
            Short modified_status_code = helper.analyzeResponse(modifiedMessage.getResponse()).getStatusCode();

            if (orignal_status.equals(modified_status_code)) {

                MatchChecker matchChecker = new MatchChecker(helper);
                List < int[] > matches = matchChecker.getMatches(modifiedMessage.getResponse(), modified_status_code.toString().getBytes(StandardCharsets.UTF_8), helper);

                issues.add(new RaiseVuln(
                base_pair.getHttpService(),
                callbacks.getHelpers().analyzeRequest(base_pair).getUrl(),
                new IHttpRequestResponse[] {
                    base_pair,
                    callbacks.applyMarkers(modifiedMessage, null, matches)
                },
                "AlphaScan - Forced Browsing",
                "The application is vulnerable to Forced Browsing, allowing unauthorized access to sensitive resources. Forced Browsing occurs when an attacker navigates to URLs or directories that are not intended to be directly accessible, potentially revealing sensitive information or functionality. This vulnerability was detected during an assessment, revealing unauthorized access to sensitive resources via forced URL accessing.<br><br>The vulnerability was further confirmed by AlphaScan, which sent the updated request without session identifier and observed the same response both with and without session, indicating the absence of proper access controls.<br><br>This issue is prone to false positives, and manual verification is required.",
                "Tentative",
                "High"
            ));

            }


        return issues;

    }


    public static boolean isStaticResource(URL requestUrl) {
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
