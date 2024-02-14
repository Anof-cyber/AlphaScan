package burp.vulnerabilities;

import java.util.ArrayList;
import java.util.List;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.utility.Config;
import burp.utility.RaiseVuln;

public class HeaderIssues {


    public static ArrayList < IScanIssue > Check_Http_Only(IHttpRequestResponse base_pair,IBurpExtenderCallbacks callbacks, IExtensionHelpers helper) {
        ArrayList < IScanIssue > issues = new ArrayList<>();

        String cookieHeader = Config.getConfigValue("CookieHeader");
        List < String > response_headers = helper.analyzeResponse(base_pair.getResponse()).getHeaders(); 

        // Extract the names of cookies from the cookieHeader
        List<String> cookieNames = extractCookieNames(cookieHeader);

        // Check if Set-Cookie header is present in the response headers
        List<String> setCookieHeaders = getSetCookieHeaders(response_headers);


        for (String setCookieHeader : setCookieHeaders) {
            // Extract cookie names from the Set-Cookie header
            List<String> setCookieNames = extractCookieNames(setCookieHeader);
            
            // Check if any of the cookie names from cookieHeader match with those in the Set-Cookie header
            for (String cookieName : cookieNames) {
                if (setCookieNames.contains(cookieName)) {
                    // Check if the cookie has the HTTP-only flag set
                    if (!isAttributePresent(setCookieHeader, cookieName,"HttpOnly")) {
                        // Raise issue if HTTP-only flag is not set
                        issues.add(new RaiseVuln(
                                    base_pair.getHttpService(),
                                    callbacks.getHelpers().analyzeRequest(base_pair).getUrl(),
                                    new IHttpRequestResponse[] { base_pair },
                                    "AlphaScan - Missing HTTP-only Flag",
                                    "The cookie '" + cookieName + "' does not have the HTTP-only flag set.",
                                    "Certain",
                                    "Information"
                                ));
                    }
                }
            }
        }
        return issues;
    }


    public static ArrayList < IScanIssue > Check_Secure(IHttpRequestResponse base_pair,IBurpExtenderCallbacks callbacks, IExtensionHelpers helper) {
        ArrayList < IScanIssue > issues = new ArrayList<>();

        String cookieHeader = Config.getConfigValue("CookieHeader");
        List < String > response_headers = helper.analyzeResponse(base_pair.getResponse()).getHeaders(); 

        // Extract the names of cookies from the cookieHeader
        List<String> cookieNames = extractCookieNames(cookieHeader);

        // Check if Set-Cookie header is present in the response headers
        List<String> setCookieHeaders = getSetCookieHeaders(response_headers);


        for (String setCookieHeader : setCookieHeaders) {
            // Extract cookie names from the Set-Cookie header
            List<String> setCookieNames = extractCookieNames(setCookieHeader);
            
            // Check if any of the cookie names from cookieHeader match with those in the Set-Cookie header
            for (String cookieName : cookieNames) {
                if (setCookieNames.contains(cookieName)) {
                    // Check if the cookie has the Secure flag set
                    if (!isAttributePresent(setCookieHeader, cookieName,"Secure")) {
                        // Raise issue if Secure flag is not set
                        issues.add(new RaiseVuln(
                                    base_pair.getHttpService(),
                                    callbacks.getHelpers().analyzeRequest(base_pair).getUrl(),
                                    new IHttpRequestResponse[] { base_pair },
                                    "AlphaScan - Missing Secure Flag",
                                    "The cookie '" + cookieName + "' does not have the Secure flag set.",
                                    "Certain",
                                    "Information"
                                ));
                    }
                }
            }
        }
        return issues;
    }


    public static ArrayList < IScanIssue > Check_CSP(IHttpRequestResponse base_pair,IBurpExtenderCallbacks callbacks, IExtensionHelpers helper) {
        ArrayList < IScanIssue > issues = new ArrayList < > ();
        List < String > response_headers = helper.analyzeResponse(base_pair.getResponse()).getHeaders();

        String csp_header = null;

        for (String header: response_headers) {
            if (header.toLowerCase().startsWith("content-security-policy")) {
                csp_header = header.split(": ", 2)[1];
                break;
            }
        }

        if (csp_header != null) {
            String[] required_directives = {
                "script-src 'self'",
                "default-src 'self'",
                "object-src 'none'",
                "frame-ancestors 'self'",
                "base-uri 'self'"
            };
            String[] prohibited_directives = {
                "unsafe-inline",
                "unsafe-eval",
                "data:",
                "allow"
            };
            List < String > missing_directives = new ArrayList < > ();
            List < String > prohibited_present = new ArrayList < > ();

            for (String directive: required_directives) {
                if (!csp_header.contains(directive)) {
                    missing_directives.add(directive);
                }
            }

            for (String directive: prohibited_directives) {
                if (csp_header.contains(directive)) {
                    prohibited_present.add(directive);
                }
            }

            if (!missing_directives.isEmpty()) {
                String missing_directives_str = String.join(", ", missing_directives);
                issues.add(new RaiseVuln(
                    base_pair.getHttpService(),
                    callbacks.getHelpers().analyzeRequest(base_pair).getUrl(),
                    new IHttpRequestResponse[] {
                        base_pair
                    },
                    "AlphaScan - CSP Header Missing Required Directives",
                    "The CSP Header does not include the following required directives: <br><b>" + missing_directives_str + "</b>",
                    "Certain",
                    "Information"
                ));
            }

            if (!prohibited_present.isEmpty()) {
                String prohibited_directives_str = String.join(", ", prohibited_present);
                issues.add(new RaiseVuln(
                    base_pair.getHttpService(),
                    callbacks.getHelpers().analyzeRequest(base_pair).getUrl(),
                    new IHttpRequestResponse[] {
                        base_pair
                    },
                    "AlphaScan - CSP Header Contains Insecure Directives",
                    "The CSP Header includes insecure directives: <br><b>" + prohibited_directives_str + "</b>",
                    "Certain",
                    "Information"
                ));
            }
        } else {
            issues.add(new RaiseVuln(
                base_pair.getHttpService(),
                callbacks.getHelpers().analyzeRequest(base_pair).getUrl(),
                new IHttpRequestResponse[] {
                    base_pair
                },
                "AlphaScan - Missing CSP Header",
                "<b>The CSP Header is missing</b>",
                "Certain",
                "Information"
            ));

        }
        return issues;
    }


    public static ArrayList < IScanIssue > Check_HSTS(IHttpRequestResponse base_pair,IBurpExtenderCallbacks callbacks, IExtensionHelpers helper) {
        ArrayList < IScanIssue > issues = new ArrayList < > ();
        List < String > response_headers = helper.analyzeResponse(base_pair.getResponse()).getHeaders();

        for (String header: response_headers) {
            if (!header.toLowerCase().startsWith("strict-transport-security")) {

                issues.add(new RaiseVuln(
                    base_pair.getHttpService(),
                    callbacks.getHelpers().analyzeRequest(base_pair).getUrl(),
                    new IHttpRequestResponse[] {
                        base_pair
                    },
                    "AlphaScan - Missing Strict-Transport-Security Header",
                    "The Strict-Transport-Security (HSTS) header is missing. HSTS ensures that the browser always communicates over HTTPS, mitigating risks associated with downgrade attacks and enhancing overall security.",
                    "Certain",
                    "Information"
                ));

            }
        }
        return issues;
    }

    public static ArrayList < IScanIssue > Check_Xframe(IHttpRequestResponse base_pair,IBurpExtenderCallbacks callbacks, IExtensionHelpers helper) {
        ArrayList < IScanIssue > issues = new ArrayList < > ();
        List < String > response_headers = helper.analyzeResponse(base_pair.getResponse()).getHeaders();

        for (String header: response_headers) {
            if (!header.toLowerCase().startsWith("x-frame-options")) {

                issues.add(new RaiseVuln(
                    base_pair.getHttpService(),
                    callbacks.getHelpers().analyzeRequest(base_pair).getUrl(),
                    new IHttpRequestResponse[] {
                        base_pair
                    },
                    "AlphaScan - Missing X-Frame-Options",
                    "The X-Frame-Options header is missing. This header is essential for preventing Clickjacking attacks by restricting the rendering of the page in a <frame>, <iframe>, <embed>, or <object>.",
                    "Certain",
                    "Information"
                ));

            }
        }
        return issues;
    }





    public static List<String> extractCookieNames(String cookieHeader) {
        List<String> cookieNames = new ArrayList<>();
        if (cookieHeader != null && !cookieHeader.isEmpty()) {
            String[] cookies = cookieHeader.split("; ");
            for (String cookie : cookies) {
                String name = cookie.split("=")[0].trim();
                cookieNames.add(name);
            }
        }
        return cookieNames;
    }

    // get all set cookie headers
    public static List<String> getSetCookieHeaders(List<String> responseHeaders) {
        List<String> setCookieHeaders = new ArrayList<>();
        for (String header : responseHeaders) {
            if (header.trim().startsWith("Set-Cookie:")) {
                setCookieHeaders.add(header.trim());
            }
        }
        return setCookieHeaders;
    }


    public static boolean isAttributePresent(String setCookieHeader, String cookieName, String attributeName) {
        // Extract the specified attribute for the specified cookie
        String[] cookieParts = setCookieHeader.split("; ");
        for (String part : cookieParts) {
            if (part.trim().startsWith(cookieName) && part.trim().contains(attributeName)) {
                return true;
            }
        }
        return false;
    }
    
}
