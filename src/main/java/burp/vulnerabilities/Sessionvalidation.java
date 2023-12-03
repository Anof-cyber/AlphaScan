package burp.vulnerabilities;

import java.util.List;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;

public class Sessionvalidation {
    
    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;
    enum AuthMethod {
        HEADER,
        COOKIE,
        NONE
    }

    public void processRequest(IHttpRequestResponse messages) {
        // Handle each IHttpRequestResponse object in the messages array
        AuthMethod authMethod = cookieHandler(messages);
        switch (authMethod) {
            case HEADER:
                // Handle authentication using headers
                //handleHeaderAuthentication(messages);
                break;
            case COOKIE:
                // Handle authentication using cookies
                //handleCookieAuthentication(messages);
                break;
            case NONE:
                // No authentication needed
                //handleNoAuthentication(messages);
                break;
            default:
                // Handle default case (if necessary)
                break;
        }

          
        }
    

    public AuthMethod cookieHandler(IHttpRequestResponse message) {
        IRequestInfo analyzedRequest = helpers.analyzeRequest(message);
        List<String> listOfHeaders = analyzedRequest.getHeaders();
    
        boolean isHeaderBasedAuth = containsAPISessionHeader(listOfHeaders);
        if (isHeaderBasedAuth) {
            return AuthMethod.HEADER;
        } else {
            boolean isCookie = check_cookie(listOfHeaders);
            if (isCookie) {
                return AuthMethod.COOKIE;
            } else {
                callbacks.issueAlert("No Authentication Session Header Or Cookie Found");
                return AuthMethod.NONE;
            }
        }
    }


    public boolean containsAPISessionHeader(List<String> headers) {
    for (String header : headers) {
        // Check if the header name matches certain patterns
        if (header.startsWith("API:") || 
            header.toLowerCase().startsWith("authorization") || 
            header.toLowerCase().startsWith("x-api-key")) {
            return true; // Return true if any of the specified headers are found
            }
        }
    return false; // Return false if none of the specified headers are found
    }


    public boolean check_cookie(List<String> headers) {

        for (String header : headers) {

            if (header.startsWith("Cookie")) {

                return true;
            }
            
        }
        return false;
    }

}
