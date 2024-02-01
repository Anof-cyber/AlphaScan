package burp.vulnerabilities;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.swing.SwingWorker;

import java.nio.charset.StandardCharsets;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;

import burp.utility.RaiseVuln;
import burp.utility.MatchChecker;

public class Sessionvalidation {

    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;
    
    public Sessionvalidation(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        this.callbacks = callbacks;
        this.helpers = helpers;
    }

 

    enum AuthMethod {
        HEADER,
        COOKIE,
        NONE
    }
    

    public void processRequest(IHttpRequestResponse messages) {
        this.callbacks = callbacks;
        this.helpers = helpers;
        // Handle each IHttpRequestResponse object in the messages array
        AuthMethod authMethod = cookieHandler(messages);
        switch (authMethod) {
            case HEADER:
                // Handle authentication using headers
                // handleHeaderAuthentication(messages);
                
                break;
            case COOKIE:
               // validate_cookie(IHttpRequestResponse message);
                validate_cookie(messages);
                break;
            case NONE:
                // No authentication needed
                // handleNoAuthentication(messages);
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

  void validate_cookie(IHttpRequestResponse message) {
    SwingWorker<Void, Void> worker = new SwingWorker<Void, Void>() {
        @Override
        protected Void doInBackground() throws Exception {
            IRequestInfo analyzedRequest = helpers.analyzeRequest(message);
            List<String> headers = analyzedRequest.getHeaders();
            Short status_code = helpers.analyzeResponse(message.getResponse()).getStatusCode();
            int request_body_offset = analyzedRequest.getBodyOffset();
            byte[] request = message.getRequest();
            String request_string = helpers.bytesToString(request);
            String request_body = request_string.substring(request_body_offset);
            
            // Extract the Cookie header
            String cookieHeader = getCookieHeader(headers);

            // Split the cookies in the Cookie header
            String[] cookies = cookieHeader.split("; ");
            

            // If only one cookie is present, check if removing it changes the status code
            if (cookies.length == 1) {
                headers.removeIf(header -> header.toLowerCase().startsWith("cookie:"));

                byte[] modifiedRequest = helpers.buildHttpMessage(headers, helpers.stringToBytes(request_body));
                IHttpRequestResponse modifiedMessage = callbacks.makeHttpRequest(message.getHttpService(), modifiedRequest);
                Short modified_status_code = helpers.analyzeResponse(modifiedMessage.getResponse()).getStatusCode();

                if (status_code == modified_status_code) {

                    callbacks.issueAlert("There is only 1 cookie in the request and not used for session");
                }
                else {
                    callbacks.issueAlert(String.valueOf(cookies[0]));
                    MatchChecker matchChecker = new MatchChecker(helpers);
                    List < int[] > matches = matchChecker.getMatches(modifiedMessage.getResponse(), modified_status_code.toString().getBytes(StandardCharsets.UTF_8), helpers);
                    List < int[] > matches2 = matchChecker.getMatches(modifiedMessage.getRequest(), helpers.stringToBytes(cookies[0]), helpers);

                    callbacks.addScanIssue(new RaiseVuln(
                        message.getHttpService(),
                        callbacks.getHelpers().analyzeRequest(message).getUrl(),
                    new IHttpRequestResponse[] {
                        message,
                        callbacks.applyMarkers(modifiedMessage, matches2, matches)
                    },
                    "AlphaScan - Session Identifier Found",
                    "The request Cookie found to be used as session. <br>" + cookies[0],
                    "Certain",
                    "Information"
                ));
                }


            }
            else {
                List<String> requiredCookies = new ArrayList<>();

                for (String cookie : cookies) {
                    // Remove the current cookie from the header
                    String modifiedCookieHeader = removeCookieFromHeader(cookieHeader, cookie);
                    // Create a new request with the modified Cookie header
                    List<String> modifiedHeaders = replaceCookieHeader(headers, modifiedCookieHeader);
                    byte[] modifiedRequest = helpers.buildHttpMessage(modifiedHeaders, helpers.stringToBytes(request_body));

                    // Send the modified request
                    IHttpRequestResponse modifiedMessage = callbacks.makeHttpRequest(message.getHttpService(), modifiedRequest);
                    Short modified_status_code = helpers.analyzeResponse(modifiedMessage.getResponse()).getStatusCode();
                    if (status_code.equals(modified_status_code)) {
                        
                    continue;
                }
                    else {
                        
                         //// Send request again only with this cookie
                        headers.removeIf(header -> header.toLowerCase().startsWith("cookie:"));
                        headers.add("Cookie: " + cookie);
                        byte[] modifiedRequest_new = helpers.buildHttpMessage(headers, helpers.stringToBytes(request_body));
                        IHttpRequestResponse modifiedMessage_new = callbacks.makeHttpRequest(message.getHttpService(), modifiedRequest_new);
                        Short modified_status_code_new = helpers.analyzeResponse(modifiedMessage_new.getResponse()).getStatusCode();
                      
                        if (status_code.equals(modified_status_code_new)) {
                            // Assume this is the one used for session
                            callbacks.issueAlert(String.valueOf(cookie));
                          
                        }
                        else {
                           // Assume this cookie is required along with other cookies. 
                           // add it to array to analysis later
                           callbacks.printOutput("Looks this cookie is required along with other cookies" + cookie);
                           requiredCookies.add(cookie);
                        }
                        }

                }

                if (!requiredCookies.isEmpty()) {
                    callbacks.printOutput(Arrays.toString(requiredCookies.toArray()));


                }
            }
            

            

            return null;
        }
    };

    worker.execute();
}

    private String getCookieHeader(List<String> headers) {
        for (String header : headers) {
            if (header.toLowerCase().startsWith("cookie:")) {
                return header.substring("cookie:".length()).trim();
            }
        }
        return "";
    }

    private String removeCookieFromHeader(String cookieHeader, String cookieToRemove) {
        // Replace the cookie to remove with an empty string
        return cookieHeader.replace(cookieToRemove + ";", "").replace(cookieToRemove, "").trim();
    }

    private List<String> replaceCookieHeader(List<String> headers, String newCookieHeader) {
        List<String> modifiedHeaders = new ArrayList<>(headers);
        for (int i = 0; i < modifiedHeaders.size(); i++) {
            if (modifiedHeaders.get(i).toLowerCase().startsWith("cookie:")) {
                modifiedHeaders.set(i, "Cookie: " + newCookieHeader);
                break;
            }
        }
        return modifiedHeaders;
    }

}
