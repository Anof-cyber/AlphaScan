package burp.vulnerabilities;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.IScannerInsertionPoint;
import burp.utility.MatchChecker;
import burp.utility.RaiseVuln;
import burp.IRequestInfo;

public class JsonCSRF {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helper;
    private static final List<String> IGNORE_HEADER = Arrays.asList("API","Authorization","X-Api-Key","CSRF","X-CSRF-TOKEN","XSRF-TOKEN");


    public ArrayList < IScanIssue > Check_JSON_CSRF(IHttpRequestResponse base_pair, IBurpExtenderCallbacks callbacks, IExtensionHelpers helper) {
        ArrayList < IScanIssue > issues = new ArrayList < > ();

        byte content_type = helper.analyzeRequest(base_pair).getContentType();
        Short orignal_status = helper.analyzeResponse(base_pair.getResponse()).getStatusCode();
        IRequestInfo analyzedRequest = helper.analyzeRequest(base_pair);
        int request_body_offset = analyzedRequest.getBodyOffset();
        byte[] request = base_pair.getRequest();
        String request_string = helper.bytesToString(request);
        String request_body = request_string.substring(request_body_offset);

        if (content_type == IRequestInfo.CONTENT_TYPE_JSON) {

            List<String> listOfHeaders = helper.analyzeRequest(base_pair).getHeaders();
            boolean hasIgnoredHeaders = hasIgnoredHeaders(listOfHeaders);

            if (!hasIgnoredHeaders) { 

            List<String> updatedHeader = updateContentTypeHeader(listOfHeaders);

            byte[] modifiedRequest = helper.buildHttpMessage(updatedHeader, helper.stringToBytes(request_body));
            callbacks.printOutput(helper.bytesToString(modifiedRequest));
            IHttpRequestResponse modifiedMessage = callbacks.makeHttpRequest(base_pair.getHttpService(), modifiedRequest);

            Short modified_status_code = helper.analyzeResponse(modifiedMessage.getResponse()).getStatusCode();

            if (orignal_status == modified_status_code) {

                MatchChecker matchChecker = new MatchChecker(helper);
                List < int[] > matches = matchChecker.getMatches(modifiedMessage.getRequest(), helper.stringToBytes("Content-Type: text/plain"), helper);

                List < int[] > matches2 = matchChecker.getMatches(modifiedMessage.getResponse(), modified_status_code.toString().getBytes(StandardCharsets.UTF_8), helper);
                  

                issues.add(new RaiseVuln(
                    base_pair.getHttpService(),
                            callbacks.getHelpers().analyzeRequest(base_pair).getUrl(),
                            new IHttpRequestResponse[]{
                                base_pair,
                                    callbacks.applyMarkers(base_pair, matches, matches2)
                            },
                            "AlphaScan - Potential JSON CSRF",
                            "The application use JSON content type without any validation. The extension use the text content type and observed that same response, It could be possible that application support JSON body with text content type, which could be used to perfrom CSRF on JSON",
                            "Tentative",
                            "Low"
                    ));
            }

        };

        }

        

        return issues;

    };



    private List<String> updateContentTypeHeader(List<String> headers) {
        List<String> updatedHeaders = new ArrayList<>(headers);

        // iterate through the headers
        for (int i = 0; i < updatedHeaders.size(); i++) {
            String header = updatedHeaders.get(i);

            // check if the header is the Content-Type header
            if (header.toLowerCase().startsWith("content-type:")) {
                // update the value of the Content-Type header to "text/plain"
                updatedHeaders.set(i, "Content-Type: text/plain");
            }
        }

        return updatedHeaders;
    }

    private boolean hasIgnoredHeaders(List<String> headers) {
        return headers.stream()
                .map(header -> header.split(":")[0]) // Extract header name
                .anyMatch(headerName -> IGNORE_HEADER.stream().anyMatch(headerName::startsWith));
    }
    
};
