package burp.vulnerabilities;

import java.util.ArrayList;
import java.util.List;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.IScanIssue;
import burp.utility.MatchChecker;
import burp.utility.RaiseVuln;

public class XMLContentType {


    public static ArrayList < IScanIssue > Check_XML_ContentType(IHttpRequestResponse base_pair, IBurpExtenderCallbacks callbacks, IExtensionHelpers helper) {

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
    
}
