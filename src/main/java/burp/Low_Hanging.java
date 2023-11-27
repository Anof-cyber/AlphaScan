package burp;
import java.util.List;
import java.util.ArrayList;

public class Low_Hanging implements IScannerCheck {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helper;

    public Low_Hanging(IBurpExtenderCallbacks callbacks, IExtensionHelpers helper) {
        this.callbacks = callbacks;
        this.helper = helper;
    }

    @Override
    public List < IScanIssue > doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        ArrayList < IScanIssue > issues = new ArrayList < > ();
        issues.addAll(Check_CSP(baseRequestResponse));
        issues.addAll(Check_HSTS(baseRequestResponse));
        issues.addAll(Check_Xframe(baseRequestResponse));

        return issues;
    }

    @Override
    public List < IScanIssue > doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        ArrayList < IScanIssue > issues = new ArrayList < > ();
        issues.addAll(Check_XML_ContentType(baseRequestResponse));

        return issues;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {

        String existinghostname = existingIssue.getUrl().getHost();
        String newhostname = newIssue.getUrl().getHost();

        if (existingIssue.getIssueName().equals(newIssue.getIssueName())) {
            
            if (!newIssue.getIssueName().equals("AlphaScan - XML Content Type Supported")) {
                if (existinghostname.equals(newhostname)) {
                return -1;
            } else {
                return 0;
            }
            
            }
            else {
                return -1;
            }
            
        } else {
            return 0;
        }
    }

    private ArrayList < IScanIssue > Check_CSP(IHttpRequestResponse base_pair) {
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

    private ArrayList < IScanIssue > Check_HSTS(IHttpRequestResponse base_pair) {
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

    private ArrayList < IScanIssue > Check_Xframe(IHttpRequestResponse base_pair) {
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

            MatchChecker matchChecker = new MatchChecker();
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