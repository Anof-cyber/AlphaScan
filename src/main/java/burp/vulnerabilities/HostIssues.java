package burp.vulnerabilities;
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
import burp.utility.MatchChecker;
import burp.utility.RaiseVuln;

import java.util.ArrayList;
import java.util.HashSet;

public class HostIssues implements IScannerCheck {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helper;

    public HostIssues(IBurpExtenderCallbacks callbacks, IExtensionHelpers helper) {
        this.callbacks = callbacks;
        this.helper = helper;
    }

    @Override
    public List < IScanIssue > doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        ArrayList < IScanIssue > issues = new ArrayList < > ();
        Set<String> scannedhosts = new HashSet<>();
        String host = baseRequestResponse.getHttpService().getHost();
        if (scannedhosts.contains(host)) {
            return issues; // Skip scanning if Host has already been scanned
        }
        issues.addAll(Check_CSP(baseRequestResponse));
        issues.addAll(Check_HSTS(baseRequestResponse));
        issues.addAll(Check_Xframe(baseRequestResponse));
        scannedhosts.add(host);

        return issues;
    }

    @Override
    public List < IScanIssue > doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        ArrayList < IScanIssue > issues = new ArrayList < > ();
        
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

    

}