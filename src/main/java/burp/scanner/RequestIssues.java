package burp.scanner;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.IScannerCheck;
import burp.IScannerInsertionPoint;
import burp.vulnerabilities.ForcedBrowsing;
import burp.vulnerabilities.XMLContentType;;

public class RequestIssues implements IScannerCheck {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helper;


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


        issues.addAll(XMLContentType.Check_XML_ContentType(baseRequestResponse,callbacks,helper));
        issues.addAll(ForcedBrowsing.forced_browsing(baseRequestResponse,callbacks,helper));
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

}
