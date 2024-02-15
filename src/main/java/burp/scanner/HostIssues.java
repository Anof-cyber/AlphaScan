package burp.scanner;
import java.util.List;
import java.util.Set;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.IScannerCheck;
import burp.IScannerInsertionPoint;
import burp.vulnerabilities.HeaderIssues;

import java.util.ArrayList;
import java.util.HashSet;

public class HostIssues implements IScannerCheck {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helper;
    private Set<String> scannedhosts = new HashSet<>();

    public HostIssues(IBurpExtenderCallbacks callbacks, IExtensionHelpers helper) {
        this.callbacks = callbacks;
        this.helper = helper;
    }

    @Override
    public List < IScanIssue > doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        ArrayList < IScanIssue > issues = new ArrayList < > ();
        
        String host = baseRequestResponse.getHttpService().getHost();
        if (scannedhosts.contains(host)) {
            return issues; // Skip scanning if Host has already been scanned
        }
        issues.addAll(HeaderIssues.Check_CSP(baseRequestResponse,callbacks,helper));
        issues.addAll(HeaderIssues.Check_HSTS(baseRequestResponse,callbacks,helper));
        issues.addAll(HeaderIssues.Check_Xframe(baseRequestResponse,callbacks,helper));
        issues.addAll(HeaderIssues.Check_Http_Only(baseRequestResponse,callbacks,helper));
        issues.addAll(HeaderIssues.Check_Secure(baseRequestResponse,callbacks,helper));
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


        if (existingIssue.getIssueName().equals(newIssue.getIssueName())) {
            
            return 1;
            
        } else {
            return 0;
        }
    }

    


    

    

    

    



    
    

}