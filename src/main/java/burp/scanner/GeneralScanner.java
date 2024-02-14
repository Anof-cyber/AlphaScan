package burp.scanner;

import java.util.ArrayList;
import java.util.List;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.IScannerCheck;
import burp.IScannerInsertionPoint;
import burp.vulnerabilities.ErrorMessage;
import burp.vulnerabilities.JsonCSRF;

public class GeneralScanner implements IScannerCheck {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helper;
    ErrorMessage errorMessage = new ErrorMessage();
    JsonCSRF jsoncsrf = new JsonCSRF();



    public GeneralScanner(IBurpExtenderCallbacks callbacks, IExtensionHelpers helper) {
        this.callbacks = callbacks;
        this.helper = helper;
    }




    @Override
    public List < IScanIssue > doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        ArrayList < IScanIssue > issues = new ArrayList < > ();
        issues.addAll(errorMessage.Check_Errors(baseRequestResponse,callbacks,helper));
        

        return issues;
    }

    @Override
    public List < IScanIssue > doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        ArrayList < IScanIssue > issues = new ArrayList < > ();
        issues.addAll(jsoncsrf.Check_JSON_CSRF(baseRequestResponse,callbacks,helper));
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


