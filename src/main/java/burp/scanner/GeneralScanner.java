package burp.scanner;

import java.util.ArrayList;
import java.util.List;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.IScannerCheck;
import burp.IScannerInsertionPoint;
import burp.vulnerabilities.CORS;
import burp.vulnerabilities.ErrorMessage;
import burp.vulnerabilities.JWTEXpired;
import burp.vulnerabilities.JsonCSRF;

public class GeneralScanner implements IScannerCheck {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helper;



    public GeneralScanner(IBurpExtenderCallbacks callbacks, IExtensionHelpers helper) {
        this.callbacks = callbacks;
        this.helper = helper;
    }




    @Override
    public List < IScanIssue > doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        ArrayList < IScanIssue > issues = new ArrayList < > ();
        issues.addAll(ErrorMessage.Check_Errors(baseRequestResponse,callbacks,helper));
        issues.addAll(JWTEXpired.Check_JWT_EXPIRY(baseRequestResponse, callbacks, helper));
        

        return issues;
    }

    @Override
    public List < IScanIssue > doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        ArrayList < IScanIssue > issues = new ArrayList < > ();
        issues.addAll(JsonCSRF.Check_JSON_CSRF(baseRequestResponse,callbacks,helper));
        issues.addAll(CORS.Check_CORS(baseRequestResponse, callbacks, helper));
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


