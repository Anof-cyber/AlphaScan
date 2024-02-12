package burp.vulnerabilities;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.IScannerCheck;
import burp.IScannerInsertionPoint;
import burp.utility.SSTIInjectionPatterns;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

public class SSTI implements IScannerCheck {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helper;

    public SSTI(IBurpExtenderCallbacks callbacks, IExtensionHelpers helper) {
        this.callbacks = callbacks;
        this.helper = helper;
    }

    public SSTI() {
    }

    @Override
    public List < IScanIssue > doPassiveScan(IHttpRequestResponse baseRequestResponse) {
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
    @Override
    public List < IScanIssue > doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {


        // Check if any erros related to template engine
        byte[] modifiedRequest = insertionPoint.buildRequest(helper.stringToBytes("${{<%[%'\\\"}}%\\\\"));
        IHttpRequestResponse updatedRequestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), modifiedRequest);

        SSTIInjectionPatterns patternchecks = new SSTIInjectionPatterns();
        String engine = patternchecks.identifyVulnerability(helper.bytesToString(updatedRequestResponse.getResponse()));
        if (engine != null) {

            SSTI CurrentObject = new SSTI();

            try {
            Method method = SSTI.class.getDeclaredMethod(engine, IHttpRequestResponse.class);
            method.setAccessible(true);
            ArrayList<IScanIssue> result = (ArrayList<IScanIssue>) method.invoke(CurrentObject, baseRequestResponse);

            }
            catch (Exception e) {
                e.printStackTrace();
            }

        }
        




        ArrayList < IScanIssue > issues = new ArrayList < > ();
        return issues;
    }




    private ArrayList < IScanIssue > Jinja2(IHttpRequestResponse base_pair) {
        ArrayList < IScanIssue > issues = new ArrayList < > ();




        return issues;
        
    }
    
    
}
