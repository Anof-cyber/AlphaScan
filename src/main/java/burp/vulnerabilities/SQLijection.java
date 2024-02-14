package burp.vulnerabilities;

import java.util.ArrayList;
import java.util.List;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.IScannerInsertionPoint;
import burp.utility.FIleHandler;
import burp.utility.MatchChecker;
import burp.utility.RaiseVuln;
import burp.utility.TimeUtility;

public class SQLijection {


    public static ArrayList < IScanIssue > TimeSQL(IHttpRequestResponse base_pair, IScannerInsertionPoint insertionPoint, IBurpExtenderCallbacks callbacks, IExtensionHelpers helper) {
        
        ArrayList < IScanIssue > issues = new ArrayList < > ();
        double original_response_time = TimeUtility.validateTime(base_pair,callbacks);
        String fileName = "payloads/time_sql.txt";
        String[] fileContent = FIleHandler.readPayloadsFromFile(fileName);
        for (String payload: fileContent) {

            byte[] modified_request = insertionPoint.buildRequest(helper.stringToBytes(insertionPoint.getBaseValue() + " " + payload));
            long preRequestTime = System.currentTimeMillis();
            IHttpRequestResponse request_response = callbacks.makeHttpRequest(base_pair.getHttpService(), modified_request);
            long postRequestTime = System.currentTimeMillis();
            long postRequestElapsedTime = postRequestTime - preRequestTime;
            List < int[] > requestHighlights = new ArrayList < > (1);
            requestHighlights.add(insertionPoint.getPayloadOffsets(helper.stringToBytes(insertionPoint.getBaseValue() + " " + payload)));

            if (postRequestTime > original_response_time) {
                double milliseconds = postRequestTime * 1000;

                if (milliseconds >= 5000) {
                    String modifiedPayload = payload.replace("5", "10");
                    byte[] modified_request_10_sec = insertionPoint.buildRequest(helper.stringToBytes(insertionPoint.getBaseValue() + " " + modifiedPayload));

                    long pre_request_time_10_sec = System.currentTimeMillis();
                    IHttpRequestResponse request_response_10_sec = callbacks.makeHttpRequest(base_pair.getHttpService(), modified_request_10_sec);

                    long post_request_time_10_sec = System.currentTimeMillis() - pre_request_time_10_sec; // Calculate the time difference

                    List < int[] > requestHighlights_10_sec = new ArrayList < > (1);
                    requestHighlights_10_sec.add(insertionPoint.getPayloadOffsets(helper.stringToBytes(insertionPoint.getBaseValue() + " " + payload.replace("5", "10"))));

                    long post_request_time_10_sec_seconds = post_request_time_10_sec / 1000; // Convert milliseconds to seconds

                    if (post_request_time_10_sec_seconds >= 10) {

                        issues.add(new RaiseVuln(
                            base_pair.getHttpService(),
                            callbacks.getHelpers().analyzeRequest(base_pair).getUrl(),
                            new IHttpRequestResponse[] {
                                base_pair,
                                callbacks.applyMarkers(request_response, requestHighlights, null),
                                callbacks.applyMarkers(request_response_10_sec, requestHighlights_10_sec, null)
                            },
                            "AlphaScan - Time Based SQL Injection",
                            "sql",
                            "Certain",
                            "High"
                        ));
                        break;

                    }

                }

            }
            

        }
        return issues;

    }




    public static ArrayList < IScanIssue > ErrorSQLInjection(IHttpRequestResponse basePair, IScannerInsertionPoint insertionPoint, IBurpExtenderCallbacks callbacks, IExtensionHelpers helper) {
    
        ArrayList<IScanIssue> issues = new ArrayList<>();
        String[] payloads = FIleHandler.readPayloadsFromFile("payloads/error_sql.txt"); 
        
    
        for (String payload : payloads) {
            byte[] modifiedRequest = insertionPoint.buildRequest(helper.stringToBytes(payload));
            IHttpRequestResponse updatedRequestResponse = callbacks.makeHttpRequest(basePair.getHttpService(), modifiedRequest);
    
            MatchChecker matchChecker = new MatchChecker(helper);
            List<int[]> matches = matchChecker.getSqlMatches(updatedRequestResponse.getResponse());
    
            if (matches.isEmpty()) {
                continue;
            }
    
            List<int[]> requestHighlights = new ArrayList<>(1);
            requestHighlights.add(insertionPoint.getPayloadOffsets(helper.stringToBytes(payload)));
    
            issues.add(new RaiseVuln(
                    basePair.getHttpService(),
                    callbacks.getHelpers().analyzeRequest(basePair).getUrl(),
                    new IHttpRequestResponse[]{
                            basePair,
                            callbacks.applyMarkers(updatedRequestResponse, requestHighlights, matches)
                    },
                    "AlphaScan - Error Based SQL Injection",
                    "The application might be vulnerable to SQL injection. The scanner detected potential SQL error patterns in the response after injecting the payload: <br><br>" + payload + "<br><br>Please investigate further to confirm the vulnerability and mitigate the risk.",
                    "Certain",
                    "High"
            ));
            break;
        }
    
        return issues;

    }


}
