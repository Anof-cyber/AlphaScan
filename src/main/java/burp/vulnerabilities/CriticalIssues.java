package burp.vulnerabilities;

import java.net.URL;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.IScannerCheck;
import burp.IScannerInsertionPoint;
import burp.utility.Config;
import burp.utility.MatchChecker;
import burp.utility.RaiseVuln;
import burp.utility.SeleniumHandler;
/**
 *
 * @author AnoF
 */

public class CriticalIssues implements IScannerCheck {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helper;
    private static final List<String> DISALLOWED_EXTENSIONS = Arrays.asList(".js", ".css", ".jpg", ".jpeg", ".png", ".gif", ".svg");


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
        WebDriver driver = initializeWebDriver();
        if (driver != null) {
            SeleniumHandler seleniumHandler = new SeleniumHandler();
            seleniumHandler.setWebDriver(driver);
            issues.addAll(ReflectedXSS(baseRequestResponse, insertionPoint, seleniumHandler));
        };
        
        //issues.addAll(AWS_SSRF(baseRequestResponse,insertionPoint));
        //issues.addAll(TimeSQL(baseRequestResponse, insertionPoint));
        //issues.addAll(ErrorSQLInjection(baseRequestResponse, insertionPoint));
        
        issues.addAll(Forced_Browsing(baseRequestResponse, insertionPoint));

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

    public ArrayList<IScanIssue> ErrorSQLInjection(IHttpRequestResponse basePair, IScannerInsertionPoint insertionPoint) {
        ArrayList<IScanIssue> issues = new ArrayList<>();
        String[] payloads = readPayloadsFromFile("payloads/error_sql.txt"); 
        
    
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
    
    // Forced Browsing is experimental
    private ArrayList < IScanIssue > Forced_Browsing(IHttpRequestResponse base_pair, IScannerInsertionPoint insertionPoint) {

        ArrayList < IScanIssue > issues = new ArrayList < > ();

        String cookieHeader = Config.getConfigValue("CookieHeader");
        callbacks.printOutput(cookieHeader);
        if (cookieHeader != null) {
            Short orignal_status = helper.analyzeResponse(base_pair.getResponse()).getStatusCode();
            List<String> headers = helper.analyzeRequest(base_pair.getRequest()).getHeaders();
            int bodyOffset = helper.analyzeRequest(base_pair.getRequest()).getBodyOffset();
            byte[] request = base_pair.getRequest();
            String request_string = helper.bytesToString(request);
            String request_body = request_string.substring(bodyOffset);
            URL requestUrl = helper.analyzeRequest(base_pair).getUrl();
            callbacks.printOutput("Cookie check");
            


            if (isStaticResource(requestUrl)) {
                callbacks.printOutput("Static file");
                return issues;
            }
            if (orignal_status != 200 || orignal_status != 201) {
                callbacks.printOutput("Status Code is 200 or 201");
                callbacks.printOutput(String.valueOf(orignal_status));
                return issues;
            }


            callbacks.printOutput("Orignal Status Code 200");
            headers.removeIf(header -> header.toLowerCase().startsWith("cookie:"));
            headers.add("Scanner: AlphaScan");

            byte[] modifiedRequest = helper.buildHttpMessage(headers, helper.stringToBytes(request_body));
            IHttpRequestResponse modifiedMessage = callbacks.makeHttpRequest(base_pair.getHttpService(), modifiedRequest);
            Short modified_status_code = helper.analyzeResponse(modifiedMessage.getResponse()).getStatusCode();

            if (orignal_status.equals(modified_status_code)) {

                issues.add(new RaiseVuln(
                base_pair.getHttpService(),
                callbacks.getHelpers().analyzeRequest(base_pair).getUrl(),
                new IHttpRequestResponse[] {
                    base_pair
                    //callbacks.applyMarkers(updated_request_response, requestHighlights, matches)
                },
                "AlphaScan - Forced Browsing",
                "The application is vulnerable to Forced Browsing, allowing unauthorized access to sensitive resources. Forced Browsing occurs when an attacker navigates to URLs or directories that are not intended to be directly accessible, potentially revealing sensitive information or functionality. This vulnerability was detected during an assessment, revealing unauthorized access to sensitive resources via forced URL manipulation.<br><br>The vulnerability was further confirmed by AlphaScan, which sent the updated request without session identifier and observed the same response both with and without session, indicating the absence of proper access controls.<br><br>This issue is prone to false positives, and manual verification is required.",
                "Tentative",
                "High"
            ));

            }
        }


        return issues;


    }
    

    private ArrayList < IScanIssue > AWS_SSRF(IHttpRequestResponse base_pair, IScannerInsertionPoint insertionPoint) {
        ArrayList < IScanIssue > issues = new ArrayList < > ();
        List < String > listOfPayload = new ArrayList < > (Arrays.asList(
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

        for (String payload: listOfPayload) {
            System.out.println(payload);
            byte[] modified_request = insertionPoint.buildRequest(helper.stringToBytes(payload));
            IHttpRequestResponse updated_request_response = callbacks.makeHttpRequest(base_pair.getHttpService(), modified_request);

            //MatchChecker matchChecker = new MatchChecker();
            MatchChecker matchChecker = new MatchChecker(helper);
            List < int[] > matches = matchChecker.getMatches(updated_request_response.getRequest(), helper.stringToBytes("hostname"), helper);

            if (matches.isEmpty()) {
                continue;
            }
            List < int[] > requestHighlights = new ArrayList < > (1);
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

    private ArrayList < IScanIssue > TimeSQL(IHttpRequestResponse base_pair, IScannerInsertionPoint insertionPoint) {

        ArrayList < IScanIssue > issues = new ArrayList < > ();
        double original_response_time = validateTime(base_pair);
        String fileName = "payloads/time_sql.txt";
        String[] fileContent = readPayloadsFromFile(fileName);
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

    private ArrayList < IScanIssue > ReflectedXSS(IHttpRequestResponse base_pair, IScannerInsertionPoint insertionPoint, SeleniumHandler seleniumHandler) {
        ArrayList < IScanIssue > issues = new ArrayList < > ();

        try {
            String fileName = "payloads/xss.txt";
            String[] fileContent = readPayloadsFromFile(fileName);

            for (String payload: fileContent) {
                byte[] modified_request = insertionPoint.buildRequest(helper.stringToBytes(payload));
                IHttpRequestResponse updated_request_response = callbacks.makeHttpRequest(base_pair.getHttpService(), modified_request);

                //MatchChecker matchChecker = new MatchChecker();
                MatchChecker matchChecker = new MatchChecker(helper);
                List < int[] > matches = matchChecker.getMatches(updated_request_response.getRequest(), helper.stringToBytes(payload), helper);
                String statedMimeType = callbacks.getHelpers().analyzeResponse(updated_request_response.getResponse()).getStatedMimeType();

                if (matches.isEmpty() && (statedMimeType == null || !statedMimeType.toLowerCase().contains("html"))) {
                    continue;
                }

                int bodyOffset = callbacks.getHelpers().analyzeResponse(updated_request_response.getResponse()).getBodyOffset();
                List < int[] > requestHighlights = new ArrayList < > (1);
                requestHighlights.add(insertionPoint.getPayloadOffsets(helper.stringToBytes(payload)));

                byte[] responseBodyBytes = Arrays.copyOfRange(updated_request_response.getResponse(), bodyOffset, updated_request_response.getResponse().length);
                String responseBody = new String(responseBodyBytes);

                try {
                    String alertText = seleniumHandler.checkForAlerts(responseBody);
                    issues.add(new RaiseVuln(
                        base_pair.getHttpService(),
                        callbacks.getHelpers().analyzeRequest(base_pair).getUrl(),
                        new IHttpRequestResponse[] {
                            base_pair,
                            callbacks.applyMarkers(updated_request_response, requestHighlights, matches)
                        },
                        "AlphaScan - Reflected XSS",
                        "The application is vulnerable to Reflected Cross-Site Scripting (XSS). This vulnerability allows an attacker to inject malicious scripts that execute in the victim's browser. The XSS payload <b>" + payload + "</b> was injected into the <b>" + insertionPoint.getInsertionPointName() + "</b> parameter and was reflected in the response. Subsequent analysis confirms that the injected payload was successfully executed as HTML in the victim's browser, resulting in the display of an alert message:<br><br><b>" + alertText + "</b><br><br>",
                        "Certain",
                        "High"
                    ));
                    break;
                } catch (Exception e) {
                    callbacks.printError("Error occurred: " + e.getMessage());
                }
            
            }
        } finally {

        }

        return issues;
    }

    private static String[] readPayloadsFromFile(String filePath) {
        try (InputStream inputStream = CriticalIssues.class.getResourceAsStream("/" + filePath); BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {

            if (inputStream != null) {
                return reader.lines().toArray(String[]::new);
            } else {
                // Handle case when resource is not found
                System.err.println("File not found in the JAR: " + filePath);
            }
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

    private static WebDriver initializeWebDriver() {
        String chromeDriverPath = Config.getConfigValue("ChromeDriverPath");
        if (chromeDriverPath == null) {
            return null;
        }
        System.setProperty("webdriver.chrome.driver", chromeDriverPath);

        ChromeOptions options = new ChromeOptions();
        options.addArguments("--headless");
        options.addArguments("--disable-gpu");

        return new ChromeDriver(options);
    }

    public boolean isStaticResource(URL requestUrl) {
        // Check if the request URL contains any disallowed file extension
        String path = requestUrl.getPath();
        for (String extension : DISALLOWED_EXTENSIONS) {
            if (path.toLowerCase().endsWith(extension)) {
                return true; // Request is for a static resource
            }
        }
        return false; // Request is not for a static resource
    }

}