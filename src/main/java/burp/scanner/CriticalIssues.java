package burp.scanner;

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
import burp.utility.FIleHandler;
import burp.utility.TimeUtility;
import burp.utility.SeleniumHandler;
import burp.vulnerabilities.AWSSSRF;
import burp.vulnerabilities.SQLijection;
/**
 *
 * @author AnoF
 */

public class CriticalIssues implements IScannerCheck {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helper;

    AWSSSRF awsssrf = new AWSSSRF();
    SQLijection sqlinjection = new SQLijection();
   

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
        
        issues.addAll(awsssrf.AWS_SSRF(baseRequestResponse,insertionPoint,callbacks,helper));
        issues.addAll(sqlinjection.TimeSQL(baseRequestResponse, insertionPoint,callbacks,helper));
        issues.addAll(sqlinjection.ErrorSQLInjection(baseRequestResponse, insertionPoint,callbacks,helper));
        
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

    

    private ArrayList < IScanIssue > ReflectedXSS(IHttpRequestResponse base_pair, IScannerInsertionPoint insertionPoint, SeleniumHandler seleniumHandler) {
        ArrayList < IScanIssue > issues = new ArrayList < > ();

        try {
            String fileName = "payloads/xss.txt";
            String[] fileContent = FIleHandler.readPayloadsFromFile(fileName);

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

   
}