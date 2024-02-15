package burp.vulnerabilities;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.net.URL;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IRequestInfo;
import burp.IScanIssue;
import burp.utility.MatchChecker;
import burp.utility.RaiseVuln;

public class CORS {

    private static ArrayList<IScanIssue> issues = new ArrayList<>();

    private static String title = "Alpha Scan - Cross Origin Resource Sharing";
    private static String description_Exploitable = "Application Does not validate the Origin and Trust all the user origin Header, It was observed that application trust the User provided Origin: <br><br>";
    private static String description_wild_card = "Application use the wild card for the origin, Application response with <b>*</b>";
    private static String descrption_null = "Application allow the null origin, which could be used to exploit the vulnerability";

    private ArrayList corsheaders_list = new ArrayList<>();

    public static ArrayList < IScanIssue > Check_CORS(IHttpRequestResponse base_pair, IBurpExtenderCallbacks callbacks, IExtensionHelpers helper)  {
        
        Check_evil(base_pair,callbacks,helper);

        return issues;
    }




    public static void Check_evil(IHttpRequestResponse base_pair, IBurpExtenderCallbacks callbacks, IExtensionHelpers helper) {
        
        IRequestInfo analyzedRequest = helper.analyzeRequest(base_pair);
        List<String> headers = helper.analyzeRequest(base_pair).getHeaders();
        headers.removeIf(header -> header.toLowerCase().startsWith("origin:"));
        headers.add("Origin: http://example.com");

        byte[] requestBody = Arrays.copyOfRange(base_pair.getRequest(), analyzedRequest.getBodyOffset(), base_pair.getRequest().length);
        byte[] newRequest = helper.buildHttpMessage(headers, requestBody);
        IHttpRequestResponse updated_request_response = callbacks.makeHttpRequest(base_pair.getHttpService(), newRequest);
        String expceted = "Access-Control-Allow-Origin: http://example.com";

        if (hasResponseHeaderWithValue(base_pair,helper, expceted)) {
            List<int[]> request_highList = MatchChecker.getMatches_regex(updated_request_response.getRequest(), "Origin: http://example.com");
            List<int[]> response_highlight = MatchChecker.getMatches_regex(updated_request_response.getResponse(), expceted);

            issues.add(new RaiseVuln(
                            base_pair.getHttpService(),
                            callbacks.getHelpers().analyzeRequest(base_pair).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(updated_request_response, request_highList, response_highlight)},
                            title,
                            description_Exploitable + "Origin: http://example.com",
                            "Certain",
                            "Medium"
                        ));
            return;
        }
        headers.removeIf(header -> header.toLowerCase().startsWith("origin:"));
        headers.add("Origin: https://example.com");
        byte[] newRequest_https = helper.buildHttpMessage(headers, requestBody);
        IHttpRequestResponse updated_request_response_https = callbacks.makeHttpRequest(base_pair.getHttpService(), newRequest_https);
        String expceted_https = "Access-Control-Allow-Origin: https://example.com";

        if (hasResponseHeaderWithValue(base_pair,helper, expceted_https)) {
            List<int[]> request_highList = MatchChecker.getMatches_regex(updated_request_response_https.getRequest(), "Origin: https://example.com");
            List<int[]> response_highlight = MatchChecker.getMatches_regex(updated_request_response_https.getResponse(), expceted_https);

            issues.add(new RaiseVuln(
                            base_pair.getHttpService(),
                            callbacks.getHelpers().analyzeRequest(base_pair).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(updated_request_response_https, request_highList, response_highlight)},
                            title,
                            description_Exploitable + "Origin: https://example.com",
                            "Certain",
                            "Medium"
                        ));
            return;
        }
    }

    public static void Check_Subdomain(IHttpRequestResponse base_pair, IBurpExtenderCallbacks callbacks, IExtensionHelpers helper) {


    }



    

    public static boolean hasResponseHeaderWithValue(IHttpRequestResponse base_pair, IExtensionHelpers helper, String headerWithValue) {
        List<String> responseHeaders = helper.analyzeResponse(base_pair.getResponse()).getHeaders();
        for (String header : responseHeaders) {
            if (header.equalsIgnoreCase(headerWithValue)) {
                return true;
            }
        }
        return false;
    }


    
    
}
