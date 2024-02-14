package burp.utility;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;

public class TimeUtility {


    public static double validateTime(IHttpRequestResponse base_pair,IBurpExtenderCallbacks callbacks) {
        long currentTime = System.currentTimeMillis();

        byte[] request = base_pair.getRequest();
        IHttpRequestResponse updated_request_response = callbacks.makeHttpRequest(base_pair.getHttpService(), request);

        long elapsedTime = System.currentTimeMillis() - currentTime;
        return (double) elapsedTime / 1000.0; // Convert milliseconds to seconds
    }
    
}
