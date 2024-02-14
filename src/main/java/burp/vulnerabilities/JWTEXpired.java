package burp.vulnerabilities;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.*;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.utility.MatchChecker;

public class JWTEXpired {


    public static ArrayList < IScanIssue > Check_JWT_EXPIRY(IHttpRequestResponse base_pair, IBurpExtenderCallbacks callbacks, IExtensionHelpers helper) {

        ArrayList < IScanIssue > issues = new ArrayList < > ();

        String request = helper.bytesToString(base_pair.getRequest());

        Pattern pattern = Pattern.compile("^[A-Za-z0-9-_]*\\.[A-Za-z0-9-_]*\\.[A-Za-z0-9-_]*$");
        Matcher matcher = pattern.matcher(request);

        List<String> jwtTokens = new ArrayList<>();

        // Find JWT tokens in the request
        while (matcher.find()) {
            jwtTokens.add(matcher.group(1));
        }

        for (String token : jwtTokens) {

            callbacks.printOutput(token);
        }

        return issues;
        
    }
    
}
