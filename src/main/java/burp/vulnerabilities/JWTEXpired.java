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

        byte[] request = base_pair.getRequest();
        
        List<String> jwtTokens = extractJWTTokens(request);
        callbacks.printOutput(String.join(",", jwtTokens));
       


        return issues;




    }


    public static List<String> extractJWTTokens(byte[] request) {
        List<String> jwtTokens = new ArrayList<>();
        final String regex = "^((?:\\.?(?:[A-Za-z0-9-_]+)){3})$";
        final Pattern pattern = Pattern.compile(regex, Pattern.MULTILINE);
        final String requestString = new String(request);

        final Matcher matcher = pattern.matcher(requestString);

        while (matcher.find()) {
            jwtTokens.add(matcher.group(0));
        }

        return jwtTokens;
    }
    
}
