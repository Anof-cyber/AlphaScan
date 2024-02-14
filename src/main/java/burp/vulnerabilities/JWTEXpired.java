package burp.vulnerabilities;

import java.util.ArrayList;
import java.util.List;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.utility.MatchChecker;

public class JWTEXpired {


    public static ArrayList < IScanIssue > Check_JWT_EXPIRY(IHttpRequestResponse base_pair, IBurpExtenderCallbacks callbacks, IExtensionHelpers helper) {

        ArrayList < IScanIssue > issues = new ArrayList < > ();

        byte[] request = base_pair.getRequest();
        String regex = "[a-zA-Z0-9-_=]+\\.[a-zA-Z0-9-_=]+\\.[a-zA-Z0-9-_=]+";

        String jwtToken = findJWTToken(request, regex);
        callbacks.printOutput(jwtToken);
       


        return issues;




    }


    public static String findJWTToken(byte[] request, String regex) {
        List<int[]> matches = MatchChecker.getMatches_regex(request, regex);

        if (!matches.isEmpty()) {
            int[] matchIndices = matches.get(0);
            return new String(request, matchIndices[0], matchIndices[1] - matchIndices[0]);
        }

        return null;
    }
    
}
