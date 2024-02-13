package burp.vulnerabilities;

import java.util.ArrayList;
import java.util.List;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.utility.MatchChecker;
import burp.utility.RaiseVuln;

public class ErrorMessage {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helper;



    public ArrayList < IScanIssue > Check_Errors(IHttpRequestResponse base_pair) {

        ArrayList < IScanIssue > issues = new ArrayList < > ();

        MatchChecker matchChecker = new MatchChecker(helper);
        List<int[]> matches = matchChecker.getSqlMatches(base_pair.getResponse());
        List<int[]> errormatchs = matchChecker.geterrormessage(base_pair.getResponse());

        if (matches.isEmpty() || errormatchs.isEmpty()) {
            return issues;
        }
        List<int[]> combinedMatches = new ArrayList<>(matches);
        combinedMatches.addAll(errormatchs);


        issues.add(new RaiseVuln(
            base_pair.getHttpService(),
                    callbacks.getHelpers().analyzeRequest(base_pair).getUrl(),
                    new IHttpRequestResponse[]{
                        base_pair,
                            callbacks.applyMarkers(base_pair, null, combinedMatches)
                    },
                    "AlphaScan - Error Message Detected",
                    "The application might be exposing error messages. The scanner detected potential error message patterns in the response. Please investigate further to confirm the source and implications of these error messages.",
                    "Certain",
                    "High"
            ));

        return issues;

    };
    
}
