package burp.vulnerabilities;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.*;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.DecodedJWT;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.utility.MatchChecker;
import burp.utility.RaiseVuln;

import java.util.Date;

public class JWTEXpired {

    public static class JwtInfo {
        private Date issuedAt;
        private Date expiresAt;

        public JwtInfo(Date issuedAt, Date expiresAt) {
            this.issuedAt = issuedAt;
            this.expiresAt = expiresAt;
        }

        public Date getIssuedAt() {
            return issuedAt;
        }

        public Date getExpiresAt() {
            return expiresAt;
        }
    }


    public static ArrayList < IScanIssue > Check_JWT_EXPIRY(IHttpRequestResponse base_pair, IBurpExtenderCallbacks callbacks, IExtensionHelpers helper) {

        ArrayList < IScanIssue > issues = new ArrayList < > ();

        String request = helper.bytesToString(base_pair.getRequest());

        Pattern pattern = Pattern.compile("eyJ[A-Za-z0-9-_]*.eyJ[A-Za-z0-9-_]*.[A-Za-z0-9-_]*"); // Use the original regex
        Matcher matcher = pattern.matcher(request);

        List<String> jwtTokens = new ArrayList<>();

        // Find JWT tokens in the request
        while (matcher.find()) {
            jwtTokens.add(matcher.group());
        }
    
        for (String token : jwtTokens) {
            Boolean expiry_set = hasExpiry(token);
            if (!expiry_set) {

                issues.add(new RaiseVuln(
                base_pair.getHttpService(),
                callbacks.getHelpers().analyzeRequest(base_pair).getUrl(),
                new IHttpRequestResponse[]{
                    base_pair
                },
                "AlphaScan - JWT Token Without Expiry",
                "The JWT token used in the request does not have an expiry set. Token: " + token,
                "Tentative",
                "Information"
                ));
            }
            else {

                JwtInfo jwtInfo = decodeJwt(token);
                if (isExpiryMoreThanOneHour(jwtInfo)) {
                    issues.add(new RaiseVuln(
                        base_pair.getHttpService(),
                        callbacks.getHelpers().analyzeRequest(base_pair).getUrl(),
                        new IHttpRequestResponse[]{base_pair},
                        "AlphaScan - JWT Valid for too long",
                        "The JWT token used in the request does not have an expiry set and its expiry time is more than 1 hour from the issued time. Token: <br><br>" + token + "<br><br>Issued Time: " + jwtInfo.getIssuedAt() + "<br><br>Expiry Time: " + jwtInfo.getExpiresAt(),
                        "Certain",
                        "Information"
                    ));
                }
            }
        }

        return issues;
        
    }


    public static boolean hasExpiry(String jwtToken) {
        try {
            DecodedJWT jwt = JWT.decode(jwtToken);
            return jwt.getExpiresAt() != null;
        } catch (JWTDecodeException e) {
            return false; // Error decoding token or invalid token
        }
    }

    public static JwtInfo decodeJwt(String jwtToken) {
        try {
            DecodedJWT jwt = JWT.decode(jwtToken);
            Date issuedAt = jwt.getIssuedAt();
            Date expiresAt = jwt.getExpiresAt();
            return new JwtInfo(issuedAt, expiresAt);
        } catch (JWTDecodeException e) {
            return null; // Error decoding token or invalid token
        }
    }

    public static boolean isExpiryMoreThanOneHour(JwtInfo jwtInfo) {
        if (jwtInfo == null) {
            return false; // Token is invalid
        }
        Date issuedAt = jwtInfo.getIssuedAt();
        Date expiresAt = jwtInfo.getExpiresAt();
        if (issuedAt == null || expiresAt == null) {
            return false; // Token is missing issuedAt or exp claims
        }
        long differenceMillis = expiresAt.getTime() - issuedAt.getTime();
        long oneHourInMillis = 3600000; // 1 hour in milliseconds
        return differenceMillis > oneHourInMillis;
    }
    
}
