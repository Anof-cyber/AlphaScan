package burp.utility;

import java.util.ArrayList;
import java.util.List;

import java.util.ArrayList;
import java.util.List;

public class CookieUtils {

    /*
     * Check if Session cookie is not null else return empty headers
     * Check if session cookie is present in currrnt reqeust header else empty headers
     * Remove the session cookie from header
     * Return the updated headers 
     */

    public static List<String> areAllCookiesPresent(String cookieHeader, List<String> headers) {
        if (cookieHeader == null) {
            return new ArrayList<>();
        }
    
        // Check if "Cookie" header is present
        boolean cookieHeaderPresent = false;
        for (String header : headers) {
            if (header.trim().startsWith("Cookie:")) {
                cookieHeaderPresent = true;
                break;
            }
        }
    
        // If "Cookie" header is not present, return an empty list
        if (!cookieHeaderPresent) {
            return new ArrayList<>();
        }
    
        // Split the cookieHeader into individual cookies
        String[] cookies = cookieHeader.split("; ");
    
        // Get request headers
        List<String> updatedHeaders = new ArrayList<>(headers);
        List<String> cookieValues = new ArrayList<>();
        for (String header : headers) {
            if (header.trim().startsWith("Cookie:")) {
                String[] cookieParts = header.trim().substring(7).split(";");
                for (String cookiePart : cookieParts) {
                    cookieValues.add(cookiePart.split("=")[0].trim());
                }
                break;
            }
        }
    
        // Check if all cookie names in cookieHeader are present in the request
        for (String cookie : cookies) {
            // Extract cookie name
            String cookieName = cookie.split("=")[0].trim();
    
            // Check if the cookie name is present in the request cookie values
            boolean cookiePresent = false;
            for (String value : cookieValues) {
                if (value.equals(cookieName)) {
                    cookiePresent = true;
                    break;
                }
            }
    
            // If any cookie is not present, return an empty list
            if (!cookiePresent) {
                return new ArrayList<>();
            } else {
                // If cookie is present, remove it from the updated headers
                updatedHeaders.removeIf(header -> header.trim().toLowerCase().startsWith("cookie:") && header.contains(cookieName));
            }
        }
    
        // If all cookies are present, return the updated headers
        return updatedHeaders;
    }
}
