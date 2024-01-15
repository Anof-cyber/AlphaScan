package burp.utility;

import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SSTIInjectionPatterns {

    private final HashMap<String, Pattern[]> patternsMap;

    public SSTIInjectionPatterns() {
        this.patternsMap = new HashMap<>();
        initializePatterns();
    }

    public String identifyVulnerability(String responseBody) {
        for (String engine : patternsMap.keySet()) {
            for (Pattern pattern : patternsMap.get(engine)) {
                Matcher matcher = pattern.matcher(responseBody);
                if (matcher.find()) {
                    return engine;
                }
            }
        }
        return null;
    }

    private void initializePatterns() {
        // Template Engine Errors
        patternsMap.put("Jinja2", new Pattern[]{
                Pattern.compile("jinja2.exceptions.TemplateSyntaxError"),
                Pattern.compile("jinja2"),
                Pattern.compile("ZeroDivisionError: division by zero"),
                Pattern.compile("jinja2\\\\.exceptions\\..*")
        });

       
    }
}

