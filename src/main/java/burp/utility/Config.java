package burp.utility;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Config {
    private static Map<String, String> configData = new HashMap<>();

    // Get config value by key
    public static String getConfigValue(String key) {
        return configData.get(key);
    }

    // Set or update config value
    public static void setConfigValue(String key, String value) {
        configData.put(key, value);
    }

    // Remove config value by key
    public static void removeConfigValue(String key) {
        configData.remove(key);
    }
}