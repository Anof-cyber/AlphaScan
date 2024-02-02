package burp.utility;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Config {
    private static Map<String, Object> configData = new HashMap<>();

    // Get config value by key
    @SuppressWarnings("unchecked")
    public static <T> T getConfigValue(String key) {
        return (T) configData.get(key);
    }

    // Set or update config value
    public static void setConfigValue(String key, Object value) {
        configData.put(key, value);
    }

    // Remove config value by key
    public static void removeConfigValue(String key) {
        configData.remove(key);
    }
}