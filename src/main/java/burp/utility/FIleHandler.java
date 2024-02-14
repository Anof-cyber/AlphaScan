package burp.utility;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

import burp.scanner.CriticalIssues;

public class FIleHandler {


    public static String[] readPayloadsFromFile(String filePath) {
        try (InputStream inputStream = CriticalIssues.class.getResourceAsStream("/" + filePath); BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {

            if (inputStream != null) {
                return reader.lines().toArray(String[]::new);
            } else {
                // Handle case when resource is not found
                System.err.println("File not found in the JAR: " + filePath);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return new String[0]; // Return an empty array if there's an issue reading the file
    }
    
}
