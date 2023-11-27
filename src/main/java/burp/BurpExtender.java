package burp;


import java.io.PrintWriter;

/**
 *
 * @author AnoF
 */
public class BurpExtender implements IBurpExtender {
    private Low_Hanging lowHangingScanner;
    private IExtensionHelpers helpers;
     private PrintWriter stdout;
    private PrintWriter stderr;
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        callbacks.setExtensionName("Vuln Scanner");
        callbacks.printOutput("Author: Sourav Kalal");
        callbacks.printOutput("Version 0.1");
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
        helpers = callbacks.getHelpers();
        
        lowHangingScanner = new Low_Hanging(callbacks,helpers);
        //criticalIssuesScanner = new CriticalIssues(callbacks);
        
         // Register scanner checks
        callbacks.registerScannerCheck(lowHangingScanner);
        //callbacks.registerScannerCheck(criticalIssuesScanner);
    }
}