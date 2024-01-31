package burp;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;
import java.awt.BorderLayout;
import javax.swing.WindowConstants;
import org.openqa.selenium.Dimension;
import burp.utility.Config;
import burp.vulnerabilities.Sessionvalidation;

public class Menueditor implements IContextMenuFactory {
    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;

    private Sessionvalidation session_validation;
   

    public Menueditor(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks; // Store the callbacks instance
        this.helpers = callbacks.getHelpers();
        
  
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        IHttpRequestResponse[] messages = invocation.getSelectedMessages();
    
        List<JMenuItem> menuItems = new ArrayList<>();
    
        JMenuItem customMenuItem = new JMenuItem("Validate Session Identifier");
        customMenuItem.addActionListener(e -> performCustomAction(messages));

        menuItems.add(customMenuItem);
      
    
        return menuItems;
    }

    private void performCustomAction(IHttpRequestResponse[] messages) {
        if (messages.length != 1) {
            // Display an alert or message indicating to select only one request
            JOptionPane.showMessageDialog(null, "Please select only one request for this action.", "Multiple Requests Selected", JOptionPane.WARNING_MESSAGE);
            return;
        }

        //Sessionvalidation sessionValidation = new Sessionvalidation();
        callbacks.printOutput("Checking cookie");
       // sessionValidation.processRequest(messages[0]);
       session_validation = new Sessionvalidation(callbacks, helpers);
       session_validation.processRequest(messages[0]);
    }
}
