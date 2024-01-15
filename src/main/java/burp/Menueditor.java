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
   

    public Menueditor(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks; // Store the callbacks instance
        this.helpers = callbacks.getHelpers();
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        IHttpRequestResponse[] messages = invocation.getSelectedMessages();
    
        List<JMenuItem> menuItems = new ArrayList<>();
    
        JMenu exploitMenu = new JMenu("Exploit");
    
        JMenuItem SSTIexploit = new JMenuItem("SSTI");
        SSTIexploit.addActionListener(e -> SSTIexploitAction(messages));
        exploitMenu.add(SSTIexploit);
    
        JMenuItem customMenuItem = new JMenuItem("Validate Session Identifier");
        customMenuItem.addActionListener(e -> performCustomAction(messages));
    
        menuItems.add(customMenuItem);
        menuItems.add(exploitMenu);
    
        return menuItems;
    }

    
private void SSTIexploitAction(IHttpRequestResponse[] messages) {
    // Create your custom dialog here
    final JDialog dialog = new JDialog();
    dialog.setTitle("SSTI Exploit");
    dialog.setModal(true);

    // Add components to the dialog
    JLabel label = new JLabel("Enter your input:");
    JTextField textField = new JTextField(20); // Sample text field
    JCheckBox checkBox = new JCheckBox("Enable Feature"); // Sample checkbox
    JButton startButton = new JButton("Start");

    startButton.addActionListener(e -> {
        // Retrieve data when the "Start" button is clicked
        String userInput = textField.getText(); // Retrieve text from the text field
        boolean featureEnabled = checkBox.isSelected(); // Retrieve checkbox state

        // Perform actions using retrieved data
        System.out.println("User input: " + userInput);
        System.out.println("Feature enabled: " + featureEnabled);

        // Perform other necessary actions or exploit logic here using the retrieved data

        dialog.dispose(); // Close the dialog after completing the action
    });

    JButton cancelButton = new JButton("Cancel");
    cancelButton.addActionListener(e -> dialog.dispose());

    JPanel contentPanel = new JPanel();
    //contentPanel.setLayout(new GridLayout(3, 1)); // Example layout, adjust as needed
    contentPanel.add(label);
    contentPanel.add(textField);
    contentPanel.add(checkBox);
    contentPanel.add(startButton);
    contentPanel.add(cancelButton);

    dialog.add(contentPanel);

    // Set other dialog properties and show the dialog
    dialog.pack();
    dialog.setVisible(true);
}

    

    private void performCustomAction(IHttpRequestResponse[] messages) {
        if (messages.length != 1) {
            // Display an alert or message indicating to select only one request
            JOptionPane.showMessageDialog(null, "Please select only one request for this action.", "Multiple Requests Selected", JOptionPane.WARNING_MESSAGE);
            return;
        }

    
        Sessionvalidation sessionValidation = new Sessionvalidation();
        sessionValidation.processRequest(messages[0]);

       

    
        // Only one request is selected, proceed with the logic for that request
        //IHttpRequestResponse message = messages[0];
        /*
        callbacks.addScanIssue(new RaiseVuln(
            message.getHttpService(),
            callbacks.getHelpers().analyzeRequest(message).getUrl(),
            new IHttpRequestResponse[] { message },
            "AlphaScan - Session Identifier Found",
            "The Session Identifier was successfully found in the request.",
            "Certain",
            "Information"
        ));
    
        callbacks.printOutput("context menu"); // Access callbacks properly
         */
    }


    


}
