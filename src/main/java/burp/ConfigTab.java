package burp;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import burp.utility.Config;

public class ConfigTab extends javax.swing.JPanel {
    private javax.swing.JLabel chromedrive_label;
    private javax.swing.JButton chrome_drive_file_button;
    private javax.swing.JLabel jLabel1;
    private IBurpExtenderCallbacks callback; // Assuming callback is set elsewhere

    public ConfigTab(IBurpExtenderCallbacks callback) {
        this.callback = callback;
        initComponents();
        attachListeners();
    }

    private void initComponents() {
        chromedrive_label = new javax.swing.JLabel();
        chrome_drive_file_button = new javax.swing.JButton();
        jLabel1 = new javax.swing.JLabel();

        chromedrive_label.setForeground(new java.awt.Color(250, 142, 41));
        chromedrive_label.setText("Select ChromeDriver for XSS");

        chrome_drive_file_button.setText("Select");
        String storedChromeDriverPath = Config.getConfigValue("ChromeDriverPath");
        jLabel1.setText(storedChromeDriverPath);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(layout.createSequentialGroup()
                    .addContainerGap()
                    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addComponent(chromedrive_label)
                        .addComponent(chrome_drive_file_button)
                        .addComponent(jLabel1))
                    .addContainerGap(243, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(layout.createSequentialGroup()
                    .addContainerGap()
                    .addComponent(chromedrive_label)
                    .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                    .addComponent(chrome_drive_file_button)
                    .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                    .addComponent(jLabel1)
                    .addContainerGap(228, Short.MAX_VALUE))
        );
    }

    private void attachListeners() {
        chrome_drive_file_button.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                selectFile();
            }
        });
    }

    private void selectFile() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Select ChromeDriver");
        int userSelection = fileChooser.showOpenDialog(this);

        if (userSelection == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();
            if (selectedFile != null) {
                String filePath = selectedFile.getAbsolutePath();
                // Save the file path using callback.saveExtensionSetting
                Config.setConfigValue("ChromeDriverPath", filePath);
                callback.saveExtensionSetting("ChromeDriverPath", filePath);
                jLabel1.setText(filePath); 
                
            }
        }
    }
}
