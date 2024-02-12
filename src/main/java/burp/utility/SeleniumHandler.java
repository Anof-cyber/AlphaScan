package burp.utility;

import org.openqa.selenium.*;

public class SeleniumHandler {
    private WebDriver driver;

    public void setWebDriver(WebDriver driver) {
        this.driver = driver;
    }

    public String checkForAlerts(String responseBody) throws Exception {
        if (driver == null) {
            throw new Exception("WebDriver is not initialized");
        }

        try {
            openHtmlContent(responseBody);
            return checkAlert();
        } catch (NoAlertPresentException e) {
            throw new Exception("No alert found in the HTML content");
        }
    }

    private void openHtmlContent(String htmlContent) {
        driver.get("data:text/html;charset=utf-8," + htmlContent);
    }

    private String checkAlert() {
        Alert alert = driver.switchTo().alert();
        String alertText = alert.getText();
        alert.accept();
        return alertText;
    }
}
