# AlphaScan
A BurpSuite extension for vulnerability Scanning


### 🚧 Under Development 🚧

This project is currently under active development. Not all features are implemented, and the code may not be stable. While contributions are appreciated, please note that I am not currently accepting external contributions.


## Vulnerabilities



###### Version  1.0

| Vulnerability                   | Details                                                                                                             |
|--------------------------------|----------------------------------------------------------------------------------------------------------------------|
| Blind Time Based Injection     | [Payloads](https://github.com/CyberM0nster/SQL-Injection-Payload-List-/blob/master/Generic%20Time%20Based%20SQL%20Injection%20Payloads)                                  |
| AWS SSRF                       | [Payloads](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Request%20Forgery/README.md#ssrf-url-for-cloud-instances)                        |
| Reflected XSS                  | [Payloads](https://github.com/Proviesec/xss-payload-list/tree/main)                                                |
| Error Based SQL injection      | [Payload-src-github](https://github.com/payloadbox/sql-injection-payload-list) ([Payload-src-twitter](https://x.com/Fabrikat0r/status/1731784913572200720?)) ([Payload-src-twitter](https://twitter.com/intigriti/status/1727669826338914506)) |
| Missing CSP Header             |                                                                                                                      |
| CSP Header with Insecure Directives |                                                                                                                  |
| CSP Header Missing Required Directives |                                                                                                            |
| Missing X-Frame Header         |                                                                                                                      |
| Missing HSTS Header            |                                                                                                                      |
| Check If Request with Body support XML Content Type Header |   Partial/ Could be False Positive, will be updated later                                                                                               |
| Verify session cookie or token | Not Part of Active or Passive Scan, Need to be validated before starting a scan through right click menu on any request with a valid session (Not expired) |
| Forced Browsing | Experimental, likely to be false positive|
| Session Identifier (HTTP Only Flag) | Only Available if Session Identifier is found|
| Session Identifier (Secure Flag) | Only Available if Session Identifier is found|
| Error Messages| Passive Scanner for Error message or Server Banner|

<br>

