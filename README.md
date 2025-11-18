# AccuKnox-Assessment-Report

## Vulnerability Findings

### 1.	HTML Injection (Reflected GET)

#### Description
The application fails to properly sanitize user-supplied input in the First Name field. When HTML tags such as:
`<a href="http://abc.com">click</a>` are submitted, they are rendered directly on the webpage without encoding. This allows an attacker to inject arbitrary HTML into the page, potentially modifying page content, embedding malicious links, or performing social engineering attacks. Because the injected payload is reflected back to the user immediately, this issue is categorized as Reflected HTML Injection. Although it does not execute JavaScript like XSS, it still enables content manipulation, phishing elements, malicious redirects, and UI deception.

#### Impact
Attackers can inject malicious links to trick users into clicking phishing or malware sites. Page content can be altered to mislead users or impersonate trusted elements. Can be used as a stepping stone toward more severe attacks if combined with other flaws.

#### Mitigation
Apply strict server-side validation and reject any input containing HTML tags. Encode all dynamic output (HTML escape <> characters before rendering). Implement a allowlist for accepted characters in user input fields.


<img width="983" height="458" alt="Screenshot From 2025-11-13 18-57-53" src="https://github.com/user-attachments/assets/6a96d11c-2525-4c4f-b948-8f80c0e5ac44" />



<img width="983" height="458" alt="Screenshot From 2025-11-13 18-58-09" src="https://github.com/user-attachments/assets/d256ef8e-9351-48bb-a81e-33b3c0c41feb" />


### 2.	Iframe Injection

#### Description 
By inserting the <iframe> injection payload inside the "ParamWidth" parameter it get reflected in the response showcasing the existence of <iframe> injection vuln.

#### Impact 
Injection of arbitrary HTML elements leads to potential execution of attacker-supplied JavaScript and defacement or manipulation of page structure. 

#### Mitigation 
Apply strict output encoding for values inserted into HTML attributes. Validate ParamWidth to only allow numeric characters. Reject or sanitize characters like <, >, ", ' also implement Content Security Policy (CSP) along side.

<img width="1903" height="764" alt="Screenshot From 2025-11-13 19-38-28" src="https://github.com/user-attachments/assets/c46736a0-7337-41d9-87ca-4a6bb7cdfed1" />


<img width="1903" height="764" alt="Screenshot From 2025-11-13 19-38-45" src="https://github.com/user-attachments/assets/c917feff-9fb5-4a39-b12d-579850614399" />


### 3.	Insecure Login

#### Description 
Upon entering and intercepting the response with Burp Suite the application is revealing the login credentials in the response. Which leads to information disclosure and anyone with the leaked valid credentials can login and takeover the account.

#### Impact 
Exposure of valid login credentials allows attackers to directly access and take over user accounts, potentially leading to full compromise of sensitive data and system functions.

#### Mitigation
Avoid sending credentials in responses, enforce strict server‑side validation and output sanitization, and ensure sensitive data is never included in client‑visible payloads.

<img width="1897" height="663" alt="Screenshot From 2025-11-13 19-45-30" src="https://github.com/user-attachments/assets/4f623113-e494-4db5-9391-74a74fa01647" />


### 4.	XXS Reflected (JSON)

#### Description 
Inserting js payload like <img src=x onerror=alert(document.cookie)> in the "search for a movie" field and clicking on search button pop up with the alert message long with the user cookies.

#### Impact
Executing injected JavaScript allows attackers to steal session cookies, impersonate users, and perform unauthorized actions within the application.

#### Mitigation
Implement strict server‑side input validation and output encoding, and enforce Content Security Policy (CSP) headers to prevent execution of untrusted scripts.

<img width="1918" height="566" alt="Screenshot From 2025-11-13 19-55-05" src="https://github.com/user-attachments/assets/4f72974c-22a3-4311-9aae-9ece4dee1bb0" />

<img width="1918" height="566" alt="Screenshot From 2025-11-13 19-55-25" src="https://github.com/user-attachments/assets/3828286e-ebbe-46dd-9724-c14ed5bd015e" />


### 5.	IDOR

#### Description 
The ticket price parameter can be manipulated on the client side, allowing a user to alter the amount paid before the purchase request is processed. This will cause huge financial loss to the business.

#### Impact
This leads to financial loss and abuse of the payment system, enabling unauthorized discounts or free ticket purchases.

#### Mitigation
Enforce strict server‑side validation of all pricing values and never rely on client‑side data for financial calculations or transaction approval.


<img width="1918" height="566" alt="Screenshot From 2025-11-13 20-08-29" src="https://github.com/user-attachments/assets/4d4aac8f-89cc-4d5a-8997-e10720e9420e" />


### 6.	Information Disclosure

#### Description 
Sensitive filenames such as backd00r.php are exposed and directly accessible, allowing anyone who knows or discovers the endpoint to view the information stored inside.

#### Impact
This can lead to unauthorized access, data leakage, or execution of sensitive functionality by attackers. 

#### Mitigation
Restrict direct access to sensitive files, use proper access controls, and avoid exposing or storing such endpoints in publicly accessible directories.

<img width="1188" height="464" alt="Screenshot From 2025-11-14 19-09-06" src="https://github.com/user-attachments/assets/a4bf58cd-208c-4d1e-b70c-90954e77fca4" />


### 7.	Directory Traversal (Directories)

#### Description
The application allows directory‑traversal characters in the directory parameter, enabling users to enumerate sensitive system folders outside the intended path, and discover the files stored in the respective directory.

#### Impact
This exposes internal server structure and sensitive directory names, aiding attackers in reconnaissance and create blueprint of further exploitation. 

#### Mitigation
Normalize and validate paths on the server side, restrict access to allowed directories only, and block traversal patterns like ../ through strict input filtering.

<img width="1578" height="765" alt="Screenshot From 2025-11-14 20-02-29" src="https://github.com/user-attachments/assets/75a714b3-a12b-4fab-a785-094b4ba9e190" />


### 8.	CSRF (Change Password)

#### Description 
As no CSRF token is present attacker can change any user password by manipulating them to click on malicious link or visiting malicious page.

#### Impact
Absence of a CSRF token allows attackers to trick users into unintentionally triggering password‑change requests, resulting in account takeover. 

#### Mitigation
Implement anti‑CSRF tokens, enforce same‑site cookies, and validate the origin of all sensitive state‑changing requests.

<img width="1578" height="765" alt="Screenshot From 2025-11-14 20-42-21" src="https://github.com/user-attachments/assets/93e45a50-ab41-4708-9b7b-4d5686cd7bc0" />


### 9.	HTTP Parameter Pollution

#### Description
Injecting `&movie=2` into the name field causes the server to process multiple "movie" parameters, resulting in parameter pollution that forces every vote to be cast for movie ID 2. 

#### Impact
This allows manipulation of voting results and undermines application integrity. 

#### Mitigation
Enforce strict server‑side parameter validation, reject duplicate parameters, and sanitize unexpected inputs before processing.


<img width="738" height="533" alt="Screenshot From 2025-11-17 18-11-20" src="https://github.com/user-attachments/assets/7adca41d-1694-4bd2-8fca-b84d1384718b" />


<img width="848" height="576" alt="Screenshot From 2025-11-17 18-11-47" src="https://github.com/user-attachments/assets/c1b9e08c-b3c0-4178-9c0e-4245e25cf00d" />


<img width="838" height="532" alt="Screenshot From 2025-11-17 18-12-03" src="https://github.com/user-attachments/assets/85074aa6-dd71-4899-8af4-bffddbd26b62" />


### 10.	Remote & Local File Inclusion

#### Description 
The "language" parameter accepts path‑traversal sequences, allowing an attacker to load arbitrary system files such as `/etc/passwd` and disclose their contents. 

#### Impact
This leads to severe information disclosure, enabling attackers to harvest system details and potentially escalate to full system compromise. 

#### Mitigation 
Strictly validate and whitelist allowed parameter values, block traversal patterns like `../`, and ensure the application never directly includes or reads files based on unsanitized user input.


<img width="991" height="763" alt="Screenshot From 2025-11-17 18-29-59" src="https://github.com/user-attachments/assets/a65d008c-e531-4f56-9b91-cd017dc6a00f" />



