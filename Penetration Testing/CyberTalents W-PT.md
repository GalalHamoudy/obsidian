## What is SSRF? 

Server Side Request Forgery is a web vulnerability that 
- allows the attacker to interact with the internal infrastructure of the target which is not accessible from outside the target network.
- can cause unauthorized actions or access to sensitive data. In some cases, it can lead to arbitrary command execution (RCE).

## SSRF Types

#### Basic SSRF
The attacker is able to fetch the full response of an internal/external resource (File, HTTP, etc)
#### Blind SSRF
Blind SSRF is harder to exploit. The request is successfully sent but no response is returned to the attacker.

PHP functions that can lead to SSRF:

- fopen()
- fread()
- fsockopen()
- curl_exec()
- file_get_contents()

## Mitigation
There is no perfect way to protect against SSRF but there are some approaches that can be taken into account.

- Make a whitelist for the IPs that the web application needs to access.
- Disable unnecessary URL schemes (ex: dict:// , file:// , ftp:// ,etc).
- Use authentication for the internal resources/services.
## Tools

- [SSRFmap](https://github.com/swisskyrepo/SSRFmap): Automatic SSRF fuzzer and exploitation tool.  
- [Gopherus](https://github.com/tarunkant/Gopherus) : This tool generates gopher link for exploiting SSRF and gaining RCE in various servers.

--------------------------------------
## What is RCE?

RCE or Remote Code Execution is a vulnerability that allows the attacker to run arbitrary code on the hosting server by sending OS commands or even a malicious code which will be executed by the server that finally would lead him to fully compromise the server resources.

There are two types: code injection and command injection. The main difference between both is that the code injection depends on the capabilities of the used programming language.

## Tools

- [Burp Suite vulnerability scanner](https://portswigger.net/burp/vulnerability-scanner)
- [commix](https://github.com/commixproject/commix)

----------------
## What is XXE? 

XXE injection attack also known as XML External Entity attack is a type of attack that is concerned with exploiting the vulnerable XML parsers in the web applications.

We can force the web application that is vulnerable to XXE to read /dev/random or /dev/urandom which will block the users from accessing the website by repeating multiple requests.

## Mitigation 

- Validating user-input .
- Disable DTD e.g in PHP the following code snippet should be set when using the default PHP XML parser in order to prevent XXE.

## Tools

- Acunetix [vulnerability scanner](https://www.acunetix.com/vulnerability-scanner/)
- wfuzz: [XML Injection Fuzz Strings](https://github.com/xmendez/wfuzz/blob/master/wordlist/Injections/XML.txt)
------------
## What is Remote File Inclusion?

Remote File Inclusion is a vulnerability that occurs when the web application allows the user to submit input into files or upload files to the server. In some cases, the attacker is able to run arbitrary code on the server.

## Tools

- [Fimap](https://tools.kali.org/web-applications/fimap) : python tool which can find LFI/RFI in web apps.
----------
## What is Local File Inclusion? 

Local File Inclusion is a vulnerability that occurs when the web application allows the user to submit input into files or upload files to the server. In some cases, the attacker is able to run arbitrary code on the server.

---
## What is Unrestricted File Upload?  

File upload vulnerability is a common security issue in most web applications that have a file upload feature without any security validation against the uploaded files.

---------
## What is SQL Injection? 

SQL Injection is a web security vulnerability in which the attacker is injecting malicious SQL queries into an SQL statement within the vulnerable web application.

Here is some example of a DBMS:

- Mysql
- SQLite
- PostgreSQL
- Oracle 
- MSSQL

SQL injection can be divided into three categories:

- In-band SQLi
- Blind SQLi
- Out-of-band SQLi

#### In-band SQLi

It is one of the most common types in which the attacker uses the same communication channel to initiate his attack.

This category has two techniques:

- Error-based SQLi
- Union-based SQLi

#### Blind SQLi

In this type, the attacker sends his injection payload to the web application and observes the response and behavior of the application server; it is called blind because the data is not returned back from the database to the attacker.

This category has two techniques:
- Boolean-based SQLi
- Time-based SQLi


#### Out-of-band SQLi

This type of SQLi occurs when the attacker can’t use the channel to launch his attack and it relies on features enabled on the database server. 

For example, the attacker would use the ability of the database to make a DNS / HTTP request to a server controlled by him.

---
## What is XSS? 

XSS or Cross-site Scripting is a client-side attack where malicious scripts are injected into the web application and executed by loading it through the web browser, this vulnerability occurs in the web application where the user input is not validated and sanitized.
## XSS Types

There are three main types of XSS:

- Reflected XSS
- Stored XSS
- DOM-based XSS

#### Reflected XSS

The reflected XSS is one of the common types in which the injected payload is returned to the vulnerable page immediately and executed by the web browser.

#### Stored XSS

Is the dangerous type where the injected payload is stored and displayed later when it is retrieved, it can be stored in the database, cookies, or session data, and when retrieved and viewed it will be executed.

#### DOM XSS

DOM-based XSS is a type of cross-site scripting vulnerability where the attack payload is executed as a result of modifying the Document Object Model (DOM) environment in the victim's browser, without any malicious content being sent to the server.


---
## What is CSRF?

CSRF or Cross-Site Request Forgery is a web vulnerability that allows the attacker to force the website user to make unintended actions. e.g: transfer money, change account password or phone number. It is also known as a one-click attack or session riding.