## Links
1. https://nixhacker.com/malware-analysis-interview-questions-1/
2. https://nixhacker.com/malware-analysis-interview-questions-2/
3. https://nixhacker.com/malware-analysis-interview-questions-3/
4. https://nixhacker.com/malware-analysis-interview-questions-4/


## Q & A

[Q1] - Explain SSL Encryption
SSL(Secure Sockets Layer) is a technology create encrypted connections between Web Server and a Browser. This is used to maintain data privacy and to protect the information in online transactions.

[Q2] - What is the difference between VPN and VLAN?
both networking technologies used to improve security and organization

VPN → 
- Creates a secure, encrypted tunnel over a public or untrusted network (like the internet) to connect remote users or networks as if they were on a private network.
- Provides encryption (AES, RSA) and authentication to secure data over untrusted networks.
- Spans across **wide-area networks (WANs)**, connecting different locations over the internet.
- ex: An employee working from home securely accesses the company’s internal systems via an encrypted VPN connection.

VLAN → 
- Logically segments a physical network into multiple isolated broadcast domains within the same infrastructure.
- Provides isolation but no encryption (unless paired with other security measures).
- Operates within a **single local network (LAN)**, segmenting devices logically.
- ex: A university separates student, faculty, and guest traffic on the same physical network using VLANs.

[Q3] - Explain SQL injection types.
There are 3 types of SQL Injections. These are:
1. **In-band SQLi (Classical SQLi)**: If a SQL query is sent and a replied to over the same channel, we call these In-band SQLi. It is easier for attackers to exploit these compared to other SQLi categories.
2. **Inferential SQLi (Blind SQLi)**: SQL queries that receive a reply that cannot be seen are called Inferential SQLi. They are called Blind SQLi because the reply cannot be seen.
3. **Out-of-band SQLi**: If the reply to a SQL query is communicated over a different channel then this type of SQLi is called Out-of-band SQLi. For example, if the attacker is receiving replies to his SQL queries over the DNS this is called an out-of-band SQLi.

[Q4] - Explain XSS types.
There are 3 types of XSS. These are:
1. **Reflected XSS (Non-Persistent)**: It is a non-persistent XSS type that the XSS payload must contain in the request. It is the most common type of XSS.
2. **Stored XSS (Persistent)**: It is a type of XSS where the attacker can permanently upload the XSS payload to the web application. Compared to other types, the most dangerous type of XSS is Stored XSS.
3. **DOM Based XSS**: DOM Based XSS is an XSS attack wherein the attack payload is executed as a result of modifying the DOM “environment” in the victim’s browser used by the original client side script, so that the client side code runs in an “unexpected” manner. (OWASP)

[Q5] - What are differences between SSL and TLS?
SSL and TLS are **cryptographic protocols** that provide secure communication over a network (e.g., the internet). They ensure that data transmitted between a client (like your browser) and a server (like a website) is **encrypted, authenticated, and tamper-proof**.

SSL → 
Supports weak algorithms (RC4, MD5)
Slow and Mostly deprecated

TLS → 
Uses stronger algorithms (AES, SHA-256)
Fast and Modern standard (required for PCI compliance)

[Q6] - How would you handle network security in a company that allows employees to bring their own devices?
Handling network security in a BYOD (Bring Your Own Device) environment involves implementing policies for device usage, enforcing strong authentication and encryption, using **mobile device management (MDM)** solutions, and educating employees about security best practices. Regular monitoring and applying network segmentation to isolate personal devices can also enhance security.

[Q7] - How does malware achieve persistence on Windows?
Malware achieves persistence on Windows by using techniques such as modifying registry keys, creating scheduled tasks, or placing malicious files in startup folders. These methods ensure that the malware runs every time the system boots or a user logs in.

[Q8] - How SIEM Collects Data from Devices

| **Device Type**      | **Log Data Collected**                           | **Protocol/Method**              |
| -------------------- | ------------------------------------------------ | -------------------------------- |
| **Firewalls**        | Blocked/Allowed traffic, intrusion attempts      | Syslog, SNMP                     |
| **Windows Servers**  | Event logs (logins, file access, PowerShell)     | WMI, Windows Event Forwarding    |
| **Linux Servers**    | Auth logs, sudo commands, kernel events          | Syslog, Rsyslog                  |
| **Switches/Routers** | Traffic flows, ACL violations                    | **NetFlow, SNMP**                |
| **Endpoints (PCs)**  | Process execution, USB usage, malware alerts     | SIEM Agent (**EDR** integration) |
| **Cloud Services**   | Login attempts, API calls, configuration changes | **REST API** (AWS CloudTrail)    |
| **Email Servers**    | Spam, phishing attempts, login failures          | SMTP logs, IMAP/POP3             |

[Q9] - How SIEM Processes Collected Data

1. **Normalization** – Converts different log formats into a standard schema.
    - Example: Converting Cisco ASA logs and Windows Event IDs into a unified format.
2. **Correlation** – Links related events (e.g., failed login → brute-force attack).
3. **Alerting** – Triggers notifications for suspicious activity.
4. **Storage & Retention** – Logs are stored for compliance (e.g., GDPR, HIPAA).

[Q10] - Challenges in SIEM Data Collection

- **Volume & Noise** – Too many logs can overwhelm the SIEM.
- **Log Format Variations** – Different devices use different log structures.
- **Latency** – Delays in log forwarding can impact real-time detection.
- **Encrypted Traffic** – Some SIEMs struggle to inspect TLS-encrypted data.

[Q11] - How do you handle incidents involving data exfiltration?
Handling data exfiltration incidents involves quickly identifying the source and extent of the breach, **isolating** affected systems, and mitigating further data loss. **Investigating** the attack vector, **restoring** data from backups, and notifying relevant stakeholders are also crucial steps.

[Q12] - What is a security baseline?
A security baseline defines the **minimum security standards** and **configurations** required for systems and applications.

[Q13] - What is the difference between EDR and AV?

- **Antivirus (AV):**
    - Relies on **signature-based detection** (compares files to a database of known malware).
    - weak with **zero-day attacks** (previously unseen malware).
    - Can **quarantine or delete** infected files.
	- No real-time response to advanced attacks.
    - Examples: Windows Defender, McAfee, Norton.
    - Limited visibility (only looks at file hashes).
	- No centralized threat hunting.
	- Simple to deploy, often pre-installed (e.g., Windows Defender).
	- Minimal configuration required.
- **EDR:**
    - Uses **behavioral analysis, machine learning (ML), and heuristics** to detect suspicious activity.
    - Detects **fileless malware, living-off-the-land (LOLBin) attacks, and ransomware**.
    - Examples: CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne.
	- **Automated response**: Kills malicious processes, isolates infected devices.
	- **Forensic timeline**: Tracks attacker movements for investigation.
	- **Rollback features**: Can undo ransomware encryption.
	- **Continuous monitoring** of processes, registry changes, network connections.
	- **Threat hunting**: Security teams can search for hidden threats.
	- **Integration with SIEM/SOAR** for better correlation.
	- Requires **centralized management console**.
	- Often **cloud-based (SaaS)** for real-time updates.
	- Needs **security team expertise** for full effectiveness.

[Q14] - Can you walk me through the threat intelligence analysis process?
1. **Collect Data:** This is the first step in any threat intelligence analysis process. I need to collect data from various sources such as open-source intelligence, threat intelligence feeds, and reports. This data should be relevant to the organization's environment and business operations.
2. **Analyze data:** With the data collected, I will analyze it to identify potential threats. I will use various tools and techniques to identify patterns, anomalies, and suspicious activities. This includes the use of data visualization tools that can help in pattern recognition.
3. **Classification:** After analyzing the data, I will classify the threats into different categories to **prioritize** them. This classification may be based on the probability and impact of the threat on the organization's operations, assets, and reputation.
4. **Validation:** Before reporting the threats to the organization or management, I will **validate the accuracy**, reliability, and credibility of the information collected. This may involve verifying the source of the data and cross-checking it with other sources.
5. **Reporting and Recommendations:** Finally, I will prepare a detailed report that summarizes the findings of my analysis and provides recommendations on how to mitigate or eliminate the identified threats. This report may include technical details, such as indicators of compromise or attack signatures, and non-technical information, such as business impacts and financial losses.

[Q15] - How do you prioritize threats based on potential impact?
- Gathering information about the threat
- Assessing the **likelihood of an attack**
- Determining the **potential impact of threat**
- Assigning a risk score
- Communicating the risk to stakeholders

[Q16] - How do you prioritize threats?
 Prioritizing threats is a critical skill in CTI, requiring an assessment of the potential impact, urgency, and likelihood of each threat. I prioritize based on the severity of the impact on the organization’s critical assets and operations, the credibility of the threat intelligence, and the organization’s vulnerability to the specific threat. This approach ensures that resources are allocated effectively, focusing on the most significant threats first.

[Q17] - How do you prioritize and manage multiple threat intelligence reports?
"I prioritize threat intelligence reports based on the potential impact and likelihood of the threat. I use a risk matrix to categorize threats and focus on high-impact, high-likelihood threats first. For instance, during a recent surge in phishing attacks, I prioritized reports related to phishing over less immediate threats, ensuring our defenses were promptly strengthened."

[Q18] - Describe a time when you identified a false positive. How did you handle it?
 I **adjusted the monitoring tool’s parameters** to minimize similar occurrences in the future, enhancing the accuracy of our threat detection efforts.

[Q19] - What port number does ping use?
Ping uses ICMP so it doesn’t use any port 

[Q20] - Describe the steps in the digital forensic investigation process.

The digital forensic process typically follows these six stages :
- **Identification:** Recognize potential sources of digital evidence.
- **Preservation:** Ensure that the digital evidence is preserved in its original state. This is often done by **creating forensic images.**
- **Collection:** Gather data from various sources, such as hard drives, servers, and cloud storage, while ensuring that the evidence remains intact.
- **Examination:** Use forensic tools to sift through the data and identify relevant evidence.
- **Analysis:** Reconstruct events based on the evidence collected, and draw conclusions about what may have occurred.
- **Reporting:** Present the findings in a clear, detailed, and legally sound report suitable for court or internal investigations. This structured approach ensures thoroughness and prevents evidence tampering.

[Q21] - How do you ensure the integrity of digital evidence?
- **Chain of Custody
- **Forensic Imaging**
- **Hashing Algorithms**

[Q22] - What are anti-forensic techniques, and how do you counter them?
Anti-forensic techniques are methods cybercriminals use to obscure, destroy, or alter evidence to avoid detection. These techniques include:

- **File Encryption:** Criminals may encrypt data to prevent access to evidence.
- **Data Wiping:** Software is used to erase files and overwrite data permanently.
- **Steganography:** Hiding data within other files, such as images or videos, to make it undetectable.
- **Log Manipulation:** Modifying system logs to hide tracks.

[Q23] -  What is data mining?
Data mining is the process of recording as much data as possible **to create reports** and analysis on user input. For instance, you can mine data from various websites and then log user interactions with this data to evaluate which website areas are accessed by users when logged in.

[Q24] -  What is data carving?
Data carving is different than data mining in that data carving searches **through raw data on a hard drive without using a file system**. It allows a computer forensic investigator to recover a deleted file from a hard drive. Data carving is essential for computer forensics investigators to find data when a hard drive’s data is corrupted.


[Q25] - Explain the difference between OSI and TCP/IP model ?

 Key Differences Between OSI and TCP/IP Models:

|Feature|**OSI Model**|**TCP/IP Model**|
|---|---|---|
|**Origin**|Developed by **ISO** (International Organization for Standardization)|Evolved from **ARPANET**, adopted by the Internet|
|**Layers**|**7 layers** (Application, Presentation, Session, Transport, Network, Data Link, Physical)|**4 layers** (Application, Transport, Internet, Network Access)|
|**Approach**|**Theoretical** (designed as a reference model)|**Practical** (based on real-world implementation)|
|**Protocol Dependency**|**Protocol-independent** (generic framework)|**Protocol-dependent** (built around TCP, IP, UDP, etc.)|
|**Layer Functionality**|Strictly separates functions (e.g., Session & Presentation layers)|Combines functions (e.g., Application layer handles Session & Presentation)|
|**Usage**|Used for **understanding & troubleshooting** networks|Used in **real-world networking** (e.g., the Internet)|

 Key Takeaways:
1. **OSI is a 7-layer theoretical model**, while **TCP/IP is a 4-layer practical model**.
2. **TCP/IP combines OSI's Application, Presentation, and Session layers** into a single **Application layer**.
3. **TCP/IP's Internet layer ≈ OSI's Network layer** (both handle IP addressing & routing).
4. **TCP/IP is the foundation of the modern Internet**, while OSI is used mainly for **education and network design**.
5. **OSI is more detailed**, but **TCP/IP is more widely implemented**.

[Q26] - Which event logs are available default on Windows?
- Security
- Application
- System

[Q27] - Compare between Normal URLs (Surface Web), v2 Onion, and v3 Onion addresses

|Feature|**Normal Web URL** (e.g., `google.com`)|**v2 Onion Address** (e.g., `facebookcorewwwi.onion`)|**v3 Onion Address** (e.g., `facebookwkhpilnemxj7...onion`)|
|---|---|---|---|
|**Domain Format**|`.com`, `.org`, `.net`, etc.|`.onion` (16 chars)|`.onion` (56 chars)|
|**Readability**|Human-friendly (e.g., `youtube.com`)|Semi-readable (shorter random string)|Fully random (long hash)|
|**Accessibility**|Via any browser (Chrome, Firefox, etc.)|**Tor Browser only** (deprecated since 2021)|**Tor Browser only** (current standard)|
|**Encryption**|HTTPS (SSL/TLS)|SHA-1 + 1024-bit RSA (weak)|SHA-3 + 3072-bit RSA (strong)|
|**Anonymity**|Low (IP/logs trackable by ISPs & sites)|High (hidden service + user anonymity)|**Highest** (improved anti-censorship)|
|**DNS System**|Uses **DNS** (centralized, can be blocked)|**No DNS** (self-authenticating)|**No DNS** (decentralized, harder to block)|
|**Brute-Force Risk**|N/A (domains are registered, not hashed)|**High** (shorter hashes guessable)|**Near-zero** (56-char entropy)|
|**Phishing Risk**|High (fake domains like `g00gle.com`)|Medium (harder to spoof than clearnet)|**Very low** (cannot fake cryptographic hash)|
|**Example Use Cases**|Everyday browsing, social media, shopping|Old dark web markets (pre-2021)|Privacy tools (SecureDrop, ProtonMail Tor mirror)|

```
Normal URL:  https://www.wikipedia.org  
v2 Onion:    http://facebookcorewwwi.onion (DEAD)  
v3 Onion:    http://facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion  
```


[Q28] -  **How do you ensure the integrity of digital evidence?**
- Use cryptographic **hashes** (like MD5 or SHA-256) to verify that the forensic image matches the original data.
- **Forensic Imaging:** Create an exact bit-by-bit copy of the original data
- Record every step in **Chain of Custody**

[Q29] -  What is a WAF, and how does it differ from a traditional firewall?

A Web Application Firewall (WAF) protects web apps by filtering and monitoring HTTP/HTTPS traffic for attacks like SQLi, XSS, and API abuse. Unlike traditional firewalls (which operate at Layers 3/4), WAFs work at Layer 7 (application layer) and understand web protocols (e.g., HTTP headers, JSON, cookies).


[Q30] -  **How would you investigate a WAF alert for a potential SQL injection attempt?**  

1. **Review WAF logs**: Extract the payload (e.g., `' OR 1=1--`), source IP, and user-agent.
2. **Verify blocking**: Check if the WAF blocked the request (HTTP 403) or if it reached the server.
3. **Correlate with other logs**: Look for repeated attempts or other suspicious activity from the same IP.
4. **Escalate**: If the attack succeeded, notify the app team for patching.

[Q31] - **How can attackers bypass a WAF?**  

- **Obfuscation**: Encoding payloads (e.g., `%3Cscript%3E` for `<script>`).
- **HTTP Parameter Pollution**: Sending duplicate parameters (`?id=1&id=1'--`).
- **Slowloris DDoS**: Slow HTTP requests to exhaust WAF resources.
- **Zero-days**: Exploiting unknown vulnerabilities not covered by WAF rules.


[Q32] - **You see 100+ WAF alerts for XSS from one IP. What’s your action plan?**  

1. **Triage**: Confirm if payloads are malicious (e.g., `<script>alert()`).
2. **Block**: Add the IP to the WAF deny list or network firewall.
3. **Investigate**: Check if any requests bypassed the WAF (server logs).
4. **Report**: Document the incident and share IoCs (Indicators of Compromise) with the team.

[Q33] - Difference Between DDoS (Layer 3 vs. Layer 7)

|**Aspect**|**Layer 3/4 DDoS** (Network/Transport)|**Layer 7 DDoS** (Application)|
|---|---|---|
|**Target**|Overwhelms bandwidth/network resources.|Exhausts application resources (e.g., HTTP/S requests).|
|**Examples**|SYN floods, UDP reflection, ICMP floods.|HTTP floods, Slowloris, GET/POST attacks.|
|**Detection**|High traffic volume, packet rate anomalies.|Abnormal request patterns (e.g., many `/login` requests).|
|**Mitigation**|Rate limiting, blackholing, scrubbing.|WAF rules, CAPTCHA, bot detection.|
|**Complexity**|Easier to detect (volume-based).|Harder to detect (mimics legitimate traffic).|

[Q34] - How to Write Correlation Rules ?

**Purpose**: Combine multiple events to detect complex threats (e.g., brute force, lateral movement).
Mention **false positive reduction** (e.g., whitelist trusted IPs).
**Steps to Write a Rule** (e.g., in Splunk/QRadar):
1. **Define the Threat**:
    - Example: *"Detect 5+ failed logins followed by a success from the same IP."*
2. **Identify Data Sources**:
    - Windows Event Logs (Event ID 4625 for failures, 4624 for success).
    - Firewall/SIEM logs.
3. **Write the Logic** (Pseudocode):
```
	WHEN (EventID=4625 AND Status="Failure") 
	WITH same IP 
	FOLLOWED BY (EventID=4624 AND Status="Success") 
	WITHIN 10 minutes 
	COUNT > 5 
	THEN ALERT "Potential Brute Force Attack"
```
1. **Test & Tune**:
    - Run in **log-only mode** to check false positives.
    - Adjust thresholds (e.g., change `COUNT > 5` to `COUNT > 10`).

**Example Correlation Rules**
- **Port Scanning**: `Multiple TCP SYN packets to different ports from one IP`.
- **Data Exfiltration**: `Large outbound transfer + connection to a known C2 server`.


[Q35] - **How to Investigate "100 Failed Logins in 5 Mins"**

**SOC Investigation Steps**:
1. **Triage the Alert**:
    - Check SIEM/WAF logs for:
        - Source IP, usernames targeted, timestamps.
        - Geolocation (e.g., unexpected country).
2. **Determine Legitimacy**:
    - **False Positive?**:
        - Is it a load balancer/misconfigured app?
        - Check user-agent (e.g., legitimate crawlers like Googlebot).
    - **Real Attack?**:
        - Payloads (e.g., `admin'--` in username field = SQLi attempt).
3. **Containment**:
    - **Short-term**: Block the IP at firewall/WAF.
    - **Long-term**: Implement rate limiting or CAPTCHA.
4. **Deep Dive**:
    - **Correlate with Other Logs**:
        - Any successful login after failures? (Check Event ID 4624).
        - Unusual activity from the same IP (e.g., port scans).
    - **Enrich Data**:
        - Threat intel feeds (Is the IP known malicious?).
5. **Escalate & Document**:
    - If credentials were compromised: Force password resets.
    - Add IoCs (IP, timestamps) to threat intelligence database.

[Q36] - Why Save Emails as .eml or .msg?

Purpose :
Saving emails in **`.eml` (MIME format)** or **`.msg` (Outlook format)** preserves the **complete email structure**, including:
- **Headers** (critical for tracing sender/IP).
- **Attachments** (for malware analysis).
- **Metadata** (timestamps, routing info).

[Q37] - **What Are DKIM, SPF & DMARC Used For?**

These **email authentication protocols** prevent spoofing/phishing by verifying sender legitimacy.

 **SPF (Sender Policy Framework)**
- **Purpose**: Validates the sender’s IP against a list of authorized mail servers.
- **How It Works**:
    - The domain owner publishes SPF records in DNS (e.g., `v=spf1 include:_spf.google.com ~all`).
    - Recipient servers check if the email’s source IP matches the SPF record.
- **Limitation**: Doesn’t protect against header spoofing (e.g., fake `From:` addresses).

 **DKIM (DomainKeys Identified Mail)**
- **Purpose**: Ensures email integrity via cryptographic signatures.
- **How It Works**:
    - The sender’s server signs the email with a private key.
    - The recipient verifies the signature using the sender’s public key (published in DNS).
- **Key Benefit**: Detects tampering (e.g., altered body/headers).
    

 **DMARC (Domain-based Message Authentication, Reporting & Conformance)**
- **Purpose**: Defines policies for handling emails that fail SPF/DKIM.
- **How It Works**:
    - Domain owners publish DMARC policies in DNS (e.g., `p=quarantine` or `p=reject`).
    - Recipient servers enforce the policy (e.g., reject/quarantine failing emails).
    - Sends reports back to the domain owner about spoofing attempts.

**Example Flow**
1. **SPF Check**: Is the sending IP authorized?
2. **DKIM Check**: Is the email untampered?
3. **DMARC Action**: If both fail, reject/quarantine the email.


[Q38] - Important Windows Events Every SOC Analyst Should Know

- **100**: Scheduled task started
- **104**: System, Security, and Application log file cleared
- **106**: New scheduled task created
- **1102**: Audit log cleared
- **4104**: Command line auditing for PowerShell
- **4624**: Successful logon
- **4625**: Failed logon
- **4634**: Logoff events
- **4647**: User-initiated logoff
- **4648**: User used explicit credentials for login (Run as)
- **4663**: Files or folders accessed (sensitive files)
- **4672**: Special privileges assigned to a user (e.g., Admin login)
- **4688**: A new process was created
- **4698**: New scheduled task was created
- **4720**: New user account created
- **4722**: Account was enabled (previously disabled)
- **4723/4724**: Password changes or reset attempts
- **4768**: Kerberos TGT ticket requested
- **4769**: Kerberos service ticket requested
- **4771**: Kerberos pre-authentication failed
- **4776**: Domain controller attempted to validate credentials
- **4798**: User’s local group membership was enumerated
- **4799**: Security-enabled local group membership was enumerated
- **4946/4947**: New inbound/outbound firewall rules added
- **5140**: Network share object was accessed
- **5145**: Network share object access checked for permissions
- **7045**: New service installed
- **1116**: Malware detected in system
- **1117**: Protection action taken on malware


[Q39] - **Windows Search order for DLLs**

1. Side-by-Side Components
2. KnownDLLs list “registry”
3. Application Directory
4. C:\Windows\System32
5. C:\Windows\system
6. C:\Windows
7. Application’s registered App Paths directories
8. System PATH


[Q40] - What is most common persistence methods : 
- Registry Modifications (add malicious entries to Windows Registry auto-start locations) 
	- `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run`
	- `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`
- Creating a scheduled task
-  Startup Folder (placing a malicious shortcut or executable in Startup Folder)
	- `%AppData%\Microsoft\Windows\Start Menu\Programs\Startup`
	- `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup`
- Service Installation (Creating a malicious service that runs at boot)
- SSH Key Addition (Adding attacker’s public key to `~/.ssh/authorized_keys` for password-less login)
- Cron Jobs (Adding malicious cron jobs for repeated execution)
- DLL Hijacking (Replacing a legitimate DLL with a malicious one that loads into a trusted process)
- Browser Extensions (Installing malicious browser extensions that run at startup)
- Fileless Persistence (Using PowerShell, macros, or in-memory techniques to avoid disk writes)

[Q41] - Compare between Sigma Rules and yara rules
Sigma Rules and YARA Rules are both used in threat detection and analysis, but they serve different purposes and operate in distinct ways.

| Feature                | Sigma Rules                                                               | YARA Rules                                                                         |
| ---------------------- | ------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| **Primary Use Case**   | Detection of security events (logs, SIEM alerts)                          | Malware identification and classification (file-based)                             |
| **Target Data**        | Log files (e.g., Windows Event Logs, Sysmon, firewall logs)               | Files (executables, documents, memory dumps)                                       |
| **Syntax**             | YAML-based                                                                | Custom rule language (text-based)                                                  |
| **Detection Approach** | Pattern matching on log fields (e.g., process names, command lines)       | Pattern matching on byte sequences, strings, and binary signatures                 |
| **Flexibility**        | Focused on structured log data, supports aggregations                     | More low-level, supports binary patterns, regex, and condition-based matching      |
| **Tooling**            | Used with SIEMs (Splunk, Elasticsearch, Sigma-compatible tools)           | Used with malware analysis tools (YARA scanner, VirusTotal, IDA Pro)               |
| **Rule Sharing**       | Widely shared for threat detection in SOC environments                    | Commonly used in malware research and threat intelligence                          |
| **Example Use**        | Detecting suspicious PowerShell commands in Windows logs                  | Identifying a malware family by its unique strings or binary patterns              |
| **Strengths**          | - Easy to write for log-based detection  <br>- Integrates well with SIEMs | - Powerful for file/memory analysis  <br>- Highly customizable for malware hunting |
| **Limitations**        | - Limited to log data  <br>- Less effective for binary analysis           | - Not designed for log parsing  <br>- Requires file access for scanning            |

[Q42] - what is Unified Kill Chain ?

The **Unified Kill Chain (UKC)** is a cybersecurity framework that combines and extends concepts from the **Cyber Kill Chain®** (by Lockheed Martin) and the **MITRE ATT&CK®** matrix to provide a more comprehensive model for understanding and defending against cyber threats. It was developed by Paul Pols of Fox-IT (part of NCC Group) to address gaps in existing models and improve threat analysis, detection, and response.

### **Key Features of the Unified Kill Chain:**
1. **Integrates Multiple Models:**  
   - Combines the **Cyber Kill Chain’s** linear attack progression with **MITRE ATT&CK’s** detailed tactics and techniques.
   - Adds additional phases to cover modern attack methods (e.g., initial access, lateral movement, and actions on objectives).

2. **18 Distinct Attack Phases:**  
   Unlike the traditional 7-step Cyber Kill Chain, the UKC breaks down attacks into **18 phases**, grouped into three broader categories:
   - **Initial Foothold (Preparation & Delivery)**  
     - Reconnaissance  
     - Weaponization  
     - Delivery  
     - Social Engineering  
     - Exploitation  
     - Persistence  
   - **Network Propagation (Lateral Movement & Privilege Escalation)**  
     - Internal Recon  
     - Privilege Escalation  
     - Defense Evasion  
     - Lateral Movement  
     - Collection  
   - **Action on Objectives (Execution & Exfiltration)**  
     - Command & Control  
     - Execution  
     - Data Exfiltration  
     - Destruction  
     - Misinformation  
     - Monetization  

3. **Focus on Defensive Strategies:**  
   - Helps security teams **map attacker behaviors** to defensive actions (e.g., detection, prevention, mitigation).  
   - Encourages **"breaking the chain"** at multiple points to disrupt attacks early.  

4. **Aligns with MITRE ATT&CK:**  
   - Each UKC phase can be mapped to **MITRE ATT&CK tactics & techniques**, making it useful for threat intelligence and detection engineering.  

[Q43] - **Why is the Unified Kill Chain Useful?**
- Provides a **more granular view** of attack lifecycles than the traditional Cyber Kill Chain. 
- Helps defenders **identify weak points** in security posture.  
- Supports **red teaming, penetration testing, and incident response** by modeling real-world attack paths.  
- Bridges the gap between **strategic (high-level kill chain) and tactical (MITRE ATT&CK techniques)** cybersecurity planning.  

### **Comparison with Other Models:**
| Model | Focus | Phases | Use Case |
|--------|--------|--------|----------|
| **Cyber Kill Chain** | Linear attack stages | 7 phases | High-level attack analysis |
| **MITRE ATT&CK** | Tactics & Techniques | 14 tactics, 200+ techniques | Detailed threat detection & response |
| **Unified Kill Chain** | Hybrid approach | 18 phases | Combines strategic & tactical defense |



[Q44] - Compare between IDS and HIDS

| Feature                   | **IDS (Intrusion Detection System)**                                                                      | **HIDS (Host-Based Intrusion Detection System)**                                                                                             |
| ------------------------- | --------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| **Scope**                 | Monitors **network traffic** for suspicious activity.                                                     | Monitors **individual host/endpoint** activities (files, processes, logs).                                                                   |
| **Deployment**            | Network-based (NIDS) or host-based (HIDS).                                                                | Installed **directly on endpoints** (servers, workstations).                                                                                 |
| **Detection Focus**       | - Network attacks (DDoS, port scans, malware C2 traffic).  <br>- Anomalies in traffic patterns.           | - File integrity changes (malware, rootkits).  <br>- Suspicious process activity.  <br>- Log analysis (failed logins, privilege escalation). |
| **Data Sources**          | - Packet captures (PCAP).  <br>- Flow data (NetFlow, sFlow).                                              | - System logs (Windows Event Log, Syslog).  <br>- File system changes.  <br>- Running processes.                                             |
| **Detection Methods**     | - Signature-based (known attack patterns).  <br>- Anomaly-based (behavioral analysis).                    | - File integrity monitoring (FIM).  <br>- Log correlation.  <br>- Behavioral analysis (unusual process execution).                           |
| **Response Capabilities** | Typically **passive** (alerts only).  <br>Some can integrate with firewalls for blocking (IPS).           | Can **block malicious processes**, quarantine files, or trigger automated responses.                                                         |
| **Examples**              | - Snort (NIDS).  <br>- Suricata.  <br>- Zeek (Bro).                                                       | - OSSEC.  <br>- Wazuh.  <br>- Tripwire.                                                                                                      |
| **Strengths**             | - Broad visibility across the network.  <br>- Effective against external threats.                         | - Deep visibility into host activities.  <br>- Detects insider threats and file tampering.                                                   |
| **Limitations**           | - Cannot inspect encrypted traffic without decryption.  <br>- Limited visibility into host-level attacks. | - Resource-intensive (CPU/memory usage).  <br>- Requires proper endpoint deployment.                                                         |


[Q45] - Compare between HIPS and EDR

| Feature                   | **HIPS (Host-Based IPS)**                                                       | **EDR (Endpoint Detection & Response)**                                                        |
| ------------------------- | ------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| **Primary Purpose**       | Prevents attacks by blocking malicious activity in real-time.                   | Detects, investigates, and responds to advanced threats.                                       |
| **Detection Method**      | - Signature-based  <br>- Behavior-based (heuristics)  <br>- Rule-based policies | - Behavioral analytics  <br>- Machine learning (ML)  <br>- Threat intelligence correlation     |
| **Response Capabilities** | - Blocks/terminates malicious processes  <br>- Prevents unauthorized changes    | - Automated response (quarantine, kill process)  <br>- Forensic analysis  <br>- Threat hunting |
| **Scope**                 | Focuses on **preventing** known and some unknown threats.                       | Focuses on **detecting, analyzing, and remediating** advanced threats.                         |
| **Data Collected**        | - Process activity  <br>- File/registry changes  <br>- Network connections      | - Process execution chains  <br>- Memory analysis  <br>- User behavior analytics (UEBA)        |
| **Forensic Capabilities** | Limited (logs basic events).                                                    | Extensive (timeline analysis, attack reconstruction).                                          |
| **Integration**           | Often standalone or part of traditional antivirus.                              | Integrates with SIEM, SOAR, and threat intelligence platforms.                                 |
| **Threat Intelligence**   | Relies on predefined rules/signatures.                                          | Uses real-time threat feeds and AI-driven analysis.                                            |
| **Examples**              | - Symantec HIPS  <br>- McAfee HIPS                                              | - CrowdStrike Falcon  <br>- Microsoft Defender for Endpoint  <br>- SentinelOne                 |


[Q46] - **How XDR Differs from EDR & SIEM**

|Feature|**EDR**|**SIEM**|**XDR**|
|---|---|---|---|
|**Scope**|Endpoints only|Log aggregation (no response)|**Multi-layered** (endpoints, network, cloud, email)|
|**Detection**|Endpoint-focused|Rule-based (logs)|**AI-driven, cross-domain correlation**|
|**Response**|Automated on endpoints|Manual (alerts only)|**Automated across all layers**|
|**Threat Hunting**|Limited to endpoints|Limited (depends on logs)|**Built-in proactive hunting**|
|**Use Case**|Advanced malware protection|Compliance & log management|**Holistic security operations**|

[Q47] - say some of Unencrypted Port and its Encrypted Port

| **Protocol** | **Unencrypted Port**             | **Encrypted Port**         |
| ------------ | -------------------------------- | -------------------------- |
| **FTP**      | 20 (Data) / 21 (Command Control) | 989 (Data) / 990 (Control) |
| **SMTP**     | 25                               | 465                        |
| **HTTP**     | 80                               | 443                        |
| **POP3**     | 110                              | 995                        |
| **NNTP**     | 119                              | 563                        |
| **IMAP**     | 143                              | 993                        |
| **Telnet**   | 23                               | SSH/SCP/SFTP (22)          |
| **DNS**      | 53                               | -                          |
| **NTP**      | 123                              | -                          |


[Q48] - What do you have in your home network?

I set up a very strong user name and password for my router and Wi-Fi, its broadcasting feature is disabled. I set up MAC address filtering on the router and I use WPA2 (Wi-Fi protected access 2) security encryption technology. It encrypts the traffic on wi-fi networks. I disabled the remote access feature. I use a firewall and configure its security measures and it is always on.


[Q49] - How **Pass the Hash** Works

1- the attacker extracts password hashes stored in memory or on the disk using tools like :
- Mimikatz: Extracts credentials and hashes from Windows systems.
- pwdump: Dumps password hashes from the SAM database.
- LSASS Process Dumping: Hashes can be obtained from the Local Security Authority Subsystem Service (LSASS) process.

2- The attacker uses the stolen hash to authenticate on other systems. Instead of cracking the hash, they "pass" it directly to establish a session. Tools like pth-winexe , pth-rpcclient , or PowerShell scripts

[Q51] - How **Kerberos Authentication** Works

Kerberos uses tickets to authenticate users securely without transmitting passwords over the network. The key components include:
- Key Distribution Center (KDC): Issues tickets.
- Ticket Granting Ticket (TGT): Allows the user to obtain session-specific tickets for services.
- Service Ticket (ST): Grants access to specific resources like file shares or databases.
When a user logs in:
- The user authenticates with the KDC to get a TGT.
- The TGT is used to request Service Tickets for accessing specific services.


[Q50] - How **Pass the Ticket** Works

1- The attacker dumps Kerberos tickets from the system's memory. Tools like Mimikatz are commonly used. Tickets are stored in the LSASS process and can be extracted directly.

2- The attacker uses the stolen ticket(s) to impersonate the victim user or access network resources. TGTs are particularly valuable because they can be used to request new Service Tickets.

[Q51] - How Overpass-the-Hash Works

This attack takes advantage of the compatibility between NTLM and Kerberos authentication protocols, It enables attackers to leverage an NTLM hash to request a Kerberos ticket for authentication in an Active Directory (AD) environment.

1- Capturing credentials (NTLM hash) via tools like Mimikatz or dumping them from memory.
2- Using tools like Mimikatz, the attacker injects the NTLM hash into the Kerberos authentication process. This requests a Ticket-Granting Ticket (TGT) from the Key Distribution Center (KDC) without needing the plaintext password.
3-The attacker uses the TGT to obtain Service Tickets (STs) for accessing specific services (e.g., file shares, databases) in the domain.


[Q52] - Password Extraction in Active Directory Environments

1. Dumping Password Hashes from the Domain Controller (NTDS.dit)
	- The NTDS.dit file stores all user password hashes in an AD environment. Attackers target this file to extract credentials
2. Extracting Credentials from LSASS (Local Security Authority Subsystem Service)
	- LSASS stores user credentials in memory during an active session. Attackers dump LSASS to extract passwords and hashes.
3. Extracting Passwords from Group Policy Preferences (GPP)
	- Older versions of Windows allowed storing plaintext passwords in Group Policy Preferences (GPP) XML files.
4. Kerberoasting
	- Kerberoasting targets accounts with Service Principal Names (SPNs) by requesting Kerberos tickets and cracking them offline.
5. Pass-the-Hash (PtH)
6. Pass-the-Ticket (PtT)
7. Overpass-the-Hash
8. DCSync Attack
	- The DCSync attack allows attackers to simulate the behavior of a domain controller and request password hashes from other DCs.
9. Credential Harvesting from Memory
	- Dumping memory of processes (like browsers, RDP clients, or email clients) to extract credentials.
10. SAM and SYSTEM File Extraction
	- (SAM) file stores local account hashes. Attackers extract it to dump local hashes.
11. LLMNR/NBT-NS Poisoning
	- Exploiting network protocols to capture NTLM hashes during authentication requests.
12. Password Spraying
	- Brute-forcing common passwords against multiple accounts to avoid lockouts
13. Brute-Force Password Attacks
	- Targeting domain accounts with tools like Hydra or CrackMapExec


[Q53] - What is the Shim Cache?
1. designed to store information about executable files that have been run on a system.
	1. It stores metadata about applications that were executed
2. stored in the registry
	1. `HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\ShimCache`

[Q54] - What is the AM Cache?
1. can be found in the Windows registry or in specific file system locations under `%WINDIR%\\System32\\config\\`
2. It holds information regarding applications installed on the machine, tracking their installation and execution details. This can include versioning, patching, and metadata about software components that have been installed.

[Q55] - common data exfiltration techniques :

- DNS Tunneling – Data hidden in DNS queries.
- HTTPS Exfiltration – Data smuggled through encrypted web traffic.
- FTP/SFTP Uploads – Files sent to attacker-controlled servers.
- Cloud Storage Abuse – Data synced to Dropbox, Google Drive, etc.
- Webhooks/API Abuse – Data sent via legitimate APIs (Slack, Discord).
- ICMP Tunneling – Data hidden in ping packets.
- USB Exfiltration – Physical theft via USB drives.
- Email Exfiltration – Sensitive data sent as email attachments.
- RDP Clipboard Abuse – Copy-paste data over Remote Desktop
- TOR/Proxies – Data routed through anonymity networks.

[Q56] - what is Virtual Address Descriptor (VAD) tree

that tracks memory sections allocated to each process, including heap, stack, and memory-mapped files.
Analyzing the VAD tree helps in identifying hidden memory regions and injecting code in forensic investigations.