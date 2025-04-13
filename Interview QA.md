[Q1] - Explain SSL Encryption
SSL(Secure Sockets Layer) is a technology create encrypted connections between Web Server and a Browser. This is used to maintain data privacy and to protect the information in online transactions.

[Q2] - What is the difference between VPN and VLAN?
both networking technologies used to improve security and organization

VPN → 
- Creates a secure, encrypted tunnel over a public or untrusted network (like the internet) to connect remote users or networks as if they were on a private network.
- Provides encryption (AES, RSA) and authentication to secure data over untrusted networks.
- Spans across **wide-area networks (WANs)**, connecting different locations over the internet.
- An employee working from home securely accesses the company’s internal systems via an encrypted VPN connection.

VLAN → 
- Logically segments a physical network into multiple isolated broadcast domains within the same infrastructure.
- Provides isolation but no encryption (unless paired with other security measures).
- Operates within a **single local network (LAN)**, segmenting devices logically.
- A university separates student, faculty, and guest traffic on the same physical network using VLANs.

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
Handling network security in a BYOD (Bring Your Own Device) environment involves implementing policies for device usage, enforcing strong authentication and encryption, using mobile device management (MDM) solutions, and educating employees about security best practices. Regular monitoring and applying network segmentation to isolate personal devices can also enhance security.

[Q7] - How does malware achieve persistence on Windows?
Malware achieves persistence on Windows by using techniques such as modifying registry keys, creating scheduled tasks, or placing malicious files in startup folders. These methods ensure that the malware runs every time the system boots or a user logs in.

[Q8] - How SIEM Collects Data from Devices

|**Device Type**|**Log Data Collected**|**Protocol/Method**|
|---|---|---|
|**Firewalls**|Blocked/Allowed traffic, intrusion attempts|Syslog, SNMP|
|**Windows Servers**|Event logs (logins, file access, PowerShell)|WMI, Windows Event Forwarding|
|**Linux Servers**|Auth logs, sudo commands, kernel events|Syslog, Rsyslog|
|**Switches/Routers**|Traffic flows, ACL violations|NetFlow, SNMP|
|**Endpoints (PCs)**|Process execution, USB usage, malware alerts|SIEM Agent (EDR integration)|
|**Cloud Services**|Login attempts, API calls, configuration changes|REST API (AWS CloudTrail)|
|**Email Servers**|Spam, phishing attempts, login failures|SMTP logs, IMAP/POP3|

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
Handling data exfiltration incidents involves quickly identifying the source and extent of the breach, isolating affected systems, and mitigating further data loss. Investigating the attack vector, restoring data from backups, and notifying relevant stakeholders are also crucial steps.

[Q12] - What is a security baseline?
A security baseline defines the minimum security standards and configurationsrequired for systems and applications.


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

