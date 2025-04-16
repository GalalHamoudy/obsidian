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

[Q14] - Can you walk me through the threat intelligence analysis process?
1. **Collect Data:** This is the first step in any threat intelligence analysis process. I need to collect data from various sources such as open-source intelligence, threat intelligence feeds, and reports. This data should be relevant to the organization's environment and business operations.
2. **Analyze data:** With the data collected, I will analyze it to identify potential threats. I will use various tools and techniques to identify patterns, anomalies, and suspicious activities. This includes the use of data visualization tools that can help in pattern recognition.
3. **Classification:** After analyzing the data, I will classify the threats into different categories to prioritize them. This classification may be based on the probability and impact of the threat on the organization's operations, assets, and reputation.
4. **Validation:** Before reporting the threats to the organization or management, I will validate the accuracy, reliability, and credibility of the information collected. This may involve verifying the source of the data and cross-checking it with other sources.
5. **Reporting and Recommendations:** Finally, I will prepare a detailed report that summarizes the findings of my analysis and provides recommendations on how to mitigate or eliminate the identified threats. This report may include technical details, such as indicators of compromise or attack signatures, and non-technical information, such as business impacts and financial losses.

[Q15] - How do you prioritize threats based on potential impact?
- Gathering information about the threat
- Assessing the likelihood of an attack
- Determining the potential impact
- Assigning a risk score
- Communicating the risk to stakeholders

[Q16] - How do you prioritize threats?
 Prioritizing threats is a critical skill in CTI, requiring an assessment of the potential impact, urgency, and likelihood of each threat. I prioritize based on the severity of the impact on the organization’s critical assets and operations, the credibility of the threat intelligence, and the organization’s vulnerability to the specific threat. This approach ensures that resources are allocated effectively, focusing on the most significant threats first.

[Q17] - "How do you prioritize and manage multiple threat intelligence reports?"
"I prioritize threat intelligence reports based on the potential impact and likelihood of the threat. I use a risk matrix to categorize threats and focus on high-impact, high-likelihood threats first. For instance, during a recent surge in phishing attacks, I prioritized reports related to phishing over less immediate threats, ensuring our defenses were promptly strengthened."

[Q18] - Describe a time when you identified a false positive. How did you handle it?
 I **adjusted the monitoring tool’s parameters** to minimize similar occurrences in the future, enhancing the accuracy of our threat detection efforts.

[Q19] - What port number does ping use?
Ping uses ICMP so it doesn’t use any port 

[Q20] - Describe the steps in the digital forensic investigation process.

The digital forensic process typically follows these six stages :
- **Identification:** Recognize potential sources of digital evidence.
- **Preservation:** Ensure that the digital evidence is preserved in its original state. This is often done by creating forensic images.
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
Data mining is the process of recording as much data as possible to create reports and analysis on user input. For instance, you can mine data from various websites and then log user interactions with this data to evaluate which website areas are accessed by users when logged in.

[Q24] -  What is data carving?
Data carving is different than data mining in that data carving searches through raw data on a hard drive without using a file system. It allows a computer forensic investigator to recover a deleted file from a hard drive. Data carving is essential for computer forensics investigators to find data when a hard drive’s data is corrupted.
