## Endpoint Detection and Response:
### EDR functions are:
- Monitors and collects data from targeted endpoints.
- Perform an analysis of the data to identify threats.
- Contain the incidents that happened and respond to threats and generate alerts.
### Components of an EDR:

#### Data collections agents:
Software components collect data from the endpoint like network activity information, filesystem information, processes running, etc.

#### Automated response rules:
Pre-configured rules that identify whether a certain activity is a threat or not and automatically take an action against it.

#### Forensics tools:
Tools that are used by security professionals to investigate incidents or even to perform a threat-hunting process.


One of the main differences between “.evtx” and “.evt” files is the **memory efficiency** as in old “.evt” logs, it requires about 300MB (maximum recommended event log size) to be mapped in memory, while in “.evtx” logs, it consists of a header and 64KB chunk and just mapping current 64KB chunk to memory.

---

As a SOC analyst, understanding **Shim Cache** and **AM Cache** is crucial for forensic investigations, particularly in malware analysis, incident response, and evidence of execution. Below is a detailed comparison:

### **1. Shim Cache (Application Compatibility Cache)**
- **Purpose**:  
  - Maintained by the **Windows Application Compatibility** infrastructure to speed up compatibility checks for executables.
  - Helps Windows decide whether a shim (compatibility fix) is needed for legacy applications.

- **Location**:  
  - **Registry**: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`  
  - **File**: `%SystemRoot%\AppCompat\Programs\Amcache.hve` (older Windows versions stored it differently)

- **Forensic Value**:  
  - Tracks **file metadata** (e.g., file path, size, last modified timestamp) of executables.  
  - **Does not confirm execution**, only that the file was present and may have been checked for compatibility.  
  - Useful for detecting:  
    - Malware that executed but was later deleted.  
    - Evidence of lateral movement (e.g., `PSExec.exe` being present).  
    - Historical execution attempts (even if blocked by AV).  

- **Limitations**:  
  - No execution timestamps.  
  - Limited to executables (EXE, DLL, etc.).  
  - Entries may persist even after file deletion.  

- **Windows Versions**:  
  - **Pre-Windows 8.1/2012 R2**: Shim Cache stored in Registry.  
  - **Windows 8.1+**: Partially replaced by **AM Cache**, but Shim Cache still exists with reduced data.

### **2. AM Cache (Amcache.hve)**
- **Purpose**:  
  - Introduced in **Windows 8/Server 2012** as part of the **Application Compatibility** database.  
  - Tracks more detailed information about executed programs for compatibility and inventory purposes.  

- **Location**:  
  - **File**: `%SystemRoot%\AppCompat\Programs\Amcache.hve`  
  - **Registry**: Not applicable (AM Cache is stored in a hive file).  

- **Forensic Value**:  
  - Contains **more metadata** than Shim Cache, including:  
    - **Full file paths** (including USB/network paths).  
    - **SHA-1 hashes** of executables (useful for malware hunting).  
    - **Program execution time** (for some entries).  
    - **PE header info** (compilation timestamp, etc.).  
  - Helps confirm **actual execution** (unlike Shim Cache).  
  - Useful for:  
    - Tracking lateral movement tools (e.g., `Cobalt Strike`, `Mimikatz`).  
    - Identifying deleted or renamed malware.  
    - Correlating with Threat Intelligence (via SHA-1 hashes).  

- **Limitations**:  
  - Not all executions are logged (depends on system policies).  
  - Requires parsing the hive file (tools like `AmcacheParser` needed).  

- **Windows Versions**:  
  - **Windows 8/2012 and later**.  

### **Comparison Summary**
| Feature               | Shim Cache | AM Cache |
|-----------------------|------------|----------|
| **Storage**           | Registry   | Hive File (`Amcache.hve`) |
| **Execution Evidence**| Indirect (file presence) | Direct (some timestamps) |
| **SHA-1 Hashes**      | No         | Yes |
| **File Metadata**     | Basic (path, size, timestamp) | Detailed (PE info, hashes) |
| **Malware Hunting**   | Useful for deleted files | Better (hashes, execution proof) |
| **Lateral Movement**  | Helps detect tools like PSExec | More detailed (network paths) |
| **Windows Support**   | All versions | Windows 8+ |

### **SOC Analyst Use Cases**
1. **Malware Investigation**:  
   - Use **AM Cache** to check SHA-1 hashes against VirusTotal.  
   - Use **Shim Cache** if AM Cache is unavailable (older systems).  

2. **Evidence of Execution**:  
   - **AM Cache** is more reliable (timestamps, hashes).  
   - **Shim Cache** only confirms file existence.  

3. **Lateral Movement Detection**:  
   - Check for `PSExec`, `WMIExec`, or other tools in both caches.  

4. **Timeline Analysis**:  
   - Correlate Shim Cache (modified time) with AM Cache (execution time).  

### **Tools for Analysis**
- **Shim Cache**:  
  - `AppCompatCacheParser` (Eric Zimmerman)  
  - `RegRipper` (shimcache plugin)  
- **AM Cache**:  
  - `AmcacheParser` (Eric Zimmerman)  
  - `KAPE` (for automated collection)  

### **Conclusion**
- **AM Cache** is superior for forensic investigations (post-Windows 8) due to richer data.  
- **Shim Cache** is still useful for legacy systems and detecting deleted files.  
- **Combine both** for comprehensive analysis (e.g., if an attacker clears one but not the other).  

---
### **Snort: Overview & SOC Usefulness**  

#### **What is Snort?**  
Snort is a **free, open-source** **Network Intrusion Detection/Prevention System (NIDS/NIPS)** that monitors network traffic in real-time, detects malicious activity, and alerts security teams.  

### **Key Functionalities**  
1. **Traffic Analysis**  
   - Inspects packets (IP, TCP, UDP, etc.) for suspicious patterns.  
2. **Signature-Based Detection**  
   - Uses **rules** (like antivirus signatures) to flag known threats (e.g., malware C2 traffic).  
3. **Protocol Analysis**  
   - Detects abnormal behavior in protocols (HTTP, DNS, SMB).  
4. **Logging & Alerts**  
   - Logs malicious traffic and triggers alerts (e.g., SIEM integration).  
5. **Prevention Mode (NIPS)**  
   - Can **block** malicious traffic (e.g., drop packets from a botnet IP).  

### **How Snort Helps in SOC Analysis**  
1. **Threat Detection**  
   - Alerts on exploits (e.g., EternalBlue), brute-force attacks, or malware callbacks.  
2. **Incident Investigation**  
   - Provides PCAP (packet capture) data for forensic analysis.  
3. **Rule Customization**  
   - SOC analysts write custom rules (e.g., detect new malware IOCs).  
4. **Integration with SIEM**  
   - Snort logs feed into Splunk, ELK, etc., for correlation.  
5. **Reducing False Positives**  
   - Fine-tuning rules minimizes noise (e.g., excluding benign traffic).  

### **Example Snort Rule**  

```bash  
alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"Possible SMB Exploit - EternalBlue"; flow:established; content:"|FF|SMB|2|"; depth:5; reference:cve,2017-0144; sid:1000001;)  
```  
- **Triggers** when detecting EternalBlue exploit traffic on port 445.  

### **Why SOCs Use Snort**  
 **Cost-effective** (open-source).  
 **Highly customizable** (adapts to new threats).  
 **Lightweight** (low resource usage).  
 **Community-driven** (shared rule updates).  

---
### **Zeek (formerly Bro): Overview & SOC Usefulness**  

#### **What is Zeek?**  
Zeek is a **powerful open-source network analysis framework** that operates as a **Network Security Monitor (NSM)**. Unlike Snort (which focuses on signature-based detection), Zeek provides **protocol-level visibility**, logging, and behavioral analysis.  

### **Key Functionalities**  
1. **Protocol Analysis**  
   - Deep inspection of **HTTP, DNS, FTP, SSH, SSL/TLS, SMB, etc.**  
   - Extracts metadata (e.g., URLs, user agents, DNS queries).  
2. **Traffic Logging**  
   - Generates structured logs (`conn.log`, `http.log`, `dns.log`, `files.log`).  
3. **Behavioral Detection**  
   - Detects anomalies (e.g., unusual data transfers, beaconing).  
4. **File Extraction**  
   - Can extract and hash downloaded files (e.g., malware samples).  
5. **Custom Scripting**  
   - Uses **Zeek scripts** (`.zeek`) for custom detections.  

### **How Zeek Helps in SOC Analysis**  
1. **Threat Hunting**  
   - Analyze **DNS exfiltration, C2 traffic, lateral movement**.  
2. **Incident Response**  
   - Provides **detailed logs** (e.g., "Who accessed this malicious IP?").  
3. **Forensic Investigations**  
   - Reconstructs **suspicious sessions** (e.g., brute-force attacks).  
4. **Malware Analysis**  
   - Extracts downloaded files (PEs, scripts) for sandboxing.  
5. **SIEM Integration**  
   - Logs feed into Splunk, ELK, etc., for correlation.  

### **Example Zeek Use Cases**  
| **Attack**           | **Zeek Logs**                             | **Detection Method**                |
| -------------------- | ----------------------------------------- | ----------------------------------- |
| **Phishing**         | `http.log` (suspicious URLs)              | `files.log` (malicious attachments) |
| **DNS Tunneling**    | `dns.log` (long TXT queries)              | Anomaly in query length             |
| **RDP Brute Force**  | `conn.log` (many short-lived connections) | High failed login attempts          |
| **Malware Download** | `files.log` (EXE from shady domain)       | File extraction + VirusTotal check  |


### **Zeek vs. Snort**  
| Feature           | **Zeek**                           | **Snort**               |
| ----------------- | ---------------------------------- | ----------------------- |
| **Primary Use**   | Network traffic analysis & logging | Signature-based IDS/IPS |
| **Detection**     | Behavioral + protocol anomalies    | Rule-based (signatures) |
| **Logging**       | Structured logs (JSON, TSV)        | Alerts + PCAPs          |
| **Customization** | Zeek scripting                     | Snort rules             |
| **Performance**   | Higher resource usage              | Lightweight             |

---
### **Suricata: Overview & SOC Usefulness**  

#### **What is Suricata?**  
Suricata is a **high-performance, open-source** **Network Intrusion Detection/Prevention System (NIDS/NIPS)** and **Network Security Monitoring (NSM)** tool. It combines **signature-based detection** (like Snort) with **advanced threat detection** (like Zeek), making it a **versatile SOC tool**.  

## **Key Functionalities**  
### **1. Multi-Threat Detection**  
- **Signature-Based** (Snort-compatible rules)  
  - Detects known malware, exploits, and attack patterns.  
- **Anomaly-Based**  
  - Flags unusual traffic (e.g., port scanning, DDoS).  
- **Protocol Analysis**  
  - Deep inspection of **HTTP, DNS, TLS, SSH, etc.**  

### **2. File Extraction & Malware Detection**  
- Extracts files (PDFs, EXEs) from network traffic.  
- Can integrate with **VirusTotal, YARA** for malware analysis.  

### **3. Logging & Metadata Generation**  
- Generates **structured logs** (EVE JSON format) for SIEM integration.  
- Tracks **IPs, domains, TLS certificates, user agents**.  

### **4. Real-Time Blocking (IPS Mode)**  
- Can **automatically block malicious traffic** (e.g., exploit attempts).  

### **5. High-Performance & Scalability**  
- Supports **multi-threading** for high-speed networks (10Gbps+).  

## **How Suricata Helps in SOC Analysis**  
| **SOC Use Case**      | **Suricata’s Role**                                               |
| --------------------- | ----------------------------------------------------------------- |
| **Threat Detection**  | Alerts on malware C2, exploits, brute-force attacks.              |
| **Incident Response** | Provides PCAPs and logs for forensic analysis.                    |
| **Threat Hunting**    | Metadata (JA3 fingerprints, DNS queries) helps track adversaries. |
| **Malware Analysis**  | Extracts malicious files from network traffic.                    |
| **SIEM Integration**  | Sends structured logs (EVE JSON) to Splunk, ELK, etc.             |

## **Suricata vs. Snort vs. Zeek**  
| Feature             | **Suricata**                   | **Snort**               | **Zeek**                  |
| ------------------- | ------------------------------ | ----------------------- | ------------------------- |
| **Detection**       | Signatures + Anomaly           | Signature-based         | Protocol analysis         |
| **Performance**     | Multi-threaded (fast)          | Single-threaded         | Moderate                  |
| **Logging**         | EVE JSON (rich metadata)       | Alerts + PCAPs          | Structured logs           |
| **Blocking**        | Yes (IPS mode)                 | Yes (IPS mode)          | No                        |
| **File Extraction** | Yes                            | Limited                 | Yes                       |
| **Best For**        | **Balanced IDS/IPS + logging** | **Lightweight IDS/IPS** | **Deep traffic analysis** |

---

## **Example Suricata Rule**  

```bash  
alert http $HOME_NET any -> $EXTERNAL_NET any (  
  msg:"Malicious User-Agent - Emotet";  
  flow:established,to_server;  
  http.user_agent;  
  content:"Mozilla/5.0 (Windows NT 10.0; Win64; x64) EvilBot";  
  sid:1000001;  
  rev:1;  
)  
```  
- Triggers when detecting **Emotet malware’s HTTP beaconing**.  

---

When working with **SIEM (Security Information and Event Management) solutions**, the most important **source types (log types)** to monitor depend on your organization's infrastructure and security priorities. However, here are the **most critical log sources** you should focus on in a SOC environment :

### **1. Endpoint Logs**  
**Source Examples:**  
- **Windows Event Logs** (Security, System, Application)  
  - Critical IDs: `4624` (Successful login), `4625` (Failed login), `4688` (Process execution), `7045` (Service installation).  
- **EDR/XDR Logs** (CrowdStrike, SentinelOne, Microsoft Defender)  
  - Detects malware, suspicious processes, lateral movement.  
- **Sysmon Logs** (Enhanced process tracking, file changes, network connections).  

### **2. Network Security Logs**  
**Source Examples:**  
- **Firewall Logs** (Palo Alto, Fortinet, Cisco ASA)  
  - Blocks/allow traffic, port scans, geo-IP anomalies.  
- **IDS/IPS Logs** (Suricata, Snort, Darktrace)  
  - Alerts on exploits, C2 traffic, DDoS.  
- **Proxy/Web Filter Logs** (Zscaler, Blue Coat, Squid)  
  - Malicious URLs, phishing attempts, data exfiltration.  

### **3. Authentication & Identity Logs**  
**Source Examples:**  
- **Active Directory (AD) Logs**  
  - Event IDs: `4768-4776` (Kerberos), `4720` (User account deleted).  
- **VPN Logs** (Cisco AnyConnect, FortiGate SSL-VPN)  
  - Failed logins, unusual locations.  
- **Multi-Factor Authentication (MFA) Logs** (Duo, Okta)  
  - Bypass attempts, suspicious MFA fatigue attacks.  

### **4. Cloud & SaaS Logs**  
**Source Examples:**  
- **Azure AD / Office 365 Logs**  
  - Risky sign-ins, mailbox forwarding rules (for phishing).  
- **AWS CloudTrail / GCP Audit Logs**  
  - Unauthorized S3 access, IAM role misuse.  
- **SaaS Apps (Slack, GitHub, Salesforce)**  
  - Insider data theft, API abuse.  

### **5. Email Security Logs**  
**Source Examples:**  
- **Microsoft Exchange / M365 Defender**  
  - Phishing emails, malicious attachments.  
- **Proofpoint / Mimecast Logs**  
  - URL clicks, impersonation attempts.  

### **6. Database & Application Logs**  
**Source Examples:**  
- **Database Logs** (SQL Server, Oracle, MySQL)  
  - SQL injection, unusual data access.  
- **Web Server Logs** (Apache, Nginx, IIS)  
  - Web shells, HTTP exploits (Log4j, etc.).  

### **7. Threat Intelligence Feeds**  
**Source Examples:**  
- **TI Platforms** (AlienVault OTX, MISP, ThreatFox)  
- **IOC Feeds** (Malware hashes, malicious IPs/domains).  


### **Prioritization for SOC Analysts**  
| **Log Source**          | **Top Use Case**                                 |
| ----------------------- | ------------------------------------------------ |
| **Windows Event Logs**  | Detect lateral movement, malware execution.      |
| **Firewall/Proxy Logs** | Block C2 traffic, data exfiltration.             |
| **AD/Azure AD Logs**    | Spot credential theft, privilege escalation.     |
| **EDR Logs**            | Endpoint threat detection & response.            |
| **Email Logs**          | Stop phishing & BEC (Business Email Compromise). |

---
