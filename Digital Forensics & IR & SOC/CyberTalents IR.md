## Live Response Acquisition
1. Collect Evidence Suitable for Portable & Rapid Acquisition
2. Collect Data Only Available While the System is Running
3. Triage a System of Interest
4. Determine If a Full Disk Image is Required

## Velociraptor

[Velociraptor](https://docs.velociraptor.app/) is an open-source tool designed for endpoint monitoring, live response, and digital forensics. It allows incident responders to collect and analyze forensic artifacts from systems in real-time, making it ideal for live response acquisition scenarios where time-sensitive and volatile data must be captured before it's lost.

### Browser History

#### Google Chrome
- Location: C:\Users\[Username]\AppData\Local\Google\Chrome\User Data\Default\History
- History is stored in an SQLite database file named History.
#### Mozilla Firefox:
- Location: C:\Users\[Username]\AppData\Roaming\Mozilla\Firefox\Profiles\[ProfileName]\places.sqlite
- History is stored in the places.sqlite file.
#### Microsoft Edge:
- Location: C:\Users\[Username]\AppData\Local\Microsoft\Edge\User Data\Default\History
- Stored in an SQLite database named History, similar to Chrome.
#### Opera:
- Location: C:\Users\[Username]\AppData\Roaming\Opera Software\Opera Stable\History
- History is stored in the History file.
#### Brave:
- Location: C:\Users\[Username]\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\History
- Stored in an SQLite database named History.


**Prefetch files** are Windows system files used to speed up the loading of applications by caching key data about recently executed programs. Location: C:\Windows\Prefetch

**The Master File Table (MFT)** is a critical component of the NTFS (New Technology File System) in Windows, acting as a database that stores information about every file and directory on a volume. It contains file attributes, metadata, and pointers to data, essential for file system operations and forensics.

**Timestamp stomping** is a technique used by attackers to modify file timestamps to cover their tracks. This involves altering one or more of the timestamps (creation, modification, access, MFT modification) to create confusion about the file’s actual activity timeline.

**An Alternate Data Stream (ADS)** in NTFS allows files to store additional data outside the primary file content. This hidden data can store metadata or even entire files, without affecting the file's size in normal views. ADS can be exploited by attackers to hide malicious code or files, making it valuable in forensic investigations.

### Memory Sections
The contents of a process’s virtual memory space are tracked by the **Virtual Address Descriptor (VAD)** tree, which is managed by the Windows Memory Manager. The VAD tree is a self-balancing structure that tracks memory sections allocated to each process, including heap, stack, and memory-mapped files.
Key components include:
- Control Areas: Store information about the backing storage for memory-mapped regions.
- File Objects: Link memory regions to files on disk, such as DLLs or executables.
Analyzing the VAD tree helps in identifying hidden memory regions and injecting code in forensic investigations.

### Persistence

In Windows, the Registry plays a key role in managing autoruns, which are programs or scripts set to execute automatically during system startup or user login. These autoruns are often defined in specific registry keys that control how and when certain applications run. Common registry locations for autorun entries include:
1. HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run (System-wide autoruns)
2. HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run (User-specific autoruns)

## Common Persistence Mechanisms

Registry persistence involves attackers using Windows Registry keys to maintain access to a compromised system.
They commonly modify specific keys like Run, RunOnce, or Services to execute malicious code at startup.
Attackers may also create hidden registry keys or leverage less-known areas like AppInit_DLLs or Scheduled Tasks for stealthier persistence.

Service persistence By installing malicious services or altering existing ones, attackers ensure that their malware runs with elevated privileges and can automatically start when the system boots.
The Windows Registry key HKLM\SYSTEM\ControlSet001\services\wuauserv refers to the Windows Update service.

Startup folders in Windows contain shortcuts to programs that automatically run when a user logs in. These folders exist for both individual users and all users on a system, located in directories like C:\Users\[Username]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup and C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup.

DLL Search Order Hijacking is a persistence technique where attackers exploit the way Windows searches for Dynamic Link Libraries (DLLs) when an application loads. Windows looks for DLLs in a specific order, starting with the directory of the application, followed by system directories.


### Other Common Auto-run keys

Run / RunOnce
	HKLM\Software\Microsoft\Windows\CurrentVersion\Run
Active Setup
	HKLM\Software\Microsoft\Active Setup\Installed Components\APPGUIDS
Shell Extensions
	HKLM\Software\Microsoft\Windows\CurrentVersion\Shell Extensions
Applnit DLLs
	HKLM\Software\Microsoft\Windows
	NT\CurrentVersion\Windows\AppInit DLLS
UserInit
	HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\UserInit
LSA Packages
	HKLM\System\CurrentControlSet\Control\Lsa\



ShimCache, also known as the Application Compatibility Cache, is a feature in Windows that tracks executable files for compatibility purposes. It is used by the Windows operating system to determine whether certain files need compatibility adjustments before execution.

---

## compare between SOAR and SIEM

SOAR (Security Orchestration, Automation, and Response) and SIEM (Security Information and Event Management) are both critical cybersecurity technologies, but they serve different purposes and complement each other in a security operations center (SOC). Here’s a detailed comparison:

### **1. Core Functionality**
| **Feature**       | **SIEM** | **SOAR** |
|-------------------|----------|----------|
| **Primary Role**  | Collects, correlates, and analyzes security event data in real-time for threat detection. | Automates and orchestrates incident response workflows. |
| **Data Sources**  | Logs, network traffic, endpoints, cloud services, and security devices. | SIEM alerts, threat intelligence feeds, ticketing systems, APIs. |
| **Key Capabilities** | Log management, event correlation, threat detection, compliance reporting. | Playbook automation, case management, response workflows, integration with third-party tools. |

### **2. Detection vs. Response**
- **SIEM**: Focuses on **detecting threats** by analyzing logs and events using rule-based correlation, machine learning, and behavioral analytics.
- **SOAR**: Focuses on **responding to incidents** by automating actions like blocking IPs, quarantining devices, or notifying analysts.

### **3. Human Involvement**
- **SIEM**: Generates alerts that require manual investigation by security analysts.
- **SOAR**: Reduces manual effort by executing predefined playbooks (e.g., auto-contain a compromised host).

### **4. Use Cases**
| **Use Case**               | **SIEM** | **SOAR** |
|----------------------------|----------|----------|
| Log aggregation & analysis  | ✅ Yes   | ❌ No    |
| Real-time threat detection | ✅ Yes   | ❌ No    |
| Automated incident response| ❌ No    | ✅ Yes   |
| Threat hunting             | ✅ Yes   | ⚠️ Limited |
| Case management            | ❌ No    | ✅ Yes   |
| Compliance reporting       | ✅ Yes   | ❌ No    |

### **5. Integration**
- **SIEM** acts as a **data aggregator** (pulling logs from multiple sources).
- **SOAR** acts as a **workflow engine** (integrating with SIEM, firewalls, EDR, ticketing systems).

### **6. Strengths & Weaknesses**
| **Aspect**     | **SIEM**                                                                      | **SOAR**                                                                                     |
| -------------- | ----------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| **Strengths**  | - Centralized visibility <br>- Compliance reporting <br>- Historical analysis | - Faster response times <br>- Reduces analyst workload <br>- Standardizes processes          |
| **Weaknesses** | - High false positives <br>- Requires tuning <br>- Limited automation         | - Relies on SIEM/other tools for detection <br>- Complex setup <br>- Needs skilled personnel |

### **7. Do You Need Both?**
- **SIEM alone** → Good for monitoring but slow at response.
- **SOAR alone** → No detection capability; needs SIEM/other tools.
- **Best Practice**: Use **SIEM for detection** and **SOAR for response** in a modern SOC.

### **Conclusion**
- **SIEM** = "What’s happening?" (Detection & Monitoring)  
- **SOAR** = "What should we do about it?" (Response & Automation)  


---
## Compare between zui and Wireshark and NetworkMiner

|Feature/Tool|**Zui** (by Brimdata)|**Wireshark**|**NetworkMiner**|
|---|---|---|---|
|**Primary Use Case**|Log analysis, security investigations|Deep packet inspection, network analysis|Forensic analysis, file extraction|
|**Data Input**|Zeek logs, PCAPs, structured data (Zed)|Live traffic & PCAP files|PCAP files (offline analysis)|
|**Interface**|GUI with Zed query language (ZQL)|GUI with filtering & dissection|GUI with file extraction & metadata|
|**Key Strengths**|- Fast log queries (Zed backend)|- Real-time capture & deep protocol analysis|- Extracts files, credentials, sessions|
||- Integrates with Zeek/Suricata logs|- Supports 3,000+ protocols|- Passive network forensics|
|**Query Language**|Zed (ZQL)|Wireshark display filters|None (click-based analysis)|
|**Forensics Focus**|Log correlation & threat hunting|Protocol debugging & troubleshooting|Evidence extraction (e.g., images, emails)|
|**Live Capture**|No (post-analysis only)|**Yes** (real-time)|No (PCAP-only)|
|**OS Support**|Windows, macOS, Linux|Windows, macOS, Linux|Windows (Linux via Mono)|
|**Open Source?**|Yes (Apache 2.0)|Yes (GPL)|Free (closed-source)|
