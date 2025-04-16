Penetration Testing Steps
- Information Gathering ->> Passive  & Active
- Vulnerability Identification ->> Nmap -  Nessus - OpenVas 
- Exploitation ->> Brute Forcing - Remote Exploit
- Post Exploitation ->> Persistence - Anti Forensics


Linux File System (Filesystem Hierarchy Standard) :

| Directory | Content / Description                                                                                            |
| --------- | ---------------------------------------------------------------------------------------------------------------- |
| /         | The root directory (It is the starting point for the file system hierarchy)                                      |
| /bin/     | Essential user command binaries                                                                                  |
| /boot/    | Linux kernel and other static files of the boot loader                                                           |
| /dev/     | Device files                                                                                                     |
| /etc/     | System configuration files                                                                                       |
| /home/    | Home directories for normal users (non-root users)                                                               |
| /lib/     | Essential shared libraries and kernel modules                                                                    |
| /media/   | Mount points for removable devices, such as: CD-ROMs and USB keys                                                |
| /mnt/     | Mount point for a temporarily mounted filesystem                                                                 |
| /opt/     | Add-on application software packages                                                                             |
| /proc/    | System processes information                                                                                     |
| /root/    | Home directory for the root user                                                                                 |
| /run/     | Volatile runtime data                                                                                            |
| /sbin/    | System administration binaries                                                                                   |
| /srv/     | Data for services provided by this system                                                                        |
| /sys/     | Information about devices, drivers, and some kernel features                                                     |
| /tmp/     | Temporary files (these temporary files are generally deleted when the system is restarted)                       |
| /usr/     | Applications and files used by users (/usr/ is the second major section of the filesystem (secondary hierarchy)) |
| /var/     | Variable data files handled by services, such as: logs, queues, caches, and spools                               |


The result of a scan on a port is usually generalized into one of three categories: 

1. Open or Accepted: The host sent a reply indicating that a service is listening on the port.
2. Closed or Denied or Not Listening: The host sent a reply indicating that connections will be denied to the port.
3. Filtered, Dropped or Blocked: There was no reply from the host.


Scanning Types :
- Network tracing
- Port scanning
- OS fingerprinting
- Version scanning
- Vulnerability scanning

Common Anti-Scanning Techniques :

1-Port-Level Techniques
- **Port Knocking**: Requires a specific sequence of connection attempts to closed ports before opening a service port.
- **Dynamic Ports**: Services use changing ports (randomized or time-based) to evade static scans.
- **Filtering Scans**:
    - **SYN Cookies**: Mitigates SYN flood scans by delaying port visibility.
    - **Rate Limiting**: Blocks IPs that send too many scan requests in a short time.
- **Honeypot Ports**: Fake open ports that log or trap scanning attempts.

2- Network-Level Techniques
- **IP Address Shuffling (Moving Target Defense)**: Frequently changing IP addresses to disrupt scanning.
- **Firewall & IDS/IPS Rules**:
    - Blocking known scanning IPs (e.g., Shodan, Censys).
    - Detecting and dropping scan-like traffic patterns.
- **TCP/IP Stack Manipulation**:
    - Modifying OS fingerprints to deceive scanners (e.g., changing TTL, TCP window size).
    - Sending misleading responses (e.g., false banners, fake service versions).

3- Application-Level Techniques
- **Obfuscated Banners**: Changing or hiding service banners (e.g., SSH, HTTP headers).
- **Challenge-Response for Access**: Requiring authentication before revealing service details.
- **Tarpitting**: Intentionally slowing down responses to waste scanner resources.
- **Custom Protocol Handling**: Using non-standard protocols or encryption to evade detection.

4- Web-Specific Anti-Scanning
- **WAF (Web Application Firewall)**: Blocking automated crawlers/scanners (e.g., blocking Nikto, Burp Suite).
- **CAPTCHAs & Rate Limits**: Preventing automated enumeration of web endpoints.
- **Obfuscated URLs & Dynamic Paths**: Making web crawling difficult.
- **Honeytokens**: Fake API keys, hidden links, or dummy endpoints to detect scans.

5- Logging & Active Response
- **Scan Detection Alerts**: Using tools like Fail2Ban, Snort, or Suricata to block scanning IPs.
- **Blacklisting Scanners**: Maintaining a list of known scanning IPs (e.g., Shodan, ZoomEye).
- **Legal Action**: Some organizations send abuse reports or take legal steps against aggressive scanners.


What do you know about Enumeration ?
Enumeration is one of the phases in penetration testing including all the information collected and can be directly used for system exploitation.
Enumeration is the process of extracting usernames, machine names, NetBIOS, DNS details, network resources, shares, IP tables, routing tables, SNMP, and services from a system or network.

| Port        | services                                    |
| ----------- | ------------------------------------------- |
| TCP 445     | SMB                                         |
| TCP/UDP 389 | LDAP                                        |
| TCP 137     | NetBios name                                |
| TCP 3389    | terminal service and remote desktop         |
| UDP 161     | Simple Network Management Protocol **SNMP** |
| TCP 53      | DNS zone transfer                           |


Post-exploitation refers to any actions taken after a session is opened.
Some example of post-exploitation:
- Collect Sensitive Files
- Add Username and Password to gain easy Access
- Persistent Shell 
- Elevate Privileges 
- Jump to Different VLAN
- Collect Hashes and Crack them

most common persistence methods : 
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


What is a Vulnerability Assessment?
A **Vulnerability Assessment** is a systematic process of identifying, classifying, and prioritizing security weaknesses (vulnerabilities) in a system, network, application, or organization’s infrastructure. The goal is to **discover flaws before attackers exploit them** and recommend remediation steps.
- Use tools like **Nessus, OpenVAS, Qualys, or Nexpose** to scan for known vulnerabilities.
- Check for misconfigurations (e.g., open ports, weak passwords).

|**Aspect**|**Vulnerability Assessment**|**Penetration Testing**|
|---|---|---|
|**Goal**|Identify weaknesses|Exploit weaknesses (simulate attack)|
|**Depth**|Broad, automated scans|Targeted, manual exploitation|
|**Risk**|Non-intrusive (no exploitation)|Intrusive (may cause disruptions)|
|**Output**|List of vulnerabilities|Proof of exploit + attack path|

Why is Vulnerability Assessment Important?
- **Prevents breaches** by finding flaws before hackers do.
- **Compliance requirement** (e.g., PCI-DSS, HIPAA, ISO 27001).
- **Reduces attack surface** by fixing misconfigurations.

