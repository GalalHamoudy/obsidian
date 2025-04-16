### Where to Hunt?

#### 1. Network-based evidence: 
Look at logs, packet captures (PCAPs), NetFlow, firewall logs, IDS/IPS alerts, DNS logs, and proxy logs for malicious traffic or patterns.
#### 2. Host-based evidence: 
Focus on file systems, registry entries, memory dumps, event logs, and installed applications for signs of compromise like malware, unauthorized access, or abnormal behavior.
#### 3. Directed by initial lead: 
Investigate based on the nature of the initial alert or lead, such as suspicious IP traffic or unauthorized file modifications.
#### 4. Use existing resources: 
Leverage SIEM systems, threat intelligence, and forensic tools to scope the incident effectively and ensure comprehensive analysis across network and host systems

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

**Timestamp** stomping is a technique used by attackers to modify file timestamps to cover their tracks. This involves altering one or more of the timestamps (creation, modification, access, MFT modification) to create confusion about the file’s actual activity timeline.

**An Alternate Data Stream (ADS)** in NTFS allows files to store additional data outside the primary file content. This hidden data can store metadata or even entire files, without affecting the file's size in normal views. ADS can be exploited by attackers to hide malicious code or files, making it valuable in forensic investigations.


### Memory Sections
The contents of a process’s virtual memory space are tracked by the Virtual Address Descriptor (VAD) tree, which is managed by the Windows Memory Manager. The VAD tree is a self-balancing structure that tracks memory sections allocated to each process, including heap, stack, and memory-mapped files.
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

**Run / RunOnce (as seen in 1st lab)**
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
**Active Setup**
HKLM\Software\Microsoft\Active Setup\Installed Components\APPGUIDS
**Shell Extensions**
HKLM\Software\Microsoft\Windows\CurrentVersion\Shell Extensions
**Applnit DLLs**
HKLM\Software\Microsoft\Windows
NT\CurrentVersion\Windows\AppInit DLLS
**UserInit**
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\UserInit
**LSA Packages**
HKLM\System\CurrentControlSet\Control\Lsa\



ShimCache, also known as the Application Compatibility Cache, is a feature in Windows that tracks executable files for compatibility purposes. It is used by the Windows operating system to determine whether certain files need compatibility adjustments before execution.


