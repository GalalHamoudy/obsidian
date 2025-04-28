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


As a SOC analyst, understanding **Shim Cache** and **AM Cache** is crucial for forensic investigations, particularly in malware analysis, incident response, and evidence of execution. Below is a detailed comparison:

---

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

---

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

---

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

---

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

---

### **Tools for Analysis**
- **Shim Cache**:  
  - `AppCompatCacheParser` (Eric Zimmerman)  
  - `RegRipper` (shimcache plugin)  
- **AM Cache**:  
  - `AmcacheParser` (Eric Zimmerman)  
  - `KAPE` (for automated collection)  

---

### **Conclusion**
- **AM Cache** is superior for forensic investigations (post-Windows 8) due to richer data.  
- **Shim Cache** is still useful for legacy systems and detecting deleted files.  
- **Combine both** for comprehensive analysis (e.g., if an attacker clears one but not the other).  

Would you like a practical example of parsing these in an investigation?