## Digital Forensics Process:

- Acquisition: a collection of digital media to be examined.
- Analysis: the actual examination of the media
- Presentation: The process by which the examiner shares the results of this analysis.
---

**Steganography** is the art and science of embedding secret messages in a cover message in such a way that no one, apart from the sender and intended recipient, suspects the existence of the message.

**KAPE** (Kroll Artifact Parser and Extractor) is a digital forensics and incident response (DFIR) tool designed to quickly collect and process forensic artifacts from Windows systems.

**Guymager** is an open-source forensic imaging tool designed for creating and verifying disk images. It is known for its speed, efficiency, and ease of use, making it a popular choice among digital forensic professionals.

---
### Security identifier (SID)

- Security identifier in Windows is a unique value used to identify any security entity that the Windows operating system (OS) can authenticate.

### Antimalware Scan Interface (AMSI) 

- is a Microsoft Windows component that allows the deeper inspection of built-in scripting services.

### Microsoft Management Console (MMC)

- It is a framework and application used for system administration tasks in Microsoft Windows operating systems. It provides a centralized and extensible platform for managing various aspects of a Windows-based computer or network. MMC serves as a container for various snap-ins, which are specialized management tools that can be added to the MMC interface to perform specific administrative tasks.

###  Windows Management Instrumentation (WMI)

- It is a set of management and instrumentation technologies built into the Microsoft Windows operating system. It provides a standardized way for administrators and software developers to access and manipulate system resources, configurations, and performance data on Windows-based computers and servers. WMI is an integral part of the Windows operating system and plays a crucial role in system management, monitoring, and automation

---

### Compare with sleuthkit and autopsy tools :

**SleuthKit (TSK)** and **Autopsy** are both digital forensics tools used for analyzing disk images and file systems, but they have some key differences in terms of functionality, usability, and use cases. Below is a comparison of the two:

### **1. Overview**
| Feature              | **SleuthKit (TSK)**                            | **Autopsy**                                          |
| -------------------- | ---------------------------------------------- | ---------------------------------------------------- |
| **Type**             | Command-line tool                              | GUI-based tool (built on SleuthKit)                  |
| **Primary Use**      | Low-level disk analysis, file system forensics | User-friendly digital forensics case management      |
| **Extensibility**    | Limited to command-line operations             | Supports plugins and modules for added functionality |
| **Automation**       | Better for scripting and automation            | Manual analysis with some automation features        |
| **Platform Support** | Windows, Linux, macOS                          | Windows, Linux, macOS                                |

### **2. Features Comparison**
| Feature | **SleuthKit (TSK)** | **Autopsy** |
|---------|------------------|-----------|
| **File System Analysis** | Yes (ext, NTFS, FAT, HFS+, etc.) | Yes (same as TSK, but via GUI) |
| **Deleted File Recovery** | Yes (via `fls`, `icat`) | Yes (with graphical interface) |
| **Timeline Analysis** | Yes (via `mactime`) | Yes (visual timeline tool) |
| **Keyword Search** | Basic (via `grep` or external tools) | Advanced (indexed keyword search) |
| **Registry Analysis (Windows)** | No (requires external tools) | Yes (via Registry Viewer) |
| **Hash Filtering** | Manual (via `hfind`) | Automated (known file filtering) |
| **Case Management** | No | Yes (multi-case support, notes, tagging) |
| **Reporting** | Manual (text-based) | Automated (HTML, Excel, etc.) |
| **Threat Detection** | No | Yes (via YARA, STIX, etc.) |
| **Memory Forensics** | No | Limited (via Volatility integration) |
| **Network Forensics** | No | Limited (support for network artifacts) |

### **3. Use Cases**
| **SleuthKit (TSK)**                                                                                                                                                                                                                                                                | **Autopsy**                                                                                                                                                                                                                                                                                       |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Best for **scripted analysis** and **low-level forensics**                                                                                                                                                                                                                         | Best for **case investigations** and **collaborative work**                                                                                                                                                                                                                                       |
| Useful for **automated processing** (e.g., parsing disk images in bulk)                                                                                                                                                                                                            | Better for **manual analysis** (e.g., law enforcement, incident response)                                                                                                                                                                                                                         |
| Preferred by **advanced users** comfortable with CLI                                                                                                                                                                                                                               | Suitable for **beginners** and **non-technical investigators**                                                                                                                                                                                                                                    |
| - Lightweight and fast<br>- Scriptable (can be integrated into custom workflows)<br>- Open-source and free<br>- Works well with other forensic tools  <br>- Steep learning curve (requires CLI knowledge)<br>- No built-in case management<br>- Limited visualization capabilities | - User-friendly GUI<br>- Built-in case management and reporting<br>- Supports plugins (e.g., Torrent analysis, EXIF extraction)<br>- Good for collaborative investigations  <br>- Can be slower for large disk images<br>- Requires more system resources<br>- Less flexible for automation  <br> |
