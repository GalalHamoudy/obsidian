### system
macOS utilizes a file system known as **Apple File System (APFS)** 

Here’s a comparison table between **HFS+ (Hierarchical File System Plus)** and **APFS (Apple File System)**, focusing on key differences and features:

| Feature               | HFS+ (Mac OS Extended) | APFS (Apple File System) |
|-----------------------|-----------------------|--------------------------|
| **Introduced**        | 1998 (Mac OS 8.1)     | 2017 (macOS High Sierra) |
| **Designed for**      | Traditional HDDs      | SSDs, Flash Storage      |
| **Encryption**        | Limited (FileVault)   | Native full-disk/file encryption (multi-key) |
| **Snapshots**         | No                    | Yes (supports Time Machine backups) |
| **Cloning**           | No                    | Yes (instant file copies, no extra space) |
| **Space Sharing**     | No                    | Yes (dynamic volume sizing) |
| **Crash Protection**  | Journaling only       | Copy-on-write (safer against corruption) |
| **File Size Limit**   | 8 EB (theoretical)    | 8 EB (practical for modern use) |
| **Directory Sizes**   | Slower with many files | Optimized for large directories |
| **Fragmentation**     | Prone over time       | Reduced (SSD-optimized) |
| **Metadata Handling** | Slower                | Faster (inline metadata) |
| **Time Machine**      | Requires dedicated HFS+ volumes | Works with APFS snapshots (efficient) |
| **Compatibility**     | macOS & older systems | macOS 10.13+ (not bootable on older macOS) |
| **Case Sensitivity**  | Optional              | Optional (case-sensitive variant available) |

### Key Takeaways:
- **APFS** is optimized for modern SSDs, offering better performance, reliability, and features like snapshots/cloning.
- **HFS+** is legacy but remains compatible with older systems and Time Machine (pre-APFS).
- APFS is the default for macOS since 2017, while HFS+ is deprecated for SSDs but still used for external drives (e.g., Time Machine on HDDs). 


- To determine which file system is used on your macOS device, use the "Disk Utility" tool. To open Disk Utility, you can type "Disk Utility" in Spotlight search.

- To view your file system, simply open “Finder”, go to the “Go” menu, then “Computer”, select the hard drive, and follow the path "File > Get Info."

In APFS (Apple File System), a container is the fundamental building block in modern disk partitioning systems. It provides a dynamic and flexible way to create logical disk partitions. You can create multiple logical structures across different disks, with files and folders stored in various areas independently of the physical structure.

 Disk (HDD)
├── Partition 1: HDD - 1
└── Partition 2: HDD - 2
    |
    + APFS Container
    ├── UID: LLL-DDD
    ├── UID: EEE-EEE
    └── UID: SSS-FFF
        |
        + APFS Volumes
        ├── VOL1 (Instance 1)
        ├── VOL1 (Instance 2)
        ├── VOL1 (Instance 3)
        └── VOL1 (Instance 4)
            |
            + APFS Namespace
            ├── Documents
            ├── Images
            └── Library


The advantages of APFS's container structure can be summarized in four main points:

- **Efficient Space Utilization:** As volumes grow and shrink within the container space, the waste of space is minimized.
- **Security Measures:** The container holds metadata that manages all volumes for data protection and crash recovery.
- **Duplication and Booting:** Multiple volumes within a container can share the same operating system, making it easy to boot with different versions of macOS.
- **Snapshots:** APFS has a snapshot feature that allows you to take a fixed image of a volume at a specific moment in time. The snapshot feature is an invaluable tool for tracking changes over time and restoring the system to a specific state.


### MacOS Directory Structure

Here's the structured table representation of the macOS directories and their purposes:  

| **/ +** **Directory** | **Description**                                                                                                                       |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| **Applications**      | Directory where applications installed on macOS are stored.                                                                           |
| **Developer**         | Created when Apple Developer Tools are installed; contains developer tools.                                                           |
| **Library**           | Shared libraries, system settings, preferences, and essential files for macOS (Note: Each user also has a personal `Library` folder). |
| **Network**           | Contains network-related devices, servers, libraries, etc.                                                                            |
| **System**            | Critical system files, libraries, and preferences required for macOS to function.                                                     |
| **Users**             | Stores all user accounts and their personal files, settings, etc. (Similar to `/home` in Linux).                                      |
| **Volumes**           | Contains mounted devices (hard disks, CDs, DVDs, DMG images, etc.).                                                                   |
| **bin**               | Essential common binaries needed for booting and running the OS.                                                                      |
| **etc**               | Machine-local system configuration files (administrative and system settings).                                                        |
| **dev**               | Device files representing peripherals (keyboards, mice, etc.).                                                                        |
| **usr**               | Secondary hierarchy with subdirectories for OS-related information, configuration files, and utilities.                               |
| **sbin**              | Essential system binaries for system administration.                                                                                  |
| **tmp**               | Temporary files and caches.                                                                                                           |
| **var**               | Variable data (logs, caches, and other files that change while the OS runs).                                                          |

### Notes:
- **Library** exists both in the root (`/Library`) and user home directories (`~/Library`).  
- **bin**, **sbin**, **usr**, **etc**, **dev**, **tmp**, and **var** follow Unix-like conventions (similar to Linux).  
- **Volumes** is macOS-specific for handling mounted storage devices.  


## Installed Application Information : 
installed applications are copied to their directories under the '/Applications' directory.
The "Info.plist" file located under each application directory's "Contents" directory serves as a database that contains all the information and configuration settings for that application.

## User Application Directories :
On MacOS, each application is kept and run in a separate sandbox for each user. You can access the data and settings available to an application for a user by navigating to “`/Users/<UserName>/Library/Containers/<bundle_id>/`". While the ".plist" files under this directory hold a lot of useful information related to the application, you can access many runtime-related data under "`/Users/<UserName>/Library/Containers/<bundle_id>/Data`".

## User Application Configurations

Each user's configuration settings of applications they use are stored in the `/Users/<UserName>/Library/Preferences/<bundle_id>.plist` file.

## User Application Cache Files

You can find cache files used by applications and information related to data utilized at runtime in the following directories:

`/Users/<UserName>/Library/Containers/<bundle_id>/Cache/*`
`/Users/<UserName>/Library/Caches/`


## Keyboard Dicts

MacOS analyzes text entered by users to suggest completion. The data is in "`/Users/<UserName>/Library/Spelling/*.dat`". This directory might contain evidence for digital forensics.
  

## AutoRun Applications

As with all operating systems, MacOS has a structure that allows certain applications to run automatically at system startup. As we all know, one of the most commonly used methods by attackers during the Persistence stage is this AutoRun structure. You can find applications set to run automatically in the ".plist" files located in the following directories:

  

`/System/Library/LaunchAgents/*.plist`
`/Library/LaunchAgents/*.plist`
`/Users/<UserName>/Library/LaunchAgents/*.plist`
`/System/Library/LaunchDaemons/`
`/Library/LaunchDaemons/`

  

It is important to distinguish between LaunchAgents and LaunchDaemons. LaunchAgents are "user" processes initiated automatically at startup, whereas LaunchDaemons are "system" processes initiated automatically at startup.


## Saved States

When MacOS reboots for any reason, it saves the status information of the user's applications in "state" files, allowing them to resume where they left off when the system restarts. Users can choose to continue from these saved states. You can access this data from the following paths:

  

`/Users/<UserName>/Library/Saved Application State/<bundle_id>.savedState/`
`/Users/<UserName>/Library/Containers/<Bundle ID>/Data/`
`/Library/Application Support/<App Name>/Saved Application State/<bundle_id>.savedState/`

  

## Notifications

The MacOS operating system displays a series of notification messages to users and maintains them in a database. The history of these messages can contain valuable data for digital forensics and is stored in the following database file:

`/private/var/folders/<DARWIN_USER_DIR>/com.apple.notificationcenter/db2/db`

  

## ThirdParty Kernel Extensions

Despite the rigorous security protocols in place on MacOS that regulate the execution of third-party applications, user consent remains an essential factor. In many cases, users are unaware of the permissions they are granting, which can potentially lead to unintended consequences. The examination of such extensions is vital to gain insights into the methods employed by malicious software for the infiltration of systems, as is frequently the case. The following directories and files are therefore subject to examination in this context:

  

`/private/var/db/loadedkextmt.plist`
`/Library/Apple/System/Library/Extensions/`
`/System/Library/Extensions/`
`/Library/Extensions/`
`/Library/StagedExtensions/`
`/Library/SystemExtensions/`
`/Library/<Filesystems/macfuse.fs/Contents>/Extensions/`

  

## Network Configuration

MacOS stores network devices and their configurations in the following files:

`/Library/Preferences/SystemConfiguration/NetworkInterfaces.plist`
`/Library/Preferences/SystemConfiguration/preferences.plist`

  

## DHCP Leases

In macOS, a series of files containing the Dynamic Host Configuration Protocol (DHCP) history of network devices is stored in a directory designated by the interface name. This directory, represented as `<interfaceName>.plist`, contains information of great significance, including the date on which a particular network device received an IP address from a DHCP server.

`/private/var/db/dhcpclient/leases/`

  

## WiFi Connections

The following files contain data that is useful for digital forensics purposes, including information such as the identity of the wireless network to which a device is connected, the user who connected it, and the duration of the connection:

  

`/Library/Preferences/com.apple.wifi.known-networks.plist`
`/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`

## CLI History

To examine users' CLI command histories, you can look at the following files:

  

`/Users/<UserName>/.bash_history`
`/Users/<UserName>/.zsh_history`

  

## Application Usage Statistics

The following database file contains information on when each user ran which application and how long they used it.

`/Users/<UserName>/Library/Application Support/Knowledge/knowledgeC.db`


---
### Tools :
[+] Disk Utility
It is used for the management of storage devices on the system and you can view, obtain information about, and organize containers, volumes, and snapshots on their current disk(s) (for modern systems using APFS).
and used for create images of disks or specific folders.

[+] dd Command
used in Linux systems and performs copying at bit level.

Before starting to create the disk image, you need to unmount the disk that you will be imaging. Use the diskutil command again:
   `diskutil unmount /dev/diskX`
Next, use the “dd” command to specify the source and destination and start the disk imaging process.

What is the command used to mount/unmount disks in the macOS command line?  - diskutil


[+] Mac_apt (https://github.com/ydkhatri/mac_apt)
 Tool used to process disk images to extract useful data/metadata for digital forensics.

- Works on E01, VMDK, AFF4, DD, split-DD, DMG (no compression), SPARSEIMAGE, Velociraptor collected files (VR) & mounted images
- zlib, lzvn, lzfse compressed files are supported!
- Native HFS & APFS parser

| Available Plugins (artifacts parsed) | Description |
|-------------------------------------|-------------|
| APPLIST                              | Reads apps & printers installed and available for each user from appList.dat |
| ARD                                  | Reads ARD (Apple Remote Desktop) cached databases about app usage |
| AUTOSTART                            | Retrieves programs, daemons, and services set to start at boot/login |
| BASICINFO                            | Basic machine & OS configuration like SN, timezone, computer name, last logged-in user, HFS info |
| BLUETOOTH                            | Gets Bluetooth Artifacts |
| CHROMIUM                             | Read Chromium Browsers (Edge, Chrome, Opera, etc.) History, Top Sites, Downloads, and Extension info |
| CFURLCACHE                           | Reads CFURL cache to URLs, requests, and responses |
| COOKIES                              | Reads .binarycookies, .cookies files, and HSTS.plist for each user |
| DOCKITEMS                            | Reads the Dock plist for every user |
| DOCUMENTREVISIONS                    | Reads DocumentRevisions database |
| DOMAINS                              | Active Directory Domain(s) that the Mac is connected to |
| FILESHARING                          | Read shared folder info |
| FIREFOX                              | Read internet history from the Mozilla Firefox browser |
| FSEVENTS                             | Reads file system event logs (from .fseventsd) |
| IDEVICEBACKUPS                       | Reads and exports iPhone/iPad backup databases |
| IDEVICEINFO                          | Reads and exports connected iDevice details |
| IMESSAGE                             | Read iMessage chats |
| INETACCOUNTS                         | Retrieve configured internet accounts (iCloud, Google, LinkedIn, Facebook…) |
| INSTALLHISTORY                       | Software Installation History |
| MSOFFICE                             | Reads Word, Excel, PowerPoint, and other office MRU/accessed file paths |
| NETUSAGE                             | Read network usage data statistics per application |
| NETWORKING                           | Interfaces, last IP address, MAC address, DHCP |
| NOTES                                | Reads notes databases |
| NOTIFICATIONS                        | Reads Mac notification data for each user |
| PRINTJOBS                            | Parses CUPS spoiled print jobs to get information about files/commands sent to a printer |
| QUARANTINE                           | Read the quarantine database and .LastGKReject file |
| QUICKLOOK                            | Reads the QuickLook “index.sqlite” and carves thumbnails from “thumbnails.data” |
| RECENTITEMS                          | Recently accessed Servers, Documents, Hosts, Volumes & Applications from .plist and .sfl files. Also gets recent searches and places for each user |
| SAFARI                               | Internet history, downloaded file information, cookies, and more from Safari caches |
| SCREENSHARING                        | Reads the list of connected hosts with Screen Sharing |
| SAVEDSTATE                           | Gets window titles from Saved Application State info |
| SCREENTIME                           | Reads ScreenTime database for program and app usage |
| SPOTLIGHT                            | Reads the spotlight index databases |
| SPOTLIGHTSHORTCUTS                   | The user typed data in the spotlight bar & targeted document/app |
| SUDOLASTRUN                          | Gets last time sudo was used and a few other times earlier (if available) |
| TCC                                  | Reads Transparency, Consent, and Control (TCC) database |
| TERMINALSTATE                        | Reads Terminal saved state files which includes full text content of terminal windows |
| TERMSESSIONS                         | Reads Terminal (bash & zsh) history & sessions for every user |
| UNIFIEDLOGS                          | Reads macOS unified logging logs from .tracev3 files |
| USERS                                | Local & Domain user information - name, UID, UUID, GID, account creation & password set dates, pass hints, homedir & Darwin paths |
| UTMPX                                | Reads the utmpx file |
| WIFI                                 | Gets wifi network information |
| XPROTECT                             | Reads XProtect diagnostic files and XProtect Behavior Service database |

