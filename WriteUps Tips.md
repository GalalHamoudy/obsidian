[ Note ! ] =========================================
What is the IPv4 address of the FTP server the suspect connected to?
 in the **filezilla.xml** When a user saves connections for FTP, SFTP, etc in Filezilla, it will save it in that file.
 ...../Users/John Doe/AppData/Roaming/FileZilla/filezilla.xml

[ Note ! ] ========================================= 
I went to a website called https://www.gps-coordinates.net/ and entered the GPS coordinates.

[ Note ! ] ========================================= 
**prefetch folder** contains information about programs you run on the system. This might indicate how many times a program is run on the system.

[ Note ! ] ========================================= 
find **Angry IP Scanner** and **Nmap**
Having some basic powershell knowledge I immediatley thought to check the **ConsoleHost_history.txt** file for any commands run by the user.

 ...../Users/John Doe/AppData/Roaming/Microsoft/windows/powershell/PSRedline

[ Note ! ] =========================================
We can run the following command to get the SHA256 hash value.
`CertUtil -hashfile ../file.mem sha256`

[ Note ! ] =========================================
How long did the suspect use Brave browser?
This one we use the plugin **windows.registry.userassist**

[ Note ! ] =========================================
I found the following useful site with a filter list for **TLS**.  
[Wireshark Filter for SSL Traffic](https://davidwzhang.com/2018/03/16/wireshark-filte-for-ssl-traffic/)

[ Note ! ] =========================================
We can go to the following website to check the MAC address.  
[macaddress.io](https://macaddress.io/)
By a given MAC address/OUI/IAB, retrieve OUI vendor information, detect virtual machines, manufacturer, locations, read the information encoded in the MAC, and get our research's results regarding any MAC address, OUI, IAB, IEEE.

[ Note ! ] =========================================
There is a file **contacts3.db**
The .db file is a sqlite database file.  
So I opened it up in sqlite3 tool

[ Note ! ] =========================================
I use this site to search for information about phone numbers. [Phone number](https://www.ipqualityscore.com/user/search)

[ Note ! ] =========================================
I checked the URLs of the site on the wayback URL.
kail>waybackurls hi.org >wayback.txt

[ Note ! ] =========================================
By using **[ViperMonkey](https://github.com/decalage2/ViperMonkey)** I was able to extract the VBA macros
ViperMonkey is a VBA Emulation engine written in Python, designed to analyze and deobfuscate malicious VBA Macros contained in Microsoft Office files (Word, Excel, PowerPoint, Publisher, etc).

[ Note ! ] =========================================

There is a Plugin called `editbox` in volatility

This plugin extracts text from the edit, combo, and list boxes of GUI applications that run on Windows.

[ Note ! ] =========================================

```
grep -Eo "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}" > 4 email address
grep -Eo "([0-9]{1,3}\\.){3}[0-9]{1,3}" > 4 IP
grep -Eo "\\b[0-9a-fA-F]{32}\\b" > 4 MD5
```

**-E:** Enables extended regular expressions.  
**-o:** Only prints the matching part of the line.
**\b:** Represents a word boundary, ensuring that the MD5 hash is not part of a larger word

[ Note ! ] =========================================
 A PST file is a personal storage table, which is a file format Microsoft programs use to store items like calendar events, contacts, and email messages.

[ Note ! ] =========================================
`pff-tools` , to extract all the emails, contacts, attachments etc
https://github.com/avranju/pff-tools

[ Note ! ] =========================================
python-[oletools](https://github.com/decalage2/oletools) :
Tools to analyze malicious documents

[ Note ! ] =========================================
Run Volatility "mftparser" plugin to analyze for potential MFT entries in memory.

[ Note ! ] =========================================

If you have a corrupted PNG file, you can use `pngcheck` to see which part is not exactly right. `pngcheck -v filename.png`

There is a tool that automate all of that for you and it works perfectly fine. `[Apreisolve](https://github.com/Zeecka/AperiSolve)`

Also, PDFs can contain scripts, and attackers take advantage of that. You can analyze PDFs by looking for Java script code inside them and stuff using [mpeepdf.py.](https://tho-le.medium.com/investigate-malicious-pdf-documents-with-mpeepdf-a-quick-user-guide-b7f31b3b013)

[ Note ! ] =========================================

we need to check RDPChache file which is located here `C:\Users\<USER>\AppData\Local\Microsoft\Terminal Server Client\Cache`

[ Note ! ] =========================================

[Virtuailor](https://github.com/0xgalz/Virtuailor) is an IDAPython tool that reconstructs vtables for C++ code written for intel architecture, both 32bit and 64bit code and AArch64 (New!). The tool constructed from 2 parts, static and dynamic.

[ Note ! ] =========================================
Volatility 2: Additional information can be gathered with kdbgscan if an appropriate profile wasn’t found with imageinfo

[ Note ! ] =========================================
Analyzing the Virtual Address Descriptor (VAD) tree helps in identifying hidden memory regions and injecting code in forensic investigations.

[ Note ! ] =========================================
## Disk and Filesystem Analysis
### Wine

Wine is great as you can run Windows apps on any linux distributions.

```bash
sudo apt update && sudo apt upgrade -y
sudo apt-get install wine64
```

#### [**dfir_ntfs**](https://github.com/msuhanov/dfir_ntfs)

Useful to parse NTFS filesystem and MFT file records.

```bash
pip3 install https://github.com/msuhanov/dfir_ntfs/archive/1.1.13.tar.gz
```

[ Note ! ] =========================================
## Artifact Analysis: Credentials
#### [Impacket](https://github.com/SecureAuthCorp/impacket)

LOVE this package, it’s very useful when needing to crack hashes or extract DPAPI blobs.

```bash
git clone https://github.com/SecureAuthCorp/impacket && cd impacket
python3 -m pip install .
```

#### [**dpapilab**](https://github.com/dfirfpi/dpapilab)

Similar to impacket, but can be more useful when needing to just see information.

```bash
git clone https://github.com/dfirfpi/dpapilab
```


The last command will normally print the secrets in the memory dump.

[ Note ! ] =========================================
## Artifact Analysis: Registry
#### **[Libregf](https://github.com/libyal/libregf)**

My second favourite tool to quickly look into registry hives:

```bash
sudo apt install libregf-utils
#usage
regfexport /path/to/hive > output.txt
```

[ Note ! ] =========================================
## Artifact Analysis: Prefetch
#### **[PrefetchRunCounts](https://github.com/dfir-scripts/prefetchruncounts)**

Never let me down…

```bash
git clone https://github.com/dfir-scripts/prefetchruncounts
sudo cp prefetchruncounts/prefetchruncounts.py /usr/bin/prefetchruncounts.py
prefetchruncounts.py /path/to/Prefetch
```

[ Note ! ] =========================================
## Artifact Analysis: Browser
#### **[firefox_decrypt](https://github.com/unode/firefox_decrypt)**

Decrypts saved firefox passwords.

```bash
https://github.com/unode/firefox_decrypt
python3 firefox_decrypt/firefox_decrypt.py /path/to/profiles/directory
```

#### [chrome_cache_viewer](https://www.nirsoft.net/utils/chrome_cache_view.html)

To run this application in Linux, you will need to have wine installed.

This tool is not limited to Chrome. For example, you can select Discord’s Cache directory and the conversations will be parsed and saveable in Json format.

```bash
wine chrome_cache_viewer.exe
```

#### [Hindsight](https://github.com/obsidianforensics/hindsight)

Great tool overall that parses multiple browsers and artifacts.

```bash
pip3 install pyhindsight
curl -sSL https://raw.githubusercontent.com/obsidianforensics/hindsight/master/install-js.sh | sh
```

[ Note ! ] =========================================
## Artifact Analysis: Emails
#### [pffexport](https://github.com/libyal/libpff)
Great tool overall that parses multiple browsers and artifacts.

```bash
sudo apt install pff-tools
pffexport
```

[ Note ! ] =========================================
## Artifact Analysis: EventLogs
#### [EVTXtract](https://github.com/williballenthin/EVTXtract)

The best !!! I love it so much. I used the library to write my own script to extract PowerShell Scripts from Event ID 4401.

```bash
pip3 install evtxtract

#one big file
evtxtract [file] > output

#split the records individually
evtxtract -s -o [output_dir] [file]
```


[ Note ! ] =========================================

#### [**swap_digger**](https://github.com/sevagas/swap_digger)

This is useful when you are dealing with a Linux disk image. It will analyze the swapfile.

```bash
sudo ./swap_digger.sh  /path/to/swapfile
```

[ Note ! ] =========================================

## Artifact Analysis: Credentials

#### [**Rekall**](https://github.com/google/rekall)

Rekall is depreciated, so you will need to install it manually and do some tweaks to make sure it works on your system. The **only reason** I suggest installing rekall is because it is **required** by **pypykatz**.

Rekall only works up to Python 3.6, so you will have to install that version of python on your system.

```bash
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt-get update
sudo apt install python3.6
sudo apt install python3.6-distutils
virtualenv --python=/usr/bin/python3.6 rekall_env
```

```bash
source rekall_env/bin/activate
python3.6 -m pip install --upgrade setuptools pip wheel
python3.6 -m pip install rekall-agent rekall
python3.6 -m pip install pypykatz
```

#### [**pypykatz**](https://github.com/skelsec/pypykatz)
LOVE this package, it mimics mimikatz but in a non-Windows environment.

```bash
pypykatz lsa rekall /path/to/memory.dump
```

#### **Windows Debugger + mimilib.dll**

If you are using a Windows VM/environment, you can use this combo to dump credentials/secrets from a memory dump.

First, download [Windbg](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools) and [mimilib.dll](https://github.com/gentilkiwi/mimikatz/releases). Then, load your memory file as a crash dump. Once that’s done do the following in the console:

```bash
.load /path/to/mimilib.dll
!process 0 0 lsass.exe
.process /r /p #address of EProcess
!mimikatz
```

The last command will normally print the secrets in the memory dump.

#### **Dpapi Dumper  

```bash
sudo mkdir /mnt/Windows
```

#### **[FindAES](https://sourceforge.net/projects/findaes/)  

This is a good tool, especially as it gives the offset where the key was found. You can then check the memory dump in a hex viewer to find the context for the found keys.

```bash
./findaes /path/to/memory.dump
```


[ Note ! ] =========================================

## Artifact Analysis: Misc

#### **Strings**
Basic, and honestly reliable.

```bash
strings -E l -A /path/to/memorydump > memorydump.txt
```
#### **Binwalk**
This is especially useful when dumping single process full memory.

```bash
binwalk --dd="*.extension" /path/to/process.dump
```


[ Note ! ] =========================================

The file is a **java scrip**t file, to run it in your Terminal, you need to use **node**:

```javascript
node just_some_js
```

[ Note ! ] =========================================

```
++++++++ [>++++++++++++>+++++++++++++<<-] >++++. -. >+++++++. <+. +.
```

This file appears to be in “**Brainfuck**” language. I’m going to one of my favorite [websites](https://www.dcode.fr/brainfuck-language) to **decode** this.

[ Note ! ] =========================================

To recover the zip file, I use this [**site**](https://users.cs.jmu.edu/buchhofp/forensics/formats/pkzip.html) which explains the structure of **PKZip archives** very well.

[ Note ! ] =========================================

We need to look into the Registry.  I HATE checking the registry in volatility, so I usually dump the hives and check them with **regripper.**
to get the MAC address of this machine's default gateway :

```bash
vol3 -f memdump.mem windows.registry.hivelist.HiveList --dump
rip.pl -r registry.SOFTWARE.0xd38985eb3000.hive -p networklist
```

[ Note ! ] =========================================

to get the name of the file that is hidden in the alternative data stream?

Let’s use the filescan plugin, and search for potential files ending with ‘:’ (which is an idicator of an alternative data stream).

```bash
vol3 -f memdump.mem windows.filescan.FileScan > filescan.txt
cat filescan.txt | grep -F ':'
#nothing

strings memdump.mem | grep -F ':' | grep -F '.txt' > matches
strings -a -el memdump.mem | grep -F ':' | grep -F '.txt' >> matches
```

[ Note ! ] =========================================

I like to use a [sandbox](https://onlinephp.io/) to quickly look at obfuscated code. By replacing the last call ‘eval’, with ‘echo’, we get the fully deobfuscated code and the flag!

[ Note ! ] =========================================

# Given the AppData folder, can you retrieve the wanted credentials?


The folder Google suggests that Chrome is installed, which may be where the credentials are stored.
Chrome saved passwords are stored in a file named ‘Local State‘. To decrypt the passwords, we also need the file ‘Login Data’. We can find and copy them to a tempdir.

```bash
mkdir tempdir
find AppData/Local/Google \( -name 'Local State' -o -name 'Login Data' \) -exec cp "{}" tempdir/ \;
#checking we are on the right track
jq . tempdir/'Local State'
```

We will need access to ‘CryptUnprotectData‘, which is normally unavailable. To do that, we need to extract the **masterkey** stored in the Protect directory.

```bash
cp -r AppData/Roaming/Microsoft/Protect tempdir/
```

JohnTheRipper jumbo version has a code to extract hashes from MasterKey files: **DPAPImk2john.py**. We need to run it and save the hash before bruteforcing it.

```bash
DPAPImk2john.py -S S-1-5-21-3702016591-3723034727-1691771208-1002 -mk tempdir/Protect/S-1-5-21-3702016591-3723034727-1691771208-1002/865be7a6-863c-4d73-ac9f-233f8734089d -c local> mkhash
john --wordlist=/usr/share/wordlists/rockyou.txt mkhash
```

Now that we found the user’s password, we can use impacket’s dpapi.py and get the actual Master Key.

```bash
dpapi.py masterkey -file tempdir/Protect/S-1-5-21-3702016591-3723034727-1691771208-1002/865be7a6-863c-4d73-ac9f-233f8734089d -sid S-1-5-21-3702016591-3723034727-1691771208-1002 -password ransom
```

With the Decrypted Master Key we are now capable of decrypting the Chrome passwords.

It took a while to put together something that would work on a Linux VM. Here is the final code :

```python
import os
import json
import sqlite3
import base64
from impacket.dpapi import DPAPI_BLOB
from binascii import unhexlify
from Cryptodome.Cipher import AES

local_state = 'tempdir/Local State'
login_data = 'tempdir/Login Data'
masterkey = unhexlify("138f089556f32b87e53c5337c47f5f34746162db7fe9ef47f13a92c74897bf67e890bcf9c6a1d1f4cc5454f13fcecc1f9f910afb8e2441d8d3dbc3997794c630")

def get_encrypted_key(localstate):
    with open(localstate, 'r') as f:
        encrypted_key = json.load(f)['os_crypt']['encrypted_key']
        encrypted_key = base64.b64decode(encrypted_key)
    f.close()
    return encrypted_key

def get_credentials(logindata):
    conn = sqlite3.connect(logindata)
    cursor = conn.cursor()
    cursor.execute('SELECT action_url, username_value, password_value FROM logins')
    rows = cursor.fetchall()
    url = rows[0][0]
    username = rows[0][1]
    encrypted_value = rows[0][2]
    return url, username, encrypted_value

def decrypt_creds(key, value):
    if value.startswith(b'v10'):
        nonce = value[3:3+12]
        ciphertext = value[3+12:-16]
        tag = value[-16:]
        cipher = AES.new(key, AES.MODE_GCM, nonce)
        password = cipher.decrypt_and_verify(ciphertext, tag)
    else:
        password = DPAPI_BLOB.decrypt(value)
    return password

encrypted_key = get_encrypted_key(local_state)
enc_key_blob = DPAPI_BLOB(encrypted_key[5:])
localstate_key = enc_key_blob.decrypt(masterkey)
url, username, encrypted_value = get_credentials(login_data)
password = decrypt_creds(localstate_key, encrypted_value)
print(" \n "  + " URL: " + url + " \n " + " Username: " + username + "\n " + " Decrypted Password: " + password.decode("utf-8"))
```


[ Note ! ] =========================================

 we need to first find any potential mail databases in the User’s directory. On Microsoft, these are often ost or pst files.
The Thunderbird database is named ‘INBOX’.


[ Note ! ] =========================================
we can get it by filtering by the event = 3 
< that will print all network connection detected.

|   |   |   |
|---|---|---|
|Sysmon|[1](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)|[Process creation](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90001)|
|Sysmon|[2](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90002)|[A process changed a file creation time](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90002)|
|Sysmon|[3](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90003)|[Network connection detected](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90003)|
|Sysmon|[4](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90004)|[Sysmon service state changed](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90004)|
|Sysmon|[5](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90005)|[Process terminated](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90005)|
|Sysmon|[6](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90006)|[Driver loaded](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90006)|
|Sysmon|[7](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90007)|[Image loaded](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90007)|
|Sysmon|[8](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90008)|[CreateRemoteThread](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90008)|
|Sysmon|[9](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90009)|[RawAccessRead](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90009)|
|Sysmon|[10](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90010)|[ProcessAccess](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90010)|
|Sysmon|[11](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90011)|[FileCreate](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90011)|
|Sysmon|[12](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90012)|[RegistryEvent (Object create and delete)](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90012)|
|Sysmon|[13](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90013)|[RegistryEvent (Value Set)](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90013)|
|Sysmon|[14](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90014)|[RegistryEvent (Key and Value Rename)](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90014)|
|Sysmon|[15](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90015)|[FileCreateStreamHash](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90015)|
|Sysmon|[16](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90016)|[Sysmon config state changed](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90016)|
|Sysmon|[17](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90017)|[Pipe created](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90017)|
|Sysmon|[18](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90018)|[Pipe connected](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90018)|
|Sysmon|[19](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90019)|[WmiEventFilter activity detected](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90019)|
|Sysmon|[20](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90020)|[WmiEventConsumer activity detected](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90020)|
|Sysmon|[21](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90021)|[WmiEventConsumerToFilter activity detected](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90021)|
|Sysmon|[22](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90022)|[DNSEvent](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90022)|
|Sysmon|[23](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90023)|[FileDelete](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90023)|
|Sysmon|[24](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90024)|[ClipboardChange](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90024)|
|Sysmon|[25](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90025)|[Process Tampering](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90025)|
|Sysmon|[26](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90026)|[File Delete Logged](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90026)|
|Sysmon|[27](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90027)|[File Block Executable](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90027)|
|Sysmon|[28](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90028)|[File Block Shredding](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90028)|
|Sysmon|[29](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90029)|[File Executable Detected](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90029)|
|Sysmon|[225](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90225)|[Error](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=90225)|

[ Note ! ] =========================================

Hadoop: The Apache Hadoop software library is a framework that allows for the distributed processing of large data sets across clusters of computers using simple programming models.

Hadoop YARN: Apache Hadoop YARN is the resource management and job scheduling technology in the open source Hadoop distributed processing framework. One of Apache Hadoop’s core components, YARN is responsible for allocating system resources to the various applications running in a Hadoop cluster and scheduling tasks to be executed on different cluster nodes.



[ Note ! ] =========================================

`C\Windows\System32\config` directory, which is the directory where the registry files are stored. Inside, we’ll find that the folder contains a dump of the system-wide **Windows** [**Registry Hives**](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives) (SYSTEM, SAM, SOFTWARE, SECURITY, etc.) >> we use Registry Explorer

the **Security Account Manager (SAM) Hive** which contains user information like username, group membership, and login information. 

the **SOFTWARE hive** which contains the information, settings, and preferences for software installed on the system, including the operating system. 

The **SYSTEM hive** contains the system’s configuration settings including the network interfaces.

the `Software\Microsoft\Windows\CurrentVersion\Uninstall` key would be the best place to identify installed applications.

**Shellbags** are a set of registry keys that store information about the view settings and preferences of folders as they are viewed in Windows Explorer.

Windows creates a number of additional artifacts when storing these properties in the registry, giving the investigator great insight into the folder, browsing history of a suspect, as well as details for any folder that might no longer exist on a system (due to deletion, or being located on a removable device).

 the shellbags stored within the **UsrClass.dat** hive. >> we use ShellBags Explorer.
`C\Users\Administrator\AppData\Local\Microsoft\Windows\UsrClass.dat`

to discover the modification time of a file executed from within the Downloads directory. To do this, we’re going to analyze the **Application Compatibility Cache (AppCompatCache)**, part of the SYSTEM registry hive. >> we use AppCompatCacheParser

Once the CSV file is generated, we’ll open it with yet another Eric Zimmerman tool, **Timeline Explorer**. This tool is a CSV viewer with robust filtering and sorting capabilities.

we need to identify the SHA1 file hash of a malicious file installed on the PC. The first step here is to determine which file is malicious. To do this, we’re going to check the **AmCache hive** to gain an understanding of the files that have been executed on the system. >> we use AmcacheParser

`C:\Windows\AppCompat\Programs\Amcache.hve`

To identify the file opened on the specified date/time, we’ll need to jump back to Registry Explorer and load the **NTUSER.DAT** artifact. This hive can be located at: `C\Users\Administrator\NTUSER.DAT`

we now need to determine the exact time a user on the system opened MSPaint. To accomplish this, we’ll continue using the available bookmarks to search against the `NTUSER.DAT` hive, this time selecting the “**RunMRU (Most recently run programs)**” bookmark.
to determine how long the application was open. For this task, we’ll use the “**UserAssist (Recently accessed items)**” bookmark to analyze the artifacts.

UserAssist is a feature in Windows that tracks the usage of executable files and applications launched by the user. It stores this information in the Windows Registry, which can be accessed by forensic analysts to reconstruct a timeline of application usage and user activity.




[ Note ! ] =========================================
List of Sysmon Event IDs for Threat Hunting :
https://systemweakness.com/list-of-sysmon-event-ids-for-threat-hunting-4250b47cd567



[ Note ! ] =========================================
By default Windows maintains a journal of filesystem activities in a file called \$Extend$UsnJrnl in a special data stream called $J. This stream contains records of filesystem operations, primarily to allow backup applications visibility into the files that have been changed since the last time a backup was run.

we’ll use Eric Zimmerman’s **_MFTECmd_** to parse and extract some information about the _Confidential_ directory and the files within it

 Since we are pointing to the \**\$J** (journal) file, we’ll also provide the path to the **$MFT** so we can resolve the parent path as suggested by the help file.
 
MFTECmd.exe -f "C:\Users\LetsDefend\Desktop\ChallengeFile\C\$Extend\$J" -m "C:\Users\LetsDefend\Desktop\ChallengeFile\C\$MFT" --csv C:\Users\LetsDefend\Desktop\<name-of-output>.csv