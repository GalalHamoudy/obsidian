[ Note ! ]---------------
What is the IPv4 address of the FTP server the suspect connected to?
 in the **filezilla.xml** When a user saves connections for FTP, SFTP, etc in Filezilla, it will save it in that file.
 ...../Users/John Doe/AppData/Roaming/FileZilla

[ Note ! ]--------------- 
I went to a website called https://www.gps-coordinates.net/ and entered the GPS coordinates.

[ Note ! ]--------------- 
**prefetch folder** contains information about programs you run on the system. This might indicate how many times a program is run on the system.

[ Note ! ]--------------- 
find **Angry IP Scanner** and **Nmap**
Having some basic powershell knowledge I immediatley thought to check the **ConsoleHost_history.txt** file for any commands run by the user.

 ...../Users/John Doe/AppData/Roaming/Microsoft/windows/powershell/PSRedline

[ Note ! ]---------------
We can run the following command to get the SHA256 hash value.
`CertUtil -hashfile ../file.mem sha256|`

[ Note ! ]---------------
How long did the suspect use Brave browser?
This one we use the plugin **windows.registry.userassist**

[ Note ! ]---------------
I found the following useful site with a filter list for **TLS**.  
[Wireshark Filter for SSL Traffic](https://davidwzhang.com/2018/03/16/wireshark-filte-for-ssl-traffic/)

[ Note ! ]---------------
We can go to the following website to check the MAC address.  
[macaddress.io](https://macaddress.io/)
By a given MAC address/OUI/IAB, retrieve OUI vendor information, detect virtual machines, manufacturer, locations, read the information encoded in the MAC, and get our research's results regarding any MAC address, OUI, IAB, IEEE.

[ Note ! ]---------------
There is a file **contacts3.db**
The .db file is a sqlite database file.  
So I opened it up in sqlite3

[ Note ! ]---------------
I use this site to search for information about phone numbers. [Phone number](https://www.ipqualityscore.com/user/search)

[ Note ! ]---------------
I checked the URLs of the site on the wayback URL.
kail>waybackurls hi.org >wayback.txt


[ Note ! ]---------------
By using **[ViperMonkey](https://github.com/decalage2/ViperMonkey)** I was able to extract the VBA macros
ViperMonkey is a VBA Emulation engine written in Python, designed to analyze and deobfuscate malicious VBA Macros contained in Microsoft Office files (Word, Excel, PowerPoint, Publisher, etc).

[ Note ! ]---------------

There is a Plugin called `editbox` in volatility

This plugin extracts text from the edit, combo, and list boxes of GUI applications that run on Windows.

[ Note ! ]---------------

```
grep -Eo "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}" > 4 email address
grep -Eo "([0-9]{1,3}\\.){3}[0-9]{1,3}" > 4 IP
grep -Eo "\\b[0-9a-fA-F]{32}\\b" > 4 MD5
```

**-E:** Enables extended regular expressions.  
**-o:** Only prints the matching part of the line.
**\b:** Represents a word boundary, ensuring that the MD5 hash is not part of a larger word

[ Note ! ]---------------
 A PST file is a personal storage table, which is a file format Microsoft programs use to store items like calendar events, contacts, and email messages.


[ Note ! ]---------------
`pff-tools` , to extract all the emails, contacts, attachments etc
https://github.com/avranju/pff-tools


[ Note ! ]---------------

python-[oletools](https://github.com/decalage2/oletools) :
Tools to analyze malicious documents


[ Note ! ]---------------
Run Volatility "mftparser" plugin to analyze for potential MFT entries in memory.


[ Note ! ]---------------

If you have a corrupted PNG file, you can use `pngcheck` to see which part is not exactly right. `pngcheck -v filename.png`

There is a tool that automate all of that for you and it works perfectly fine. `[Apreisolve](https://github.com/Zeecka/AperiSolve)`

Also, PDFs can contain scripts, and attackers take advantage of that. You can analyze PDFs by looking for Java script code inside them and stuff using [mpeepdf.py.](https://tho-le.medium.com/investigate-malicious-pdf-documents-with-mpeepdf-a-quick-user-guide-b7f31b3b013)

[ Note ! ]---------------

we need to check RDPChache file which is located here `C:\Users\<USER>\AppData\Local\Microsoft\Terminal Server Client\Cache`

[ Note ! ]---------------

[Virtuailor](https://github.com/0xgalz/Virtuailor) is an IDAPython tool that reconstructs vtables for C++ code written for intel architecture, both 32bit and 64bit code and AArch64 (New!). The tool constructed from 2 parts, static and dynamic.

[ Note ! ]---------------
Volatility 2: Additional information can be gathered with kdbgscan if an appropriate profile wasn’t found with imageinfo

[ Note ! ]---------------


[ Note ! ]---------------


[ Note ! ]---------------


[ Note ! ]---------------