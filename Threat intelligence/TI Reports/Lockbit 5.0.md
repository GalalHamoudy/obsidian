## source :

https://www.trendmicro.com/en_us/research/25/i/lockbit-5-targets-windows-linux-esxi.html
https://blog.checkpoint.com/research/lockbit-returns-and-it-already-has-victims/
https://documents.trendmicro.com/images/uploads/20250924%20New%20LockBit%205.0%20Targets%20Multiple%20Platforms-70jqtcf.txt
https://www.vectra.ai/blog/lockbit-is-back-whats-new-in-version-5-0
https://socradar.io/blog/lockbit-5-0-ransomware-cartel-what-you-need-to-know/
https://www.broadcom.com/support/security-center/protection-bulletin/new-lockbit-ransomware-variant-5-0-found-in-the-wild
https://www.picussecurity.com/resource/blog/the-lockbit-comeback-how-the-group-evolved-after-a-global-takedown
https://osintteam.blog/digging-into-lockbit-5-0-a-casual-review-insight-298dd8facb85
https://github.com/TheRavenFile/Daily-Hunt/blob/main/LockBit%205.0%20Ransomware
https://theravenfile.com/2025/05/09/lockbit-ransomware-leaked/


## Executive Summary:

LockBit uses strategy called **"double extortion"**
the victim's data is exfiltrated or stolen first, and when the victim's data is encrypted, the victim will be threatened that the data will be disseminated if the victim does not want to pay the ransom.

LockBit 3.0 uses strategy called **"triple extortion"**
attackers will carry out DDoS attacks after the encryption and data exfiltration stages have been carried out.

LockBit 3.0 is a form of version development in the form of merging source code with "Conti ransomware".

LockBit 4.0 uses an anti-analysis technique using **a UPX packer**

In September 2025, there was an issue that said that the DragonForce ransomware gang formed **a joint affiliation** with the Qilin and LockBit ransomware gangs, hence the LockBit ransomware gang called itself **LockBit 5.0.**

LockBit 5.0 panel page:
```
lockbitsuppyx2jegaoyiw44ica5vdho63m5ijjlmfb7omq3tfr3qhyd.onion  
lockbitfbinpwhbyomxkiqtwhwiyetrbkb4hnqmshaonqxmsrqwg7yad.onion  
lockbitapt67g6rwzjbcxnww5efpg4qok6vpfeth7wx3okj52ks4wtad.onion
```

LockBit signatures:
```
HEUR:Trojan-Ransom.Win32.Lockbit.pef
Trojan-Ransom.Win32.Lockbit.five
95daa771a28eaed76eb01e1e8f403f7c #MD5 of file readme
ca93d47bcc55e2e1bd4a679afc8e2e25 #MD5 of sample
a1539b21e5d6849a3e0cf87a4dc70335 #MD5 of sample
e818a9afd55693d556a47002a7b7ef31 #MD5 of Smokeloader
IP: 205.185.116.233
Domain: karmaO[.]xyz
ASN: 53667
RDP: 205.185.116.233:3389
Name: WINDOWS-401V6QI
Server: Apache/2.4.58 (Win64) OpenSSL/3.1.3
```

YARA-rules "`win_ransom_Lockbit5`" created by the @RussianPanda

LockBit Group uses Smokeloader in their attacks


## Behavioral Analysis & Signature Detection:

1- The encryptor performs a self-delete process. 
This technique is commonly used as an evasion from the security system or monitoring system that exists on an infected system.
2- When the self-delete process takes place, there are other processes running in parallel that may be thread-hijacking or code-injection techniques. 
This is evidenced by the existence of several signatures below, such as
- RenameItSelf → the process encryptor tries to change the process name. The name of this process may be related to other processes already present within the infected system, leading to `defrag.exe`.
- AdjustPrivilegeToken → the encryptor process executes a privilege-escalation technique so that the encryptor has access rights to be able to take control of `defrag.exe` process.
- WriteProcessMemory → a process when privilege-escalation is successful, the encryptor writes the memory to `defrag.exe` or take control.
Thread-hijacking or code-injection processes are possible in these processes, where the encryptor injects the payload or ransomware's main process into defrag.exe process. After the encryptor successfully performs the injection, it will self-delete.

3- defrag.exe encrypt or modify files stored on infected systems. In addition, in parallel, the file-dropping process in the form of "ReadMeforDecrypt.txt" ransomnote is also running.

In addition, defrag.exe detected to have discovered an infected system as evidenced by the discovery of a file-sharing system `(\?? \Q: , \?? \W: , etc.)`, which indicates the existence of a lateral-movement technique through file-sharing.

Anti-Forensics and Defense Evasion:
1-ETW Patching
The malware patches the EtwEventWrite API in user mode by overwriting the function's beginning with a 0xC3 (RET) instruction. This effectively disables Windows Event Tracing, preventing security solutions from monitoring its activities.

2-Service Termination
It contains a hardcoded list of 63 service name hashes. The malware hashes the names of running services and compares them against this list. If a match is found, the service is terminated to disable security tools or backup solutions. 
Example Service Hashes: FEF56F15, BEC3470B, 9757464D, 88CE6B8E, 826AC445...

3-Log Clearing
Upon the completion of the encryption process, the EvtClearLog API is used to wipe all event logs, removing traces of the attack.


