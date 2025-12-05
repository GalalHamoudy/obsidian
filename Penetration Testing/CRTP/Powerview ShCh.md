## Domain Enumeration

Get current domain :
```
Get-Domain
```

Get object of another domain
```
Get-Domain
```

Get domain SID for the current domain
```
Get-DomainSID
```

Get domain policy for the current domain
```
Get-DomainPolicyData
```

Get domain controllers for the current domain
```
Get-DomainController
```

Get domain controllers for another domain
```
Get-DomainController -Domain moneycorp.local
```

Get a list of users in the current domain
```
Get-DomainUser
Get-DomainUser -Identity student1
```

Get list of all properties for users in the current domain
```
Get-DomainUser -Identity student1 -Properties *
Get-DomainUser -Properties samaccountname, logonCount
```

Search for a particular string in a user's attributes:
```
Get-DomainUser -LDAPFilter "Description =*built*" | Select name, Description
```

Get a list of computers in the current domain
```
Get-DomainComputer | select Name
Get-DomainComputer -Operatingsystem "*Server 2022*"
Get-DomainComputer -Ping
```

Get all the groups in the current domain
```
Get-DomainGroup | select Name
Get-DomainGroup -Domain <targetdomain>
```

Get all groups containing the word "admin" in group name
```
Get-DomainGroup *admin*
```

Get all the members of the Domain Admins group
```
Get-DomainGroupMember -Identity "Domain Admins" -Recurse
```

Get the group membership for a user:
```
Get-DomainGroup -UserName "student1"
```

List all the local groups on a machine 
(needs administrator privs on non-dc machines) :
```
Get-NetLocalGroup -ComputerName dcorp-dc
```

Get members of the local group "Administrators" on a machine 
(needs administrator privs on non-dc machines) :
```
Get-NetLocalGroupMember -ComputerName dcorp-dc -GroupName Administrators
```

Get actively logged users on a computer
(needs local admin rights on the target)
```
Get-NetLoggedon -ComputerName dcorp-adminsrv
```

Get locally logged users on a computer 
(needs remote registry on the target - started by-default on server OS)
```
Get-LoggedonLocal -ComputerName dcorp-adminsrv
```

Get the last logged user on a computer 
(needs administrative rights and remote registry on the target)
```
Get-LastLoggedon -ComputerName dcorp-adminsrv
```

Find shares on hosts in current domain.
```
Invoke-ShareFinder -Verbose
```

Find sensitive files on computers in the domain
```
Invoke-FileFinder -Verbose
```

Get all fileservers of the domain
```
Get-NetFileServer
```

Get the ACLs associated with the specified object
```
Get-DomainObjectAcl -SamAccountName student1 -ResolveGUIDs
```

Get the ACLs associated with the specified prefix to be used for search
```
Get-DomainObjectAcl -SearchBase "LDAP://CN=Domain Admins, CN=Users, DC=dollarcorp, DC=moneycorp, DC=local" -ResolveGUIDs -Verbose
```

Search for interesting ACEs
```
Find-InterestingDomainAcl -ResolveGUIDS
```

Get the ACLs associated with the specified path
```
Get-PathAcl -Path "\\dcorp-dc.dollarcorp.moneycorp.local\sysvol"
```

Get list of GPO in current domain.
```
Get-DomainGPO
Get-DomainGPO -ComputerIdentity dcorp-student1
```

Get GPO(s) which use Restricted Groups or groups.xml for interesting users
```
Get-DomainGPOLocalGroup
```

Get users which are in a local group of a machine using GPO
```
Get-DomainGPOComputerLocalGroupMapping -ComputerIdentity dcorp-student1
```

Get machines where the given user is member of a specific group
```
Get-DomainGPOUserLocalGroupMapping -Identity student1 -Verbose
```

Get OUs in a domain
```
Get-Domai nOU
Get-ADOrganizationalUnit -Filter * -Properties
```

Get GPO applied on an OU. Read GPOname from gplink attribute from
```
Get-NetOU
Get-DomainGPO -Identity "{0D1CC23D-1F20-4EEE-AF64-D99597AE2A6E}"
```

Get a list of all domain trusts for the current domain
```
Get-DomainTrust
Get-DomainTrust -Domain us.dollarcorp.moneycorp.local
```

Get details about the current forest
```
Get-Forest
Get-Forest -Forest eurocorp. local
```

Get all domains in the current forest
```
Get-ForestDomain
Get-ForestDomain -Forest eurocorp. local
```

Get all global catalogs for the current forest
```
Get-ForestGlobalCatalog
Get-ForestGlobalCatalog -Forest eurocorp. local
```

Map trusts of a forest (no Forest trusts in the lab)
```
Get-ForestTrust
Get-ForestTrust -Forest eurocorp. local
```


---
## Lab

To list a specific property of all the users, we can use the select-object (or its alias select) cmdlet.
For example, to list only the samaccountname run the following command:
```powershell
Get-DomainUser | select -ExpandProperty samaccountname
```

To see details of the Domain Admins group:
```powershell
Get-DomainGroup -Identity "Domain Admins"
```

To enumerate members of the Domain Admins group:
```powershell
Get-DomainGroupMember -Identity "Domain Admins"
```

to query the root domain as Enterprise Admins group is present only in the root of a forest
```powershell
Get-DomainGroupMember -Identity "Enterprise Admins" -Domain moneycorp.local
```

to check for modify rights/permissions for the studentx
```powershell
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "studentx"}
```

Since studentx is a member of the RDPUsers group, let us check permissions for it too
```powershell
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"}
```

to list all the computers in the DevOps OU
```powershell
(Get-DomainOU -Identity DevOps).distinguishedname | %{Get-DomainComputer -SearchBase $_} | select name
```

to enumerate GPO applied on the DevOps OU, we need the name of the policy from the gplink attribute from the OU
```
(Get-DomainOU -Identity DevOps).gplink
```
the result : [LDAP://cn={**0BF8D01C-1F62-4BDC-958C-57140B67D147**},cn=policies,cn=system,DC=dollarcorp,DC=moneycorp,DC=local;0]
Next :
```
Get-DomainGPO -Identity '{0BF8D01C-1F62-4BDC-958C-57140B67D147}'
```

It is possible to hack both the commands together in a single command (profiting from the static length for GUIDs):
```
Get-DomainGPO -Identity (Get-DomainOU -Identity DevOps).gplink.substring(11,(Get-DomainOU -Identity DevOps).gplink.length-72)
```

to list only the external trusts in the moneycorp.local forest
```
Get-ForestDomain | %{Get-DomainTrust -Domain $_.Name} | ?{$_.TrustAttributes -eq "FILTER_SIDS"}
```

To identify external trusts of the dollarcorp domain
```
Get-DomainTrust | ?{$_.TrustAttributes -eq "FILTER_SIDS"}
```

enumerate trusts for eurocorp.local forest
```
Get-ForestDomain -Forest eurocorp.local | %{Get-DomainTrust -Domain $_.Name}
```

Find all machines on the current domain where the current user has local admin access
```
Find-LocalAdminAccess -Verbose
```

Find computers where a domain admin (or specified user/group) has sessions:
```
Find-DomainUserLocation -Verbose
Find-DomainUserLocation -UserGroupIdentity "RDPUsers"
```

Find computers where a domain admin session is available and current user has admin access (uses Test-AdminAccess).
```
Find-DomainUserLocation -CheckAccess
```

Find computers (File Servers and Distributed File servers) where a domain admin session is available.
```
Find-DomainUserLocation -Stealth
```

List sessions on remote machines (https://github.com/Leo4j/Invoke-SessionHunter)
```
Invoke-SessionHunter -FailSafe
```

An opsec friendly command would be (avoid connecting to all the target machines by specifying targets)
```
Invoke-SessionHunter -NoPortScan -Targets C:\AD\Tools\servers.txt
```

We can connect to dcorp-adminsrv using winrs as the student user
```
winrs -r:dcorp-adminsrv cmd
```

We can also use PowerShell Remoting
```
Enter-PSSession -ComputerName dcorp-adminsrv.dollarcorp.moneycorp.local
```





