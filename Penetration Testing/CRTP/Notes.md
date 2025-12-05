Security Groups vs OUs :
- **OUs** are handy for **applying policies** to users and computers, which include specific configurations that pertain to sets of users depending on their particular role in the enterprise. Remember, a user can only be a member of a single OU at a time, as it wouldn't make sense to try to apply two different sets of policies to a single user.
- **Security Groups**, on the other hand, are used to **grant permissions over resources**. For example, you will use groups if you want to allow some users to access a shared folder or network printer. A user can be a part of many groups, which is needed to grant access to multiple resources.

---

Password Spraying

```
python ntlm_passwordspray.py -u <userfile> -f <fqdn> -p <password> -a <attackurl>
```

We provide the following values for each of the parameters:

userfile - Textfile containing our usernames - _"usernames.txt"_
fqdn- Fully qualified domain name associated with the organisation that we are attacking - _"za.tryhackme.com"_
password - The password we want to use for our spraying attack - _"Changeme123"_
attackurl - The URL of the application that supports Windows Authentication - _"http://ntlmauth.za.tryhackme.com"_

---

LDAP Pass-back Attacks  

However, one other very interesting attack can be performed against LDAP authentication mechanisms, called an LDAP Pass-back attack. This is a common attack against network devices, such as printers, when you have gained initial access to the internal network, such as plugging in a rogue device in a boardroom.

LDAP Pass-back attacks can be performed when we gain access to a device's configuration where the LDAP parameters are specified. This can be, for example, the web interface of a network printer. Usually, the credentials for these interfaces are kept to the default ones, such as `admin:admin` or `admin:password`. Here, we won't be able to directly extract the LDAP credentials since the password is usually hidden. However, we can alter the LDAP configuration, such as the IP or hostname of the LDAP server. In an LDAP Pass-back attack, we can modify this IP to our IP and then test the LDAP configuration, which will force the device to attempt LDAP authentication to our rogue device. We can intercept this authentication attempt to recover the LDAP credentials.

---
GPO distribution

GPOs are distributed to the network via a network share called `SYSVOL`, which is stored in the DC. All users in a domain should typically have access to this share over the network to sync their GPOs periodically. The SYSVOL share points by default to the `C:\Windows\SYSVOL\sysvol\` directory on each of the DCs in our network.
PS C:\> gpupdate /force

---
LDAP  

Another method of AD authentication that applications can use is Lightweight Directory Access Protocol (LDAP) authentication. LDAP authentication is similar to NTLM authentication. However, with LDAP authentication, the application directly verifies the user's credentials. The application has a pair of AD credentials that it can use first to query LDAP and then verify the AD user's credentials.

LDAP authentication is a popular mechanism with third-party (non-Microsoft) applications that integrate with AD. These include applications and systems such as:

- Gitlab
- Jenkins
- Custom-developed web applications
- Printers
- VPNs

---

Execution Policy 
Several ways to bypass
	powershell -ExecutionPolicy bypass
	powershell -c <cmd>
	powershell -encodedcommand
	$env:PSExecutionPolicyPreference="bypass"


Bypassing PowerShell Security
We will use Invisi-Shell (https://github.com/OmerYa/Invisi-Shell) for bypassing the security controls in PowerShell.

We can use the AMSITrigger (https://github.com/RythmStick/AMSITrigger) or DefenderCheck (https://github.com/t3hbb/DefenderCheck) to identify code and strings from a binary or script that Windows Defender may flag.

For full obfuscation of PowerShell scripts, see Invoke-Obfuscation (https://github.com/danielbohannon/Invoke-Obfuscation). That is used for obfuscating the AMSI bypass in the course!

Steps to avoid signature based detection are pretty simple:
1) Scan using AMSITrigger
2) Modify the detected code snippet
3) Rescan using AMSITrigger
4) Repeat the steps 2 & 3 till we get a result as “AMSI_RESULT_NOT_DETECTED” or “Blank”


Tools such as Codecepticon (https://github.com/Accenture/Codecepticon) can also obfuscate the source code to bypass any signature-related detection.

A great tool to obfuscate the compiled binary is ConfuserEx (https://mkaring.github.io/ConfuserEx/)

ConfuserEx is a free .NET obfuscator, which can stop AVs from performing signature based detection.