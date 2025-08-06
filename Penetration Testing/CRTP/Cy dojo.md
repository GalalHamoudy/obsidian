Event ID:
https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx

Labs :
https://tryhackme.com/module/hacking-active-directory

More:
https://github.com/Orange-Cyberdefense/GOAD
https://www.hackthebox.com/blog/active-directory-penetration-testing-cheatsheet-and-guide


---
4768 : TGT was requested
4769 : ST was requested
4770 : ST was renewed
4624 : succeed login in service server using ST

---
Kerberoast attack 
tools:
impacket's GetUserSPNs.py 
invoke-kerberoast - part of powerSploit
steps:
1- query the AD for accounts with an SPN
2-Request RC4 ST from the DC using these SPN values
3- Extract received Services Tickets and dump them to file
4- launch offline brute force attack
detect:
in 4769 : the account and service names not end with $ + ticket encryption will be 0x17 which is RC4
in 4662 : the same account name with many object type and name (enumeration)
in 5145 : audit attempts to access files and folders on a shared folder

---
Kerberos: Domain Dominance

Q - how hackers could access the NTDS.dit file ? 


