### 1. Kerberoasting

This attack targets service accounts within the domain. When a user requests access to a network service, they receive a service ticket encrypted with that service account's password hash. Attackers request tickets for services that use weak, guessable passwords (often high-privilege, older accounts). They then take these encrypted tickets offline and attempt to crack the password hash through brute-force. Success gives them the plaintext password of a service account, which can often lead to elevated privileges.

### 2. AS-REP Roasting

This pre-authentication attack targets user accounts that have a specific setting disabled for legacy compatibility. Normally, a user proves their identity before receiving a login ticket. For these vulnerable accounts, an attacker can simply ask for a login ticket on their behalf, and the Domain Controller will send one encrypted with that user's password hash. The attacker then takes this hash offline to crack it, revealing the user's password without any authentication attempts or brute-forcing the server.

### 3. Pass-the-Hash (PtH)

This is a lateral movement technique that exploits the underlying authentication protocol. Instead of needing a user's plaintext password, an attacker who has obtained a user's password hash (e.g., from memory on a compromised machine) can use that hash directly to authenticate to another network resource. The system accepts the hash as proof of identity, allowing the attacker to move sideways across the network as that user without ever decrypting the password.

### 4. Golden Ticket Attack

This is a devastating persistence and privilege escalation attack. If an attacker manages to steal the password hash of the **KRBTGT** account (the domain's master key used to sign all authentication tickets), they can forge their own Kerberos Ticket Granting Tickets (TGTs). They can craft a "Golden Ticket" that grants them access to any resource, for any user (even fictional ones), for as long as they want. This gives them near-total control of the domain and is very difficult to detect.

### 5. Silver Ticket Attack

Similar to a Golden Ticket but more limited in scope. Instead of forging a master TGT, an attacker forges a Service Ticket for a specific service (like a file server or database). To do this, they need the password hash of the service account for that specific machine. While not as powerful as a Golden Ticket, it is stealthier, as it communicates directly with the target service and bypasses the Domain Controller entirely, making detection harder.

### 6. DCSync Attack

This is an impersonation attack used to steal password data directly from a Domain Controller. An attacker who has gained sufficient privileges can pose as a Domain Controller and use a directory replication protocol to "sync" user data with a rogue system. This request forces a legitimate Domain Controller to send over the password hashes for targeted user accounts, including highly privileged ones. It essentially tricks the DC into handing over its crown jewels.

### 7. LLMNR/NBT-NS Poisoning

This attack exploits legacy name resolution protocols on Windows networks. When a computer tries to connect to another resource (like `\fileserver`) but fails to find it via DNS, it broadcasts a request using these less secure protocols. An attacker on the network can listen for these broadcasts and respond, claiming to be the requested resource. This tricks the victim's computer into sending their username and a hashed version of their password directly to the attacker, which can then be relayed or cracked.

### 8. Credential Theft from LSASS Memory

The Local Security Authority Subsystem Service (LSASS) is the process in Windows that handles user logins and stores credentials in memory for single sign-on functionality. Attackers use techniques to dump or read the memory of the LSASS process from a compromised machine. This memory dump often contains password hashes, and sometimes even plaintext passwords, of users who have logged onto that system, including domain administrators.

### 9. AD CS (Certificate Services) Exploitation

This modern attack vector targets Microsoft's Public Key Infrastructure (PKI) in AD. Misconfigured or vulnerable Certificate Authorities can be abused in several ways. For example, an attacker with low privileges can request a certificate for a user or computer they don't own if templates are poorly configured. They can then use this certificate for authentication, often leading to privilege escalation by obtaining a certificate for a high-privilege account like a Domain Controller.

### 10. Password Spraying

This is a brute-force attack that trades stealth for breadth. Instead of rapidly guessing many passwords for a single user (which triggers lockouts), attackers "spray" a few commonly used passwords (e.g., "Spring2024!", "Company123") against every user account in the domain. This attack exploits weak, predictable passwords and the fact that many organizations have at least one account using a default or common password, allowing attackers to find a single entry point without triggering account lockout policies.