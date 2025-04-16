### **Active Directory (AD) - Key Uses**

Active Directory (AD) is a **directory service** by Microsoft, primarily used in Windows networks for:
1. **Centralized User Management**
    - Create, manage, and authenticate users/groups across a network.
2. **Single Sign-On (SSO)**
    - Users log in once to access multiple services (files, emails, apps).
3. **Access Control & Permissions**
    - Define who can access what (e.g., shared folders, printers).
4. **Group Policy (GPO) Enforcement**
    - Apply security policies (password rules, firewall settings) across all devices.
5. **Device Management**
    - Control domain-joined PCs/servers (updates, restrictions).
6. **Security & Auditing**
    - Monitor logins, track changes, and detect suspicious activity.
7. **DNS & Network Services**
    - Helps in locating resources (like servers) within the network.

Domain: 
A domain is a logical grouping of network objects (computers, users, devices) that share a common security database. Each domain has its own unique name and security policies.

Domain Controller (DC): 
A domain controller is a server that runs the Active Directory Domain Services (AD DS) role. It stores a copy of the Active Directory database and authenticates users and computers in the domain.

Organizational Units (OUs): 
OUs are containers within a domain that allow administrators to organize and manage objects such as users, groups, and computers. OUs can have their own policies applied to them.

Group Policy: 
Group Policies are a set of configurations that define how computers and users operate within an Active Directory environment. They control various aspects of the user interface, desktop environment, security, and other settings.

Active Directory Authentication: 
Authentication is the process of verifying the identity of users, computers, and services attempting to access resources within an Active Directory environment. It ensures secure access to network resources and helps protect against unauthorized access. 
- NTLM
- Kerberos
- LDAP

### NTLM Authentication

NTLM (NT LAN Manager): NTLM is an older authentication protocol used in Windows environments. While still supported for compatibility reasons, it's less secure than newer protocols like Kerberos.
NTLM authenticates users through a challenge-response mechanism. This process consists of three messages:

- The user shares their username, password, and domain name with the client.
- The client develops a scrambled version of the password — or hash — and deletes the full password.
- The client passes a plain text version of the username to the relevant server.
- The server replies to the client with a challenge, which is a 16-byte random number.
- In response, the client sends the challenge encrypted by the hash of the user’s password.
- The server then sends the challenge, response, and username to the domain controller (DC).
- The DC retrieves the user’s password from the database and uses it to encrypt the challenge.
- The DC then compares the encrypted challenge and client response. If these two pieces match, then the user is authenticated and access is granted.

### Kerberos Authentication

Kerberos: Kerberos is the default authentication protocol used in Active Directory environments. It offers strong authentication and supports features like mutual authentication, ticket-based access control, and single sign-on (SSO).

A Kerberos ticket is essentially a cryptographic token that serves as proof of the user's identity. It contains information such as the user's identity, the ticket's expiration time, the ticket-granting ticket (TGT), and session key information.

Kerberos tickets are used primarily for authentication and authorization purposes in a distributed network environment. When a user logs into a Kerberos-enabled system, they are issued a Ticket Granting Ticket (TGT) after successfully authenticating to the Key Distribution Center (KDC), which is the central authentication server in a Kerberos realm. This TGT can then be used to request service tickets from the KDC for accessing specific services within the network.

### LDAP 

LDAP (Lightweight Directory Access Protocol): LDAP is a protocol used for accessing and managing directory information stored in Active Directory. While not an authentication protocol itself, LDAP can be used in conjunction with other protocols for authentication and directory services.

- LDAP authentication involves clients sending authentication requests to Active Directory domain controllers using the LDAP protocol. 
- The domain controllers verify the provided credentials against the directory database and grant access if authentication is successful.


Trust Relationship :
A trust relationship is a logical link established between domains or forests to allow users, computers, and services in one domain or forest to access resources in another domain or forest.
Types of Trusts:
- One-Way Trust: Allows access from one domain to another, but not vice versa.
- Two-Way Trust: Allows bidirectional access between two domains.
- Forest Trust: Establishes a trust relationship between entire forests, enabling resource access across forest boundaries.

Pivoting :
Pivoting allows attackers to move from one compromised system or account to another within the network, exploiting trust relationships and misconfigurations to escalate privileges and access sensitive resources.
Techniques:
- Pass-the-Hash (PtH)
- Pass-the-Ticket (PtT)
- Overpass-the-Hash (OtH)
- Kerberoasting
- Golden Ticket
