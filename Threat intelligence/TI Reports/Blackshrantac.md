## Executive Summary:

- BlackShrantac is an active Ransomware-as-a-Service (RaaS) operation.
- The group is characterized by an exceptionally high operational tempo, claiming 17 victims globally within its first 34 days of operation.
- BlackShrantac focuses strategically on high-leverage industries critical to the global economy. The top targeted sectors include Manufacturing, Technology, and Financial Services

Ransomware Type : Data Broker
First Discovered : 2025-09-17
Last Discovered : 2025-10-20
Victims : 17
URL : http://jvkpexgkuaw5toiph7fbgucycvnafaqmfvakymfh5pdxepvahw3xryqd.onion
Classification : 	Active RaaS organization using a dedicated malware variant (Trojan:Win64/Blackshrantac.Z). 
TOX ID :	EFE1A6E5C8AF91FB1EA3A170823F5E69A85F866CF33A4370EC467474916941042E29C2EA4930

Intelligence indicates BlackShrantac's TTPs include phishing with malicious attachments (MITRE T1566.001) and supply chain compromise (T1195.002) for initial access. For execution, the group utilizes command line interpreters like PowerShell, Windows Command Shell, and Bash (T1059.001, T1059.003, T1059.004).

To maintain their foothold, the group establishes persistence through methods like creating scheduled tasks or modifying registry run keys and startup folders (T1547.001, T1053.005).
  
Detection Indicators:  
Unlike traditional ransomware, BlackShrantac’s signature activity is massive data staging and exfiltration, not file encryption.  
Key red flag: Anomalous high-volume outbound data transfers without clear operational justification.  
  
source :
https://www.ransomware.live/group/blackshrantac
https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Trojan:Win64/Blackshrantac.Z!MTB&ThreatID=2147954864
https://www.ransomlook.io/groups
https://breach.house/country/EG