Daily tasks of a threat intelligence analyst :

. Monitoring and Data Collection
- **Reviewing Intelligence Feeds:** Starting the day by analyzing incoming data from commercial and free threat feeds, (OSINT), government advisories (e.g., CISA), and industry-specific ISACs (Information Sharing and Analysis Centers).
- **Dark Web & Surface Web Surveillance:** Monitoring underground hacking forums, Telegram channels, and code repositories (like GitHub) for leaked company data, mentions of the organization, or new attack methodologies.
- **Checking Alerting Consoles:** Reviewing security alerts (SIEM/EDR) for Indicators of Compromise (IOCs) such as malicious IPs, file hashes, or domain names that might indicate an active or attempted breach.

. Analysis and Investigation
- **Analyzing Threats (TTPs):** Analyzing the Tactics, Techniques, and Procedures (TTPs) of threat actors to understand their motivations, capabilities, and target profiles.
- **Malware Analysis:** Dissecting malware samples, often using sandboxing techniques, to identify active techniques and develop countermeasures.
- **Hypothesis Generation:** Proactively creating hypotheses about potential security breaches, such as "Is a specific Ransomware-as-a-Service (RaaS) group targeting our industry sector?".
- **Threat Actor Profiling:** Tracking specific Advanced Persistent Threats (APTs) or criminal groups to predict their next moves.

. Reporting and Dissemination
- **Creating Intel Reports:** Producing actionable intelligence reports for various audiences, including technical analysis for incident responders and high-level summaries for executive decision-makers.
- **Briefing Security Teams:** Regularly meeting with SOC (Security Operations Center) analysts, incident response teams, and leadership to share insights on emerging threats.
- **Refining Threat Models:** Updating internal threat models and risk assessment documents to ensure defenses are aligned with the current threat landscape.

. Collaboration and Operationalization
- **Incident Response Support:** Providing context, such as threat actor background and TTPs, to incident response teams during an active security incident.
- **Threat Hunting:** Using intelligence to proactively search for hidden threats within the network.
- **Tooling Optimization:** Tuning SIEM or EDR systems with new indicators to improve detection rates and reduce false positives.

---

Threat intelligence feeds source :

. Open-Source & Community Feeds (Free)
- **AlienVault Open Threat Exchange (OTX)**: A global community sharing "pulses" of Indicators of Compromise (IOCs)
- **abuse.ch Projects**: A collection of highly specialized feeds including:
    - **[URLhaus](https://urlhaus.abuse.ch/)**: Focused on malicious URLs distributing malware.
    - **ThreatFox**: A shared platform for malware-related indicators.
    - **MalwareBazaar**: A database for sharing and analyzing malware samples.
- **[Spamhaus Project](https://www.spamhaus.org/)**: Specialized in IP and domain reputation related to spam and botnets.
- **[SANS Internet Storm Center (ISC)](https://isc.sans.edu/)**: Provides a "Daily Stormcast" and technical data from a [global sensor network](https://www.wiz.io/academy/threat-intel/must-follow-threat-intel-feeds).
- **PhishTank**: A community-driven clearinghouse for data and verification of phishing URLs.
- **AbuseIPDB**: A community-powered database used to [track and report malicious IP addresses](https://ismalicious.com/posts/best-threat-intelligence-api-comparison-2026).
- **Blocklist.de**: A volunteer-run service reporting [brute-force attacks](https://hunt.io/glossary/best-threat-intelligence-feeds) on SSH, FTP, and web servers.

. Commercial Intelligence Feeds (Paid)
- **[Recorded Future](https://www.recordedfuture.com/)**: Uses an Intelligence Graph to correlate relationships across a million global sources.
- **CrowdStrike Falcon X**: Integrates adversary profiles and malware analysis directly into endpoint security workflows.
- **Mandiant (Google Cloud)**: Known for incident-response-backed intelligence on APT groups and nation-state actors.
- **Flashpoint Ignite**: Specialized in Deep and Dark Web intelligence and human intelligence (HUMINT).
- **Cisco Talos**: One of the world's largest commercial threat intelligence teams, powering Cisco's security infrastructure.
- **[IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/)**: A cloud-based sharing platform with collections of curated research and vulnerability data.
- **Digital Shadows (ReliaQuest)**: Focuses on [Digital Risk Protection (DRP)](https://www.gartner.com/reviews/market/security-threat-intelligence-products-and-services) and monitoring external attack surfaces.


. Government & Sector-Specific Feeds
- **CISA Automated Indicator Sharing (AIS)**: A free service for real-time exchange of machine-readable cyber threat indicators.
- **FBI InfraGard**: A public-private partnership focused on [protecting U.S. critical infrastructure](https://socradar.io/blog/the-ultimate-list-of-free-and-open-source-threat-intelligence-feeds/).
- **ISACs (Information Sharing and Analysis Centers)**: Sector-specific groups (e.g., FS-ISAC for Finance, Health-ISAC) that share intelligence [tailored to specific industries](https://www.cycognito.com/learn/threat-intelligence/threat-intelligence-feeds/).
- **CISA Known Exploited Vulnerabilities (KEV) Catalog**: An authoritative list of vulnerabilities confirmed to be exploited in the wild.


. Tools that help you find or aggregate feeds rather than being a single feed source.
- **Shodan**: A search engine used to find exposed internet-connected devices.
- **GreyNoise**: Essential for filtering "internet noise" to prioritize targeted attacks.
- **[MISP (Malware Information Sharing Platform)](https://www.misp-project.org/)**: An open-source platform that [aggregates feeds from various OSINT sources](https://www.anomali.com/blog/open-source-threat-intelligence-feeds).
- **OpenCTI**: A platform for [collecting and visualizing](https://www.wiz.io/academy/threat-intel/the-top-oss-threat-intelligence-tools) threat data in a structured format.


| Category                                | Tool Name                                          | Primary Focus                                                               |
| --------------------------------------- | -------------------------------------------------- | --------------------------------------------------------------------------- |
| **Threat Intelligence Platforms (TIP)** | [Recorded Future](https://www.recordedfuture.com/) | AI-driven "Intelligence Graph" correlating 1M+ global sources.              |
|                                         | Anomali ThreatStream                               | Multi-source feed aggregation and normalized IOC enrichment.                |
|                                         | [ThreatConnect](https://threatconnect.com/)        | Workflow automation and "Risk Quantifier" for business-level reporting.     |
|                                         | [OpenCTI](https://github.com/opencti-platform)     | Open-source platform using STIX 2 standards for complex data visualization. |
|                                         | MISP                                               | Federated, open-source community for sharing malware indicators and TTPs.   |

Top Underground Forums in 2026
- **[XSS](https://www.cloudsek.com/knowledge-base/dark-web-forums-and-deep-web-communities)**: A premier Russian-language forum established in 2013. It is widely considered the "Wall Street" of the dark web, primarily used by advanced threat actors and **Initial Access Brokers (IABs)** to trade network access, ransomware tooling, and high-value exploits.
- **[Dread](https://deepstrike.io/blog/top-dark-web-search-engines)**: Often described as the "Reddit of the dark web," it functions as a central community hub for discussion, **scam verification**, and reputation building rather than direct sales.
- **[BreachForums](https://en.wikipedia.org/wiki/BreachForums)**: The most famous English-language successor to **RaidForums**. It specializes in the massive distribution and monetization of **stolen datasets** and corporate leaks. Despite multiple takedowns, various versions (v1, v2, and newer mirrors) have remained central to the leak ecosystem.
- **[Exploit.in](https://flare.io/learn/resources/blog/dark-web-forums)**: One of the oldest continuously active forums (since 2005), catering to **seasoned Russian-speaking operators**. It is a major marketplace for **Zero-Day exploits**, custom malware, and specialized hacking services.
- **[DarkForums](https://www.kelacyber.com/blog/top-deep-web-and-dark-web-forums/)**: An English-language forum that surged in popularity in 2025 by absorbing users displaced after the shutdown of BreachForums. It focuses heavily on **stealer logs** and newly leaked databases.
- **[LeakBase](https://socradar.io/blog/top-10-deep-web-and-dark-web-forums/)**: A prominent hub for **data redistribution**, known for hosting extensive archives of compromised credentials and stealer logs.
- **Nulled** & **Cracked**: Large English-language communities popular for **cracking tools**, account-abuse methods, and "gray-area" digital services. While considered lower-tier than XSS, their massive user bases make them major drivers of automated credential abuse.


| Report Name                    | Target Audience     | Brief Description                                                                                                    |
| ------------------------------ | ------------------- | -------------------------------------------------------------------------------------------------------------------- |
| **Ad-Hoc / Flash Alert**       | SOC & IT Teams      | Rapid, "first-look" report on a breaking zero-day or high-profile global attack.                                     |
| **Post-Mortem / After Action** | Security Leadership | Analysis of a past internal incident to identify "intelligence gaps" and improve defenses.                           |
| **Executive Daily Digest**     | C-Suite / CISOs     | A 1-page summary of the top 3-5 global threats impacting the organization's industry that day.                       |
| **Vulnerability Assessment**   | Patch Management    | Deep dive into a specific CVE (vulnerability) to see if it is actively being exploited "in the wild."                |
| **Threat Actor Profile**       | Threat Hunters      | A "biography" of a specific group (e.g., APT28) including their history, favorite tools, and typical targets.        |
| **External Attack Surface**    | Risk & Compliance   | A report mapping out the company's internet-facing assets and potential "weak spots" visible to hackers.             |
| **Brand Protection / VIP**     | Legal & Executives  | Monitoring for leaked executive credentials, fake social media profiles, or "typosquatting" domains.                 |
| **Geopolitical Analysis**      | Risk Management     | Assessing how physical conflicts (e.g., wars, elections) might trigger retaliatory cyberattacks against the company. |

 TLP (Traffic Light Protocol: RED/AMBER/GREEN/CLEAR) and classification level (e.g., Confidential).
- **RED** = Only for the people in the room.  
- **AMBER** = Only for your team (if they need it).  
- **GREEN** = Share with trusted partners, but not publicly.  
- **WHITE** = Share anywhere.


The components considered while developing an intelligence strategy are the following:
Threat Intelligence Requirement Analysis
Threat Reports
Intelligence and Collection Planning
Threat Trending
Asset Identification
Intelligence Buy-In

Priority Intelligence Requirements (PIRs) :
are **high-level questions** that guide the collection and analysis of threat intelligence to support specific business or security objectives.
are in the form of a series of questions that assists the threat intelligence team to focus on what is important to the higher-level management.

MoSCoW prioritization or MoSCoW analysis is defined as a **prioritization method**
The word "MoSCoW" is an acronym for:
	MUST Have (Compulsory)
	SHOULD Have (Having high priority)
	COULD Have (Preferred but not essential)
	WON'T Have (Can be postponed or can be suggested for future project execution)



Building a Threat Intelligence Collection Plan
1. Data Collection
2. Structuring/ Normalization
3. Storing and Data Visualization
4. Sharing Information

**OSTrICa** is a open source framework that allows everyone to automatically collect and visualize any sort of data

GOSINT framework allows a security analyst to collect and standardize structured and unstructured threat intelligence.



**TAXII (Trusted Automated exchange of Indicator Information)**
Used as a protocol for security sharing of intelligence in **STIX and CybOX**


**STIX (Structured Threat Information eXpression)** :
**CybOX (Cyber Observable eXpression)** :
A standardized language used to describe cyber observables


What is Threat Modeling?
Threat modeling is a structured process used to :
(Understanding the system) > (Identifying threats) > (Mitigating threats) > (Validating the model)


The **Sliding Scale** of Cyber Security **Model** :
< 1 2 3 4 5 >
1- Architecture
2- passive defense
3- Active defense
4- intelligence
5- offense

A **Sock Puppet** is an important component in SOCMINT investigations. It is a fake online identity (fake account) that is used to add a layer of anonymity to the investigators because it is not linked to them.



Elements required to create concise, actionable, and customized threat intelligence reports:

Report Details
Client Details
Test Details
Traffic Light Protocol (TLP)
Analysis Methodology
Threat Details
Executive Summary
Indicators of Compromise
Recommended Actions

---

### 1. Searching for Suspicious Domains (Lookalike Domains)

**Step:** Use the software dnstwist (on Linux or Windows).
**Command:**
dnstwist -r -g -m --ssdeep brandname.com
**Explanation:**  
This command generates all domains similar to your company’s name (typos, repeated letters, swapped characters, etc.).


**Advanced Step:** Go to crt.sh.
Search for:
%.brandname.com
**Task:**  
Extract a list of all recently issued SSL certificates. Then manually filter the list to look for keywords such as:
- support-
- -login
- -secure

**Google Dorks**
```
intitle:"BrandName Login" -site:brandname.com
inurl:payment "BrandName" -site:brandname.com
site:*.tk "BrandName Support"
```


The CTI Blueprints authoring tool is a web application you run locally to create CTI reports based on the aforementioned CTI Blueprint templates. You select what kind of report you want to create based on your target audience or use case, and the tool will walk you through the report creation process. It includes rich dropdown menus, text boxes, tables, file saving, and the ability to edit multiple pages simultaneously.




