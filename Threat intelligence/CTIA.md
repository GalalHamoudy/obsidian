# Module 1 : introduction to Threat Intelligence

### STAGES OF CYBER THREAT INTELLIGENCE
The concept of intelligence is somehow reflecting the concept of "**knowns**" and “**unknowns**" proposed by **Donald Rumsfeld**. According to him, there are three stages in achieving the intelligence: [unknown unknowns - known unknowns - known knowns].
The threat intelligence process begins at unknown unknowns stage at which we do not have any idea about the threats and try to locate them. After obtaining the information about the threats, we move to the second stage called known unknowns. At this stage, we analyze the information and understand the nature of the threats, and with that data, we mitigate the threats and reach the final stage called known knowns. The implementation of these three stages of intelligence would lead to action and to achieve results. But the journey from the unknown unknowns to the known knowns is a tough job in case of cyber threats.

### Type of threat intelligence

		    High Level   -  Low Level
Long term :       Strategic           -  Tactical
short term :       Operational      - Technical


### Example: Ransomware Group Threat Intelligence

| | **High-Level (The "Why" & "What")** | **Low-Level (The "How")** |
| :--- | :--- | :--- |
| **Long-Term (Strategic)** | **Strategic Intelligence:** <br>An analysis report for the C-suite detailing that the ransomware group is shifting its business model to "double extortion" (stealing data before encrypting). It discusses the group's likely motivation (political pressure, financial gain), their long-term goals, and the potential financial and reputational impact on the company over the next 12-18 months. This helps executives make decisions about cybersecurity insurance, budget allocation, and incident response planning. | **Tactical Intelligence:** <br>A detailed profile of the ransomware group's **Tactics, Techniques, and Procedures (TTPs)**. This includes their preferred initial access methods (e.g., phishing with malicious PDFs, exploiting unpatched VPNs), the specific tools they use for lateral movement (e.g., Mimikatz, Cobalt Strike), and their data exfiltration patterns. This helps the SOC and threat hunters proactively search for these behaviors inside the network. |
| **Short-Term (Operational)** | **Operational Intelligence:** <br>A specific alert from an ISAC (Information Sharing and Analysis Center) warning of an imminent, coordinated campaign by this group targeting the healthcare sector over the next 72 hours. It includes indicators like newly registered domain names mimicking hospital brands and a list of targeted IP ranges. This allows the security team to immediately tighten firewall rules, block those domains, and increase monitoring on critical assets. | **Technical Intelligence:** <br>A real-time **Indicators of Compromise (IOC)** feed containing the hashes of the latest ransomware payload, malicious IP addresses of command-and-control (C2) servers, and specific filenames used by the malware. These IOCs are ingested directly into security tools (like SIEMs and antivirus) to automatically block or detect the threat. |

*   **Strategic:** "The enemy's overall goal is to destroy our supply chain morale. We need to invest in better training and fortifications." (Long-term, High-level)
*   **Tactical:** "The enemy's infantry platoons use flanking maneuvers and specific radio frequencies. Train our squads on counter-maneuvers and listen for those frequencies." (Long-term, Low-level)
*   **Operational:** "Enemy forces are massing north of Hill 451 and will likely attack at dawn. Move our artillery and reinforce the northern perimeter." (Short-term, High-level)
*   **Technical:** "Here are the specific radio transmissions and unit identifiers for the enemy scouts. Jam these frequencies and be on the lookout for these uniforms." (Short-term, Low-level)


### Threat Intelligence in Risk Management

**Frame**:     Threat intelligence is used to understand the direction and operations needed to perform risk management.
**Assess**:     Threat intelligence is used to identify, assess, and track potential threats and vulnerabilities.
**Respond**: Threat intelligence is used to evaluate and implement courses of action after the identification of risks.
**Monitor**:  Threat intelligence is used to monitor the ongoing threat changes to provide real-time support to security decisions and practices.


### What Are Threat Intelligence SOPs?

A **Standard Operating Procedure (SOP)** for threat intelligence is a formal, written document that details the consistent, repeatable steps for performing critical functions within the threat intelligence lifecycle. Think of it as a playbook that ensures your team operates efficiently, effectively, and consistently, especially under pressure.

The primary goals of Threat Intelligence SOPs are to:
*   **Ensure Consistency:** Everyone on the team follows the same processes.
*   **Improve Efficiency:** Reduce time spent deciding *how* to do something.
*   **Maintain Quality:** Uphold standards for intelligence collection, analysis, and dissemination.
*   **Facilitate Training & Onboarding:** New analysts have a clear guide to their responsibilities.
*   **Enable Measurable Improvement:** You can't improve a process that isn't documented.

### Core Components of a Threat Intelligence SOP

A well-structured SOP typically includes the following sections:

1.  **Purpose & Scope:**
    *   **Purpose:** A clear statement of what the SOP is designed to achieve (e.g., "To define the process for handling and responding to a high-confidence indicator of compromise (IOC)").
    *   **Scope:** Defines who and what the SOP applies to (e.g., "This SOP applies to all Tier 1 and Tier 2 Threat Intelligence Analysts").

2.  **Roles & Responsibilities:**
    *   Clearly defines who is responsible for each step in the process.
    *   *Examples:* Threat Intelligence Analyst, Senior Analyst, Intelligence Manager, SOC Lead, CISO.

3.  **Prerequisites & Tools:**
    *   Lists any required training, security clearances, or access levels.
    *   Specifies the software and tools needed (e.g., Threat Intelligence Platform (TIP), SIEM, Malware Analysis Sandbox, ticketing system).

4.  **Procedure (The Step-by-Step Guide):**
    *   This is the core of the SOP. It breaks down the task into clear, sequential steps. It often uses flowcharts or numbered lists.

5.  **References & Definitions:**
    *   Links to related policies, procedures, or external standards (e.g., MITRE ATT&CK, STIX/TAXII).
    *   Defines key terms used in the SOP (e.g., IOC, TTP, Threat Actor, Confidence Level).

6.  **Revision History:**
    *   Tracks the version, date, author, and description of changes. SOPs are living documents and must be regularly reviewed and updated.


### Key Threat Intelligence SOPs Every Program Should Have

Here are the most critical areas that require formal SOPs:

#### 1. SOP for the Intelligence Lifecycle (The "Umbrella" SOP)
This is a high-level SOP that governs the entire process from start to finish.
*   **Steps:** Direction -> Collection -> Processing -> Analysis -> Dissemination -> Feedback.
*   **Details:** Defines how requirements are set, what sources are used, how data is normalized, the analysis methodology, and the channels for sharing reports.

#### 2. SOP for Indicator of Compromise (IOC) Management
This is one of the most tactical and frequently used SOPs.
*   **Purpose:** To standardize the ingestion, validation, enrichment, and dissemination of IOCs.
*   **Key Steps:**
    1.  **Receipt/Ingestion:** How IOCs are received (feeds, emails, reports).
    2.  **Validation & Vetting:** Check for false positives, assess context and source reliability.
    3.  **Enrichment:** Add context (e.g., which threat actor uses this? What campaign is it part of?).
    4.  **Grading:** Assign a confidence level (e.g., High/Medium/Low) and severity.
    5.  **Action:** Define what happens based on the grade.
        *   *High Confidence/Critical:* Immediate push to SIEM, EDR, and firewall.
        *   *Medium Confidence:* Push to SIEM for alerting only.
        *   *Low Confidence:* Store for future reference or further investigation.
    6.  **Expiration:** Define a TTL (Time to Live) for IOCs to keep lists clean.

#### 3. SOP for Threat Intelligence Report Writing & Dissemination
This ensures that intelligence is communicated clearly and to the right audience.
*   **Purpose:** To define the structure, classification, and distribution of intelligence reports.
*   **Key Steps:**
    1.  **Audience Identification:** Who is this for? (e.g., Executive Board, SOC, IT Operations).
    2.  **Report Classification:** TLP (Traffic Light Protocol: RED/AMBER/GREEN/CLEAR) and classification level (e.g., Confidential).
    3.  **Report Structure:** Mandate a consistent format (e.g., Executive Summary, Key Findings, Associated IOCs, MITRE ATT&CK Mapping, Recommendations).
    4.  **Dissemination Channels:** How the report is sent (e.g., Email for executives, ticket for SOC, automated feed for IOCs).

#### 4. SOP for Incident Response (IR) Integration
This SOP defines how the threat intelligence team supports active security incidents.
*   **Purpose:** To provide a rapid and structured intelligence support function during an incident.
*   **Key Steps:**
    1.  **Activation:** How the IR team formally requests intelligence support.
    2.  **Triage & Research:** Analyst pivots off provided IOCs to identify the threat actor, their TTPs, and goals.
    3.  **Proactive Hunting:** Provide the IR team with additional IOCs and TTPs to hunt for within the environment.
    4.  **Reporting Loop:** Provide regular, concise updates to the Incident Commander.

#### 5. SOP for Vulnerability Management Integration
This focuses on prioritizing patching based on threat intelligence.
*   **Purpose:** To contextualize new vulnerabilities based on active exploitation in the wild.
*   **Key Steps:**
    1.  **Monitoring:** Track sources for new CVEs and exploit proofs-of-concept (PoCs).
    2.  **Contextualization:** Is this vulnerability being exploited? By whom? Is there a known ransomware group using it? Is it relevant to our tech stack?
    3.  **Prioritization:** Recommend a patching priority (e.g., **Critical**: Actively exploited and relevant to our public-facing servers) to the patch management team.

#### 6. SOP for Third-Party & Open-Source Intelligence (OSINT) Management
This governs the use of external data sources.
*   **Purpose:** To ensure the reliable and secure use of external intelligence.
*   **Key Steps:**
    1.  **Source Evaluation:** Criteria for vetting and approving new intelligence sources (e.g., accuracy, timeliness, relevance).
    2.  **Collection:** Approved methods for collecting OSINT (e.g., using dedicated VMs, anonymization tools).
    3.  **Data Handling:** Rules for storing and handling sensitive OSINT data.

### Example: A Simplified SOP for Handling a High-Confidence IOC

*   **Purpose:** To rapidly respond to a high-confidence IOC associated with active ransomware campaigns.
*   **Roles:** Tier 1 Analyst (discovers), Tier 2 Analyst (vets), SOC (blocks).
*   **Procedure:**
    1.  An IOC (e.g., a malicious IP) is ingested from a trusted feed with a "critical" rating.
    2.  **Tier 1 Analyst:** Immediately creates a high-priority ticket and notifies the Senior Analyst.
    3.  **Tier 2 Analyst:**
        *   Manually validates the IOC in a sandbox or OSINT tool. Confirms it's malicious.
        *   Enriches it: Links it to a known ransomware-as-a-service group.
        *   Grades it: **Confidence: High, Impact: Critical.**
    4.  **Action:**
        *   Immediately pushes the IOC to the firewall and EDR for blocking via the TIP's API.
        *   Notifies the SOC Lead via dedicated chat channel.
        *   Adds the IOC to the weekly threat intelligence report for record-keeping.
    5.  **Feedback:** The SOC confirms the block was successful and closes the loop in the ticket.



### The components considered while developing an intelligence strategy are the following:

Threat Intelligence Requirement Analysis
Threat Reports
Intelligence and Collection Planning
Threat Trending
Asset Identification
Intelligence Buy-In



### Threat Intelligence Maturity Model

The Threat Intelligence Maturity Model describes the levels of the threat intelligence applicability in an organization and
shows how much an organization is secure from the emerging threats.

Maturity Level 0 : Vague Where to Start
Maturity Level 1 : Preparing for CTI
Maturity Level 2 : Increasing CTI Capabilities
Maturity Level 3 : CTI Program in Place
Maturity Level 4 : Well-Defined CTI Program


### Collective Intelligence Framework (CIF)

Collective Intelligence Framework (CIF) is a cyber threat intelligence management system that allows you to combine known malicious threat information from many sources and use that information for incident response, detection, and mitigation.

CIF helps you to parse, normalize, store, post process, query, share, and produce data sets of threat intelligence.

TI Platform :
- crowd Strike
- Norm shield
- Misp
- Threat Connect
- Yeti
- ThreatSteam

---

# Module 02 : Cyber Threats and Kill Chain Methodology



Hacking Forums :

Hackaday (https://hackaday.com)
The Ethical Hacker Network (https://www.ethicalhacker.net)
Hack This Site (https://www.hackthissite.org)
Hak5 Forums (https://forums.hak5.org)
Evil Zone (https://evilzone.org)

APT lifecycle :
1- preparation
2- initial intrusion 
3- expansion
4- persistence
5- search and exfiltration
6- CleanUp

### loCs are divided into four categories:
Email Indicators
Host-Based Indicators
Network Indicators
Behavioral Indicators

---

# Module 03 : Requirements, Planning, Direction, and Review




-------[121]