https://quizlet.com/678635732/flashcards [33]
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


### **Predictive Threat Intelligence vs. Proactive Security**

| Feature                  | Predictive Threat Intelligence                                                              | Proactive Security                                                                                 |
| :----------------------- | :------------------------------------------------------------------------------------------ | :------------------------------------------------------------------------------------------------- |
| **Focus**                | Focuses on data analytics, AI and ML, and historical information to predict future threats. | Focuses on vulnerability scanning, threat hunting, and security implementation to prevent attacks. |
| **Timeframe**            | Searches for advanced threats to anticipate, accumulate, and prepare for future threats.    | Uses ongoing, real-time trends to detect and mitigate potential threats.                           |
| **Methods**              | Can be integrated with external threat intelligence feeds to predict threats.               | Regular internal audits and assignments to identify vulnerabilities and protect resources.         |
| **Goal**                 | Predicts and be prepared for future incidents.                                              | Prevents and minimize risks in advance.                                                            |
| **Examples**             | Discovering malware trends to predict the next possible target.                             | Educating employees to be aware of threats and conduct regular security assessments.               |
| **Tools & Technologies** | Depends on threat intelligence feeds, AI and ML, and data analytics.                        | Depends on IDS/IPS, SIEM, firewalls, and vulnerability assessment tools.                           |
| **Integration**          | Compatible with other security measures to provide additional security.                     | Part of an organization’s critical security strategies, including the IH&R plan.                   |


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


the sequence of steps involved in scheduling a threat intelligence program?

1. Review the project charters
2. Build a work breakdown structure (WBS)
3. Identify all deliverables
4. Define all activities
5. Identify the sequence of activities
6. Identify and estimate resources for all activities
7. Identify task dependencies
8. Estimate duration of each activity
9. Develop the final schedule


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

### Use of MITRE ATT&CK Framework in Threat Intelligence

Understand Adversary Behavior
Visualize Adversary Footprints
Identify Threat Groups
Enrich Threat Intelligence
Integrate ATT&CK with Existing Tools

### Use of MITRE ATT&CK Framework in Red Teaming

Simulate Real-time Attacks
Ensure Coverage and Validation
Identify Gaps
Measure the Efficiency
Continual Enhancement
Reporting

---

# Module 03 : Requirements, Planning, Direction, and Review

### Priority Intelligence Requirements

Priority Intelligence Requirements (PIRs) are essential for making strategic, operational, or tactical changes in the organizational infrastructure to reduce the risk.
They help organizations to reach their strategic goals by providing dynamic situational awareness about the evolving threat landscape.
PIRs are in the form of a series of questions that assists the threat intelligence team to focus on what is important to the higher-level management.

PIRs enable organizations to answer the following questions:
- What types of data need to be collected?
- Are there any gaps in the collected data?
- What talent and resources are needed to support the intelligence program?


### Prioritizing requirements 
Prioritizing requirements needs a combination of analytical and social skills to develop a set of requirements based on priority.
A detailed and focused requirement analysis must be done to divide or categorize the assets according to their importance.


### MoSCoW Method for Prioritizing Requirements

MoSCoW prioritization or MoSCoW analysis is defined as a prioritization method that assists in prioritizing requirements based on iterative and incremental approaches.
This method is about setting the requirements based on the order of priority, where the most important requirement be met first, for a greater chance of success.
It plays a vital role in agile project management, software development, and business analytics.

The word "MoSCoW" is an acronym for:
	MUST Have (Compulsory)
	SHOULD Have (Having high priority)
	COULD Have (Preferred but not essential)
	WON'T Have (Can be postponed or can be suggested for future project execution)



### Rule of Engagement

Rule of Engagement (ROE) is the formal permission to implement a threat intelligence program.
ROE provides "top-level" guidance for implementing a threat intelligence program.
ROE helps the intelligence team to overcome legal, federal, and policy-related restrictions to use different tactics, systems, and personnel.



### Project charter

Project charter is a short document that describes the entire project, including the objectives and goals of the project, how it will be carried out, stakeholders involved in the project, etc.
Project charter ensures that the project is implemented in the right direction to create deliverables that help in achieving the goals and objectives of the project.


---
# Module 04 : Data Collection and Processing


### Building a Threat Intelligence Collection Plan

1. Data Collection
2. Structuring/ Normalization
3. Storing and Data Visualization
4. Sharing Information

OSTrICa is a open source framework that allows everyone to automatically collect and visualize any sort of threat intelligence data harvested (loCs), from open, internal, and commercial sources using a plugin based architecture.

The GOSINT framework is a project used for collecting, processing, and exporting high-quality Indicators of Compromise (loCs).
GOSINT allows a security analyst to collect and standardize structured and unstructured threat intelligence.


**Social-Engineer Toolkit (SET)** is an open source Python tool aimed at extracting threat intelligence via social engineering.
**SpeedPhish Framework (SPF)** is a python tool designed to allow for quick recon and deployment of simple social engineering phishing exercises.

**KFSensor** is a host-based Intrusion Detection System (IDS) that acts as a honeypot to attract and detect hackers and worms by simulating vulnerable system services and Trojans.



### Methods for Data Structuring/Normalization

**STIX (Structured Threat Information eXpression)**

Community driven, part of MITRE standards 
Both human understandable and machine readable
Contains information on threat indicators, incidents, threat actor tactics, attack techniques or operations, etc.

**OpenIOC (Open Indicators of Compromise)**

Used to trace advanced threat actor campaigns, techniques and tools
Consists of metadata references and definition of the IOC

**CybOX (Cyber Observable eXpression)**

A standardized language used to describe cyber observables, created by MITRE
Encodes and communicates information on cyber observables Offers a common solution for all cyber security-related use cases

**TAXII (Trusted Automated eXchange of Indicator Information)**

Includes a set of technical specification and messages by MITRE
Used as a protocol for security sharing of intelligence in STIX and CybOX


**Tableau**
It is a simple data visualization tool that effectively produces interactive visualizations for complex data analytics as compared to general BI solutions.

**QlikView**
It offers powerful business intelligence, analytics, and enterprise reporting capabilities with a simple and hassle-free user interface.


------------[281]

# Lab V2

Open Source Intelligence Gathering 

http://exploit-db.com/google-hacking-database
https://ci-www.threatcrowd.org/
https://pulsedive.com/
https://whois.domaintools.com/
http://www.kloth.net/services/nslookup.php
https://www.maltego.com/
https://osintframework.com/
https://github.com/trustedsec/social-engineer-toolkit
https://honeydb.io/
https://viz.greynoise.io/
https://www.mandiant.com/


Valkyrie Unknown File Hunter (UFH) is a lightweight scanner that identifies unknown and potentially malicious files on the network. After scanning the systems, it classifies all audited files as "Safe," "Malicious," or "Unknown." While "Safe" files are deemed safe and "Malicious" files are deleted immediately, it is in the "Unknown" category that most zero-day threats are found.
https://wiki.itarian.com/frontend/web/topic/how-to-use-unknown-file-hunter


Tableau is a data visualization tool that helps people see and understand data. It is particularly efficient in handling massive and variable data sets used in big data operations with Al and machine learning. Tableau can connect to a wide variety of data sources, including databases, spreadsheets, and cloud-based applications. It can then be used to create interactive visualizations that can be shared with others.
https://www.tableau.com/

https://www.youtube.com/watch?v=mHFvIQmp_C0
https://www.youtube.com/watch?v=zemNLx0-LRw


Of course. This is an excellent question at the heart of proactive cybersecurity.

### What is Threat Modeling?

Threat modeling is a structured process used by security teams to identify, quantify, and address the security risks associated with an application, system, or business process. Think of it as a "blue team" exercise where you put on your attacker's hat and ask:

*   **What are we building?** (Understanding the system)
*   **What can go wrong?** (Identifying threats)
*   **What are we going to do about it?** (Mitigating threats)
*   **Did we do a good job?** (Validating the model)

The primary goal is to find security flaws *before* they are implemented or exploited, making security cost-effective and built-in from the start.

---

### Core Components of a Threat Modeling Methodology

Most methodologies revolve around answering these four questions, often formalized as:

1.  **Decompose the System:** Understand how the system works, its data flows, trust boundaries, and assets.
2.  **Identify Threats:** Systematically find potential threats against the system.
3.  **Address Threats:** Determine how to mitigate each threat.
4.  **Validate the Model:** Ensure the model is accurate and the mitigations are effective.

---

### Comparison of Major Threat Modeling Methodologies

Here are the most widely used and discussed methodologies, compared across key dimensions.

| Methodology | Primary Focus / "Lens" | Core Question | Best For | Pros | Cons |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **STRIDE** | **Attacker's Goals** | "What are the types of bad things that can happen?" | **Software & Application Design.** Microsoft's de facto standard. | - **Intuitive & Comprehensive:** Covers a broad range of threat types. <br>- **Easy to learn and apply.** <br>- Great for developers. | - Can be overly generic. <br>- Doesn't prioritize risks. <br>- Can be time-consuming for large systems. |
| **DREAD** | **Risk Prioritization** | "How bad would it be if this threat happened?" | **Prioritizing STRIDE threats.** (Often used as a supplement). | - **Provides a quantitative score** for risk. <br>- Helps decide what to fix first. | - **Highly subjective** (scoring depends on the person). <br>- Fell out of favor due to inconsistency. |
| **PASTA** | **Risk & Business Impact** | "How do attacker techniques align with our business impact?" | **Risk Management & aligning security with business objectives.** | - **Very comprehensive & business-focused.** <br>- Integrates attacker perspective with business impact. <br>- Good for compliance. | - **Heavyweight process.** <br>- Can be complex and time-consuming. <br>- Overkill for simple applications. |
| **TRIKE** | **Risk Management** | "What is our acceptable level of risk?" | **Organizations with a mature risk management program.** | - Focuses on **"acceptable risk"** from a stakeholder perspective. <br>- Very thorough. | - **Very complex** and has a steep learning curve. <br>- Not as widely adopted as STRIDE or PASTA. |
| **VAST** | **Scalability & Automation** | "How can we scale threat modeling across the entire organization?" | **Large organizations with DevOps/Agile pipelines.** | - **Designed for scalability.** <br>- Integrates well with DevOps (DevSecOps). <br>- Uses visual models from architecture diagrams. | - Requires specialized tools (like ThreatModeler) for full benefit. <br>- Less focus on deep, manual analysis for a single component. |
| **Attack Trees** | **Specific Attack Scenarios** | "How exactly could an attacker achieve a specific goal?" | **Analyzing specific, high-value attack vectors.** | - **Very detailed and visual.** <br>- Excellent for understanding complex attack paths. <br>- Good for penetration testing. | - **Narrow focus** (one tree per goal). <br>- Doesn't provide a systematic way to find all threats. |
| **OCTAVE** | **Operational Risk** | "What are our critical assets and how are they threatened?" | **Organizational risk assessment, not just software.** | - **Organization-centric,** not technology-centric. <br>- Focuses on strategic, practice-related risks. | - Not suitable for software design/development lifecycle. <br>- A large, multi-phase process. |

---

### Deeper Dive into the Most Common Methodologies

#### 1. STRIDE
This is the most common starting point. It categorizes threats into six types, which are also violations of core security properties:

*   **S**poofing: Impersonating someone or something else. (Violates **Authentication**)
*   **T**ampering: Modifying data or code. (Violates **Integrity**)
*   **R**epudiation: Claiming you didn't perform an action. (Violates **Non-Repudiation**)
*   **I**nformation Disclosure: Exposing information to unauthorized users. (Violates **Confidentiality**)
*   **D**enial of Service: Denying or degrading service to users. (Violates **Availability**)
*   **E**levation of Privilege: Gaining capabilities without authorization. (Violates **Authorization**)

**How it's used:** You create a Data Flow Diagram (DFD) of your system and then apply the STRIDE categories to each element (e.g., "Can an external entity spoof this process? Can this data store be tampered with?").

#### 2. PASTA (Process for Attack Simulation and Threat Analysis)
PASTA is a seven-stage, risk-centric methodology that blends technical and business views.

1.  Define Objectives
2.  Define Technical Scope
3.  Application Decomposition
4.  Threat Analysis
5.  Vulnerability & Weakness Analysis
6.  Attack Modeling & Simulation
7.  Risk & Impact Analysis

**How it's used:** It's a more complete framework that uses attack trees (see below) in stage 6 to model specific threats identified in earlier stages, always tying them back to business impact.

#### 3. Attack Trees
A graphical, hierarchical model representing attacks against a system. The root node is the attacker's goal (e.g., "Steal Customer Database"). Child nodes represent different ways to achieve that goal (e.g., "Exploit SQL Injection," "Bribe an Employee," "Compromise Backup Server"). These can be further broken down with AND/OR conditions.

**How it's used:** It's fantastic for diving deep into a known high-priority threat to understand all the potential attack paths, which helps in designing layered defenses.

---

### How to Choose a Methodology

The best methodology depends on your context:

*   **For Development Teams / Agile Environments:** Start with **STRIDE**. It's practical, well-understood, and integrates well into the design phase of the SDLC. **VAST** is excellent if you have the tooling and need to scale.
*   For **Risk & Compliance Teams:** **PASTA** or **OCTAVE** are more appropriate as they directly tie technical threats to business risk and impact.
*   For **Analyzing a Specific Critical Threat:** Use **Attack Trees** to map out every possible avenue of attack.
*   For **Operational & Organizational Risk:** **OCTAVE** is designed specifically for this purpose.

### The Modern Trend: Hybrid and Practical Approaches

Many organizations don't use a single methodology in its pure form. Instead, they create a hybrid, practical approach. A very common and effective modern workflow is:

1.  **Decompose:** Draw a diagram of your system (e.g., a simple flowchart or a more formal DFD).
2.  **Identify:** Use **STRIDE** as a checklist to brainstorm potential threats for each component in the diagram.
3.  **Prioritize:** Use a simple **Risk Matrix** (Likelihood vs. Impact) or the **DREAD** concept (without strict scoring) to prioritize the identified threats.
4.  **Mitigate:** Decide on actions (fix, mitigate, accept, or transfer) for the high-priority items.

This approach combines the comprehensiveness of STRIDE with the pragmatism of risk prioritization, making threat modeling an accessible and valuable practice for teams of all maturity levels.


---

the following techniques will help you to perform qualitative data analysis :
Brainstorming, interviewing. SWOT analysis, Delphi technique 

---

Excellent question. This gets into the foundational concepts of how trust is established and managed in security and identity systems.

The types of trust models you've listed are common ways to categorize how one entity decides to trust another. Here is a breakdown of each:

---

### A. Validated Trust
This model is based on the **verification of specific attributes or credentials**.

*   **How it works:** An entity must prove it meets certain predefined criteria or possesses a specific, verifiable quality. The trust is not granted by default; it must be earned through proof.
*   **Analogy:** A bouncer checking your ID at a bar to validate your age. The bouncer doesn't know you, but trusts the government-issued credential you provide.
*   **Real-World Example:**
    *   **TLS/SSL Certificates for Websites:** Your browser trusts a website because a trusted Certificate Authority (CA) has **validated** that the website owns the domain. The browser checks the site's certificate against a list of trusted CAs.
    *   **Login with Google/Facebook:** A third-party application trusts your identity because Google/Facebook has **validated** it for them.

### B. Direct Historical Trust (Often called "Persistent Trust" or "Behavioral Trust")
This model is based on a **history of successful and positive interactions**.

*   **How it works:** Trust is built over time. The more consistently an entity behaves in a trustworthy manner, the higher the level of trust it is granted. Conversely, a single breach of trust can destroy it.
*   **Analogy:** A colleague you've worked with for years. You trust them because they have consistently met deadlines, been reliable, and acted with integrity. Your trust is based on your direct history with them.
*   **Real-World Example:**
    *   **Email Spam Filters:** They learn to "trust" emails from certain senders because you consistently open them and don't mark them as spam. They build a "history" of good behavior.
    *   **Amazon's Seller Ratings:** You are more likely to trust a seller with a long history of positive reviews than a new seller with no history.

### C. Mandated Trust (Often called "Imposed Trust" or "Delegated Trust")
This model is based on a **rule or policy set by a central authority**.

*   **How it works:** An entity is trusted because a trusted authority *says* it should be trusted. The trust is not necessarily earned or validated by the trusting party directly; it is mandated from the top down.
*   **Analogy:** In the military, a private trusts a general because the chain of command mandates that lower ranks trust the authority of higher ranks. The private doesn't need to personally validate the general's expertise.
*   **Real-World Example:**
    *   **Corporate Network Access:** Your computer is trusted to access certain file servers because the IT department has placed it in the correct Active Directory group. The server trusts your computer based on this mandated policy.
    *   **Government Security Clearances:** An agency mandates that anyone with a "Top Secret" clearance is trusted to see certain information.

### D. Mediated Trust (Often called "Introduced Trust" or "Third-Party Trust")
This model relies on a **trusted third party to vouch for an otherwise unknown entity**.

*   **How it works:** Two parties who do not know each other both trust a common third party. This third party acts as an intermediary to "introduce" them and facilitate trust between them.
*   **Analogy:** A friend introduces you to someone you've never met. You trust this new person not because you know them, but because your trusted friend is vouching for them.
*   **Real-World Example:**
    *   **Public Key Infrastructure (PKI):** This is the classic example. When you visit a website, you don't know the site, and the site doesn't know you. A Certificate Authority (like DigiCert, Let's Encrypt) **mediates** the trust between you (the browser) and the website.
    *   **PGP/GPG Web of Trust:** In this model, users sign each other's public keys. If Alice trusts Bob, and Bob signs Charlie's key, Alice may choose to trust Charlie's key based on Bob's **mediation**.

---

### Summary Table

| Trust Model | Basis of Trust | Key Question | Example |
| :--- | :--- | :--- | :--- |
| **Validated Trust** | Proof of attributes or credentials | "Can you prove you are who/what you claim to be?" | Checking a driver's license |
| **Direct Historical Trust** | Past interactions and behavior | "Have you been trustworthy in the past?" | A seller's review score |
| **Mandated Trust** | Rule or policy from an authority | "Does the rulebook say I should trust you?" | Corporate IT access policies |
| **Mediated Trust** | Vouching by a trusted third party | "Does someone I already trust, trust you?" | SSL Certificates on the web |

In practice, most complex systems (like the internet) use a combination of these models. For instance, your browser uses **Mandated Trust** in its list of root CAs, which then enables **Mediated Trust** for websites, which is granted after the CA performs **Validated Trust** checks on the website owner.

---

Of course. Here's a brief overview of each of these frameworks and tools. They come from different domains (operating system security, networking, data visualization, and threat intelligence), so their purposes are quite distinct.

---

### A. SIGVERIF (Signature Verification)

**Domain:** Operating System Security (Specifically, Windows)

**Brief Description:**
SIGVERIF, or "File Signature Verification," is a built-in Windows utility. Its primary function is to check the digital signatures of all critical system files. A digital signature confirms that a file is genuine, has not been tampered with, and comes from a trusted publisher (like Microsoft).

**Key Purpose:**
- **Identify Unsigned System Files:** It scans core system files and lists those that are not digitally signed.
- **Troubleshoot System Instability:** Helps determine if system crashes or errors are caused by corrupted or modified system files.
- **Malware Detection:** While not a primary antivirus tool, it can help identify system files that have been replaced or altered by malware.

**Analogy:** A museum verifying the authenticity of its most valuable artifacts against the official artist's registry.

---

### B. TC COMPLETE

**Domain:** Networking / Quality of Service (QoS)

**Brief Description:**
TC COMPLETE refers to the full implementation and configuration of **Traffic Control (tc)** in the Linux kernel. The `tc` command is the user-space utility for configuring the built-in Linux packet scheduler, which manages how network traffic is queued and shaped.

**Key Purpose:**
- **Traffic Shaping:** Intentionally delaying packets to control bandwidth usage and ensure it doesn't exceed a set rate.
- **Priority Management:** Implementing QoS policies to give priority to critical traffic (e.g., VoIP, video conferencing) over less important traffic (e.g., file downloads).
- **Network Emulation:** Creating artificial limitations like delay, packet loss, and duplication to test application performance under poor network conditions.

**Analogy:** A smart traffic light system that can create dedicated lanes for emergency vehicles (high-priority traffic) while managing the flow of regular cars (standard traffic) to prevent jams.

---

### C. Highcharts

**Domain:** Data Visualization / Software Development

**Brief Description:**
Highcharts is a popular, powerful JavaScript library used to create interactive, web-friendly charts and graphs. It is purely client-side and is used by developers to embed sophisticated data visualizations into websites and web applications.

**Key Purpose:**
- **Create Interactive Charts:** Generates a wide variety of chart types like line, spline, area, bar, pie, scatter, and more.
- **Dashboarding:** A key component in business intelligence (BI) and monitoring dashboards to present data intuitively.
- **Cross-Browser Compatibility:** Ensures charts work consistently across all modern web browsers and devices.

**Analogy:** A master graphic designer who can take your raw spreadsheet data and turn it into a beautiful, interactive infographic for your website.

---

### D. Threat Grid

**Domain:** Cybersecurity / Threat Intelligence

**Brief Description:**
Threat Grid is a cloud-based malware analysis and threat intelligence platform, now part of Cisco Secure. It combines advanced sandboxing with threat intelligence to analyze suspicious files and URLs in a safe, virtual environment.

**Key Purpose:**
- **Malware Sandboxing:** Execute suspicious files and observe their behavior (processes created, network connections, file modifications) without risking the host system.
- **Threat Scoring:** Provides a weighted threat score (e.g., 0-100) to indicate the maliciousness of a sample.
- **Correlation & Enrichment:** Correlates analyzed samples with global threat intelligence to provide context, such as associated campaigns, threat actors, and Indicators of Compromise (IOCs).

**Analogy:** A high-security biolab where scientists safely analyze a new, unknown virus to understand how it works, what its symptoms are, and how to detect it.

### Summary Table

| Tool / Framework | Primary Domain | Core Function |
| :--- | :--- | :--- |
| **SIGVERIF** | OS Security (Windows) | Verify the integrity of system files. |
| **TC COMPLETE** | Networking (Linux) | Control and shape network traffic. |
| **Highcharts** | Data Visualization | Create interactive charts for the web. |
| **Threat Grid** | Cybersecurity | Analyze malware and provide threat intelligence. |


---

Type of Data analysis 

**A. Predictive**

- Uses historical data and statistical models to **forecast future outcomes**.
    
- Answers: _"What could happen in the future?"_
    

**B. Diagnostic**

- Looks at past data to **understand why something happened**.
    
- Answers: _"Why did this happen?"_
    

**C. Descriptive**

- Analyzes **real-time or historical data** to summarize what is happening **now** or what has happened.
    
- Answers: _"What is happening?"_ or _"What happened?"_
    

**D. Prescriptive**

- Suggests **actions to take** based on data analysis to affect desired outcomes.
    
- Answers: _"What should we do?"_
