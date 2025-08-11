# Threat Intelligence (TI) Overview

## Introduction to Cyber Threat Intelligence (CTI)

- CTI focuses on data collection and information analysis to gain a better understanding of threats facing an organization.
- Intelligence can be classified by:
  - **Time dedicated**: Long-term vs. short-term intelligence
  - **Form**: Strategic, tactical, or operational intelligence

## Intelligence Levels

### Strategic Level
- Informs top decision makers (C-suite: CEO, CFO, COO, CIO, CSO, CISO)
- Focuses on high-level trends, risks, and business impacts

### Operational Level
- Supports day-to-day decision making for resource allocation
- Provides information about:
  - Groups targeting the organization
  - Most recently active threat actors

### Tactical Level
- Delivers immediate, actionable information
- Includes indicators like:
  - IP addresses, domains, URLs
  - Hashes, registry keys, email artifacts
- Used for alert context and incident response prioritization

## Threat Actor Characteristics
Any threat actor can be defined by:
- Its type
- Its motivations
- Its sophistication level
- Its intended effect
- The campaigns it was involved in
- Its Tactics, Techniques, and Procedures (TTPs)

## ==The Intelligence Cycle==
A six-phase process: (Planning - collection - processing - analysis - Dissemination - Report)

1. **1.** **Planning and Direction:**
    This initial phase involves identifying the intelligence requirements, determining the scope of the analysis, and outlining the collection strategy. It includes defining the specific questions that need to be answered and deciding which methods and sources will be used to gather information. 
    
2. **2.** **Collection:**
    This stage focuses on gathering raw data from various sources. These sources can include open-source information (like news articles and social media), human intelligence (HUMINT), signals intelligence (SIGINT), imagery intelligence (IMINT), and more. 
    
3. **3.** **Processing:**
    The collected data is then transformed into a usable format. This may involve translating information, organizing it into databases, and creating searchable formats. 
    
4. **4.** **Analysis:**
    In this crucial step, the processed information is analyzed to identify patterns, trends, and potential threats. Analysts evaluate the data, assess its reliability, and draw conclusions based on the available evidence. 
    
5. **5.** **Dissemination:**
    The analyzed intelligence is then communicated to the relevant decision-makers or stakeholders. This ensures that those who need the information can use it to make informed decisions. 
    
6. **6.** **Feedback:**
    The final stage involves gathering feedback on the intelligence products and the overall process. This feedback helps refine the intelligence cycle, improve future analyses, and ensure that the process remains effective.


### **Scenario: Preventing a Terrorist Attack**

#### **1. Planning & Direction**
- **Tasking:** A national security agency receives vague reports about a potential terrorist threat in a major city.
- **Priority:** The agency defines its intelligence requirements—identifying the group involved, their plans, and possible targets.

#### **2. Collection**
- **Methods Used:**
    - **HUMINT (Human Intelligence):** An undercover agent infiltrates a suspected group.
    - **SIGINT (Signals Intelligence):** Monitoring encrypted communications between suspects.
    - **OSINT (Open Source Intelligence):** Scanning social media for extremist propaganda.
- **Data Gathered:** The group is planning a bomb attack on a subway station next week.

#### **3. Processing**
- **Decryption:** Breaking coded messages between operatives.
- **Translation:** Converting intercepted foreign-language communications.
- **Organizing:** Structuring raw data into usable reports.

#### **4. Analysis**
- **Assessment:** Analysts determine:
    - The credibility of the threat.
    - Likely targets and methods.
    - Possible collaborators.
- **Conclusion:** The threat is credible, with a high likelihood of an attack in 5 days.

#### **5. Dissemination**
- **Report Format:** A classified intelligence brief is prepared.
- **Recipients:** Shared with law enforcement, counterterrorism units, and government officials.

#### **6. Feedback & Reevaluation**
- **Response:** Police increase security at subway stations.
- **New Intel:** Surveillance confirms suspects are conducting reconnaissance.
- **Cycle Repeats:** Updated intelligence leads to the arrest of the cell before the attack

## Threat Models and Frameworks

### The Cyber Kill Chain® (Lockheed Martin)
Seven attack stages:
1. Reconnaissance
2. Weaponization
3. Delivery
4. Exploitation
5. Installation
6. Command and Control (C2)
7. Actions on objectives

### The Diamond Model
Four core elements:
1. Adversary
2. Infrastructure
3. Capability
4. Victim
Connected by sociopolitical and technical axes

### MITRE ATT&CK™ Framework
Describes threat actor activities across:
- Enterprise environments
- Cloud environments
- Mobile devices
- Industrial control systems

## Threat Hunting

- Proactive search for signs of compromise
- Goals:
  - Shorten dwell time (time between infiltration and detection)
  - Minimize breach impact

### Threat Hunting Maturity Model
Five levels:
1. Initial
2. Minimal
3. Procedural
4. Innovative
5. Leading

### Threat Hunting Process
Six iterative steps:
1. Purpose
2. Scope
3. Equip
4. Plan Review
5. Execute
6. Feedback

## Data-Driven Methodology

1. Define research goal
2. Model data (using OSSEM)
3. Emulate adversary (using Mordor project)
4. Define detection model
5. Validate detection model (using HELK platform)
6. Document and communicate findings

## TaHiTI Methodology
(Targeted Hunting Integrating Threat Intelligence)

### Three Phases:
1. **Initiate**
   - Transform hunt trigger into investigation abstract
   - Store in backlog

2. **Hunt**
   - Define and refine hypothesis
   - Execute investigation

3. **Finalize**
   - Document findings

### Three Hypothesis Types:
1. Threat intelligence-based
2. Situational awareness-based
3. Domain expertise-based

## ATT&CK Enterprise Tactics
Full spectrum of attack behaviors:
- Reconnaissance
- Resource Development
- Initial Access
- Execution
- Persistence
- Privilege Escalation
- Defense Evasion
- Credential Access
- Discovery
- Lateral Movement
- Collection
- Command and Control
- Exfiltration
- Impact

## Collection Management Framework (CMF)
- Tracks tools and data sources
- Can be as simple as an Excel worksheet

## OSSEM Project Components
1. ATT&CK Data Sources
2. Common Information Model (CIM)
3. Data Dictionaries
4. Data Detection Model

## Sigma Rules Structure
Four sections:
1. Metadata
2. Log source
3. Detection
4. Condition

## Adversary Emulation
Five-step ATT&CK process:
1. Gather threat intel
2. Extract techniques
3. Analyze and organize
4. Develop tools
5. Emulate adversary

### APT3 Emulation Phases
1. Initial Compromise
2. Network Propagation
3. Exfiltration

## Tools and Resources

### Analysis Tools:
- ATT&CK Navigator
- CARET (CAR Exploitation Tool)
- MITRE Cyber Analytics Repository (CAR)

### Emulation Tools:
**Open Source:**
- Atomic Red Team
- Mordor
- CALDERA
- HELK (Hunting ELK)

**Commercial:**
- Cobalt Strike
- Cymulate
- Attack-IQ

## Types of Threat Intelligence

1. **Tactical**
   - Real-time threat information
   - Immediate defensive actions

2. **Operational**
   - Threat actor motives/capabilities
   - Comprehensive threat landscape

3. **Strategic**
   - Long-term trends
   - Emerging risks
   - Geopolitical factors

## Analysis of Competing Hypotheses (ACH)
- Developed by CIA officer Richards J. Heuer Jr.
- Mitigates cognitive biases
- Enhances assessment quality

## Intelligence Gathering Disciplines

- OSINT (Open Source Intelligence)
- HUMINT (Human Intelligence)
- GEOINT (Geospatial Intelligence)
- SIGINT (Signals Intelligence)
- FININT (Financial Intelligence)
- SOCINT (Social Media Intelligence)
- IMINT (Imagery Intelligence)
- RECON (Reconnaissance)

## Traffic Light Protocol (TLP)
Information sensitivity classification:
- TLP:RED
- TLP:AMBER
- TLP:GREEN
- TLP:CLEAR

## TTPs Analysis
- **Tactics**: Overall attack strategies
- **Techniques**: Specific tools/methods
- **Procedures**: Step-by-step processes

## Indicator Types

### IOC Categories:
1. File-based (hashes, filenames)
2. Network-based (IPs, domains)
3. Registry-based (keys, values)
4. Behavioral-based (activity patterns)

### Lockheed Martin Classification:
1. Atomic (IPs, emails)
2. Computed (hashes, regex)
3. Behavioral (action sequences)

## Indicator Lifecycle
1. Revelation (discovery)
2. Maturation (optimization)
3. Utility (deployment)

## Pivoting Techniques
- Connects unrelated data points
- Common IOCs used:
  - Network indicators
  - Host-based indicators

## Analysis Tools

- **YARA**: Malware detection/analysis
- **Sigma**: Log analysis rules (YAML)
- **MSTICpy**: Python library for threat investigation

## False Flags in Cyberattacks
- Deceptive tactics to mislead investigators
- Goals:
  - Misdirect attribution
  - Obscure attacker identity
  - Create confusion about attack origin

## Intelligence Cycle (Six Phases)
1. Direction
2. Collection
3. Processing
4. Analysis
5. Dissemination
6. Feedback