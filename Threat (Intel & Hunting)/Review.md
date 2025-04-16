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

## The Intelligence Cycle
A six-phase process:

1. **Planning and Targeting**
   - Identify key organizational assets
   - Understand why organization might be targeted
   - Address security concerns of decision makers

2. **Preparation and Collection**
   - Define and develop collection methods
   - Gather information based on requirements

3. **Processing and Exploitation**
   - Process collected data to generate information
   - Note: Unprocessed data equals lost intelligence

4. **Analysis and Production**
   - Analyze information to generate intelligence
   - Mitigate analyst bias through structured techniques

5. **Dissemination and Integration**
   - Distribute intelligence to relevant sectors
   - Consider:
     - Priority issues
     - Appropriate recipients
     - Urgency and detail level
     - Preventive recommendations

6. **Evaluation and Feedback**
   - Establish feedback mechanisms
   - Evaluate intelligence effectiveness
   - Make necessary adjustments

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