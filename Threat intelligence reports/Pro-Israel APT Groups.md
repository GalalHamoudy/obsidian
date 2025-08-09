# Comprehensive Threat Intelligence Profile: Pro-Israel APT Groups in the Cyber Conflict Landscape

## I. Executive Summary

The cyber domain has emerged as a significant battleground in the escalating geopolitical tensions between Israel and Iran. This conflict has witnessed a notable surge in malicious cyber activities, particularly in the aftermath of physical strikes.1 The landscape is complex, populated by a diverse array of actors, including state-sponsored entities, ideologically aligned hacktivist groups, and their proxies. These groups employ a wide spectrum of attack methods, ranging from disruptive Distributed Denial of Service (DDoS) attacks and general data theft to more sophisticated intrusions, malware deployment, and cyber-physical sabotage.3

A critical finding from the analysis of the provided intelligence is a significant discrepancy in the initial categorization of the specified groups. While the query labels all six groups as "PRO-ISRAEL," the available information indicates a different reality for most. Only **Garuna Ops** and **Predatory Sparrow** are explicitly identified or strongly implied to be pro-Israel or affiliated with Israeli interests.4 Conversely,

**NPFN**, **Lefaroll**, and **Israeli Gladiator** are consistently described as pro-Iranian hacktivist groups or linked to Iranian state actors, actively engaged in targeting Israeli entities.3 For

**Eagle7**, the provided data lacks specific APT-related intelligence within the context of the Israel-Iran conflict, with mentions primarily referring to unrelated commercial entities or general cyber threats.10 The operational sophistication across these groups also varies considerably, with Predatory Sparrow demonstrating advanced capabilities often associated with state-sponsored operations, while others, such as Garuna Ops, appear to focus on more overt hacktivist-style DDoS campaigns.

The observed contradictions in group affiliations underscore a pervasive challenge in open-source intelligence and threat analysis. The fluidity of threat actor identities, coupled with the potential for mislabeling or the use of generic names, can lead to significant confusion. This situation highlights the imperative for rigorous verification of group affiliations and operational contexts, particularly in politically charged cyber conflicts where deception and false flags are common. For cybersecurity professionals, an initial assumption based on a group's name or a broad categorization can be misleading, potentially resulting in misallocation of defensive resources and an incomplete understanding of the true threat landscape.

Furthermore, the activities of certain groups, notably Predatory Sparrow, illustrate the increasingly blurred boundaries between traditional hacktivism and state-sponsored operations. While Predatory Sparrow presents itself as a hacktivist entity, its demonstrated "technical proficiency beyond that of a typical hacktivist group," its use of "customized 'wiper' malware," and its "strategic target selection" 9 align more closely with the capabilities of nation-state actors. This pattern is not unique, as intelligence indicates that Iranian cyber forces frequently employ "fake identities or front groups to hide their state connections".3 Such a deliberate strategy by nation-states to leverage hacktivist personas as "cutouts" allows them to achieve geopolitical objectives while maintaining plausible deniability.8 This operational characteristic complicates attribution efforts for defenders, as the public self-description of a group may not accurately reflect its true capabilities or backing. Consequently, even seemingly "hacktivist" activity must be thoroughly assessed for underlying state sponsorship, demanding a deeper analysis of tactics, techniques, and procedures (TTPs) and the resources available to the actors.

## II. Introduction to Advanced Persistent Threats (APTs) in Geopolitical Context

### Definition and Characteristics of APTs

Advanced Persistent Threats (APTs) represent a highly sophisticated and sustained form of cyberattack. In these operations, an intruder establishes an undetected presence within a target network with the primary objective of exfiltrating sensitive data over an extended period.14 Unlike opportunistic cyberattacks that often aim for immediate disruption or financial gain, APTs are characterized by their patient and methodical approach, often remaining hidden within a network for weeks or even months while meticulously achieving their objectives.15

The motivations behind APT campaigns typically fall into four broad categories: cyber espionage, which involves the theft of intellectual property or state secrets; eCrime, focused on financial gain; hacktivism, driven by ideological or political agendas; and outright destruction of data or systems.14

An APT attack typically unfolds in three distinct stages:

- **Infiltration:** The initial phase often involves social engineering techniques, with spear-phishing emails being a common vector. These emails are meticulously crafted and selectively target high-level individuals, such as senior executives or technology leaders, often leveraging information gleaned from previously compromised accounts to enhance their legitimacy.14
    
- **Escalation and Lateral Movement:** Once initial access is gained, attackers deploy malware to establish a foothold within the organization's network. They then systematically move laterally, mapping the network infrastructure and gathering credentials, including account names and passwords, to access critical business information. A key aspect of this stage is the establishment of "backdoors," ensuring persistent access even if initial entry points are discovered and closed.14
    
- **Exfiltration:** In the final stage, cybercriminals typically consolidate the stolen information in a secure location within the compromised network. Once a sufficient volume of data has been collected, they extract, or "exfiltrate," it without detection. Attackers may employ distraction tactics, such as launching Denial-of-Service (DoS) attacks, to divert the security team's attention and tie up network resources while the data is being siphoned off.14 Even after data exfiltration, the network may remain compromised, serving as a potential future access point for the threat actors.
    

### The Role of Cyber Operations in the Israel-Iran Conflict

The ongoing Israel-Iran conflict has extended significantly into the cyber domain, transforming it into a "fierce cyberspace battle".4 This digital front has seen a dramatic escalation, with a reported "700% increase in cyberattacks against Israel" observed shortly after physical military strikes.1 This immediate surge indicates that cyber operations are not merely supplementary but are integrated as a critical component of modern geopolitical conflict. The alleged actions of Israeli intelligence, possibly Mossad, conducting sabotage inside Iran, which may have included cyberattacks on air defense systems and missile launch sites, with a slow Iranian response hinting at disabled systems 3, illustrate cyber means being used to augment physical attacks and shape battlefield outcomes. This demonstrates cyber warfare's capacity as a force multiplier, capable of influencing the physical environment and exerting psychological pressure.

Cyber operations in this conflict serve multiple strategic purposes. They include direct disruption through DDoS attacks, data theft, and espionage to gather intelligence. Furthermore, these operations are employed to influence public opinion through propaganda and disinformation campaigns.3 Both state-linked cyber units and aligned hacktivist groups are actively involved in these digital confrontations. A recurring tactic observed is the use of "fake identities or front groups" by state actors to obscure their true origins and affiliations.3 This practice of employing "cutouts" provides plausible deniability, a key feature of asymmetric warfare, which complicates definitive attribution and, consequently, hinders retaliatory measures or the application of international legal frameworks.

The dynamic nature of this cyber conflict also presents an evolving threat landscape and a continuous dilemma for defenders. Adversaries are demonstrating increased efficiency, focus, and a business-like approach in their operations.16 They are constantly innovating techniques and developing creative solutions to circumvent modern defenses.16 This includes a growing trend of "living off the land," where threat actors increasingly leverage legitimate remote monitoring and management (RMM) tools rather than deploying custom malware.16 Furthermore, the adoption of generative Artificial Intelligence (AI) by threat actors to enhance their operations, such as crafting highly convincing phishing emails, is becoming more prevalent.17 These developments make detection significantly more challenging, as malicious activity often blends seamlessly with normal network traffic. For organizations, this implies that traditional signature-based defenses are becoming increasingly insufficient. An effective defense strategy now necessitates the implementation of advanced behavioral analytics (UEBA), robust threat intelligence integration, and continuous monitoring to detect subtle anomalies and adapt rapidly to evolving TTPs.18 This continuous adaptation is essential to stay ahead in the ongoing digital arms race.

## III. APT Group Profiles

The following profiles detail the characteristics of each group based on the provided intelligence. It is crucial to reiterate the significant discrepancy in the query's "PRO-ISRAEL" labeling for NPFN, Lefaroll, and Israeli Gladiator, as the available information consistently identifies them as pro-Iranian or anti-Israel.

### A. Garuna Ops

- **Attribution & Threat Intelligence**
    
    - **Suspected Geographic Origin:** Garuna Ops is identified as an "Indian hacktivist group".4
        
    - **Alleged Affiliations:** The group has explicitly "announced its support for Israel" 6 and issues calls to "non-Muslim hackers" to engage in actions with an "anti-Palestinian stance".5 This confirms its pro-Israel alignment, consistent with the overall categorization requested. The fact that a group originating from India is actively involved and publicly aligns itself with Israel in the conflict underscores the globalized nature of cyber warfare. Geopolitical conflicts can draw in actors from geographically distant regions, potentially operating as ideologically aligned hacktivists or even proxies, thereby complicating traditional threat mapping that might only focus on direct state-on-state confrontations. This indicates that national interests or shared ideologies can drive cyber activity from unexpected origins.
        
- **Digital Footprint & Presence**
    
    - **Official/Cover Websites:** No official or cover websites specifically attributed to Garuna Ops as a threat actor are detailed in the provided information.
        
    - **Social Media Accounts:** The group's activities are noted through "Garuna Ops' post on Telegram".5 While general hacktivist presence on X (formerly Twitter) is mentioned in the broader context of the conflict, specific X/Twitter accounts for Garuna Ops are not detailed.5
        
    - **Forums:** No information regarding forums (underground, clearnet, or dark web) used by Garuna Ops.
        
    - **Dark Web Links:** No dark web links (marketplaces, leak sites, or communication channels) are provided for Garuna Ops.
        
- **Attack Methods & Tools**
    
    - **Primary Attack Vectors:** Garuna Ops primarily engages in Distributed Denial of Service (DDoS) attacks.3
        
    - **Malware/Tools Used:** No specific malware or tools are directly attributed to Garuna Ops. The broader context of APT activity in the conflict mentions the use of wiper malware, ransomware, and the exploitation of PLCs, SCADAs, and other Operational Technology (OT) systems as potential future actions or general activities by various actors, but not specifically by Garuna Ops.3
        
    - **Exploits & Vulnerabilities Commonly Targeted:** No specific exploits or vulnerabilities are mentioned as being commonly targeted by Garuna Ops.
        
- **Indicators of Attack (IOAs) & Tactics**
    
    - **Behavioral Patterns:** The group is described as taking position, preparing, and "swiftly executed their attacks".3
        
    - **Signatures:** No specific file hashes, IPs, domains, or YARA rules are provided for Garuna Ops.
        
    - **TTPs (MITRE ATT&CK Framework mapping):** The primary TTP identified is DDoS attacks.3 While no direct MITRE ATT&CK mapping is provided for Garuna Ops, DDoS attacks fall under the Impact tactic (TA0040) within the MITRE ATT&CK framework, specifically T1499, "Denial of Service."
        
- **Infrastructure Analysis**
    
    - **C2 (Command & Control) Servers:** No specific C2 server domains or IP ranges are identified for Garuna Ops.
        
    - **Proxy/Pivot Networks:** No information on proxy/pivot networks (e.g., TOR, bulletproof hosting, compromised devices) used by Garuna Ops.
        
    - **Malware Distribution Channels:** No specific malware distribution channels are identified for Garuna Ops.
        
- **Historical Background**
    
    - **Origins & Alleged Affiliations:** Garuna Ops is a newly formed group 20 that emerged in the context of the Israel-Palestine conflict, announcing its support for Israel.6
        
    - **Notable Attacks & Campaigns (Timeline of Major Incidents):**
        
        - **October 8, 2023:** Claimed responsibility for DDoS attacks on Palestinian network infrastructure.4
            
        - **Mid-September (prior to Oct 2023):** Previously claimed responsibility for attacking an Israeli public railroad, although this incident was denied by Israel.21
            
    - **Evolution Over Time:** The available information does not detail an extensive evolution in tools, targets, or methods beyond its initial emergence and engagement in DDoS attacks.
        

### B. Eagle7

- **Attribution & Threat Intelligence**
    
    - **Suspected Geographic Origin:** No specific geographic origin is provided for a cyber threat group named Eagle7.
        
    - **Alleged Affiliations:** The provided intelligence does not link any cyber threat group named "Eagle7" to the Israel-Iran conflict. The name "Eagle7" appears in contexts entirely unrelated to cyber warfare, such as a tank in the game World of Tanks Blitz 10, an x-ray screener training and certification platform 11, a creative agency 12, and a proprietary trading firm.13 While "Eagle7" is mentioned in general lists of attack types (DDoS, critical infrastructure intrusion, malware, data theft) within the broader context of the conflict, these mentions lack direct attribution to a specific threat actor named "Eagle7".3 The repeated appearance of the name "Eagle7" across such disparate and unrelated contexts, while also appearing in generic lists of cyberattack types without specific attribution, highlights a significant challenge in threat intelligence: the problem of name overlap. This phenomenon makes it difficult to definitively link a generic name to a specific threat actor, underscoring the critical need for unique identifiers and more granular contextual information in threat reporting to avoid misinterpretations.
        
- **Digital Footprint & Presence**
    
    - **Official/Cover Websites:** Websites associated with the name "Eagle7" include `wotblitz.com` (gaming) 10,
        
        `eaglecbt.com` (x-ray training) 11,
        
        `eagle7.in` (creative agency) 12, and
        
        `eagleseven.com` (trading firm).13 None of these are identified as official or cover websites for a cyber threat group.
        
    - **Social Media Accounts:** The creative agency `eagle7.in` mentions its presence on Facebook, Twitter, and Instagram for marketing purposes.12 However, no direct social media presence for a cyber threat group named Eagle7 is detailed.
        
    - **Forums:** No information regarding forums (underground, clearnet, or dark web) used by a cyber threat group named Eagle7.
        
    - **Dark Web Links:** No dark web links (marketplaces, leak sites, or communication channels) are provided for a cyber threat group named Eagle7.
        
- **Attack Methods & Tools**
    
    - **Primary Attack Vectors:** No specific primary attack vectors are attributed to an APT group named Eagle7 in the provided intelligence. General APT activities in the conflict context include DDoS attacks, intrusion attempts on critical infrastructure, malware deployment, data theft, wiper malware, ransomware, and exploitation of PLCs, SCADAs, and other OT systems.3
        
    - **Malware/Tools Used:** No specific malware or tools are attributed to an APT group named Eagle7.
        
    - **Exploits & Vulnerabilities Commonly Targeted:** No specific exploits or vulnerabilities are mentioned as being commonly targeted by an APT group named Eagle7.
        
- **Indicators of Attack (IOAs) & Tactics**
    
    - **Behavioral Patterns:** No specific behavioral patterns are attributed to an APT group named Eagle7.
        
    - **Signatures:** No specific file hashes, IPs, domains, or YARA rules are provided for an APT group named Eagle7.
        
    - **TTPs (MITRE ATT&CK Framework mapping):** No specific TTPs are attributed to an APT group named Eagle7.
        
- **Infrastructure Analysis**
    
    - **C2 (Command & Control) Servers:** No specific C2 server domains or IP ranges are identified for an APT group named Eagle7.
        
    - **Proxy/Pivot Networks:** No information on proxy/pivot networks used by an APT group named Eagle7.
        
    - **Malware Distribution Channels:** No specific malware distribution channels are identified for an APT group named Eagle7.
        
- **Historical Background**
    
    - **Origins & Alleged Affiliations:** No historical background for an APT group named Eagle7 in the context of the Israel-Iran conflict is provided in the available information.
        
    - **Notable Attacks & Campaigns (Timeline of Major Incidents):** No notable attacks or campaigns are attributed to an APT group named Eagle7.
        
    - **Evolution Over Time:** No information on the evolution of tools, targets, or methods for an APT group named Eagle7.
        

### C. NPFN

- **Attribution & Threat Intelligence**
    
    - **Suspected Geographic Origin:** The acronym "NPFN" primarily refers to the "Nigeria Police Force - National Cybercrime Center" (`nccc.npf.gov.ng`) 22, which is a law enforcement entity, not a threat actor. However, in the context of the Israel-Iran conflict, "NPFN" is listed among "pro-Iran hacktivist goals and commitments" and within a list of "pro-Iran (65 Groups)".3 This constitutes a direct contradiction to the query's "PRO-ISRAEL" label and points to a significant lexical ambiguity. The dual identification of "NPFN" as both a legitimate national cybercrime center and a pro-Iranian hacktivist group highlights the critical need for context and unique identifiers when tracking threat actors. Such ambiguity can lead to misinformed defensive postures, as resources might be misdirected due to confusion over group identities.
        
    - **Alleged Affiliations:** As a threat actor, NPFN is listed as a pro-Iranian hacktivist group.3
        
- **Digital Footprint & Presence**
    
    - **Official/Cover Websites:** The official website `nccc.npf.gov.ng` belongs to the Nigeria Police Force - National Cybercrime Center.22 No website for a pro-Iran hacktivist group named NPFN is detailed.
        
    - **Social Media Accounts:** "NPFN" is listed in a Telegram post alongside other pro-Iran hacktivist groups.3 However, no specific Telegram or X/Twitter accounts are detailed for NPFN as a threat actor.
        
    - **Forums:** No information regarding forums (underground, clearnet, or dark web) used by NPFN as a threat actor.
        
    - **Dark Web Links:** No dark web links (marketplaces, leak sites, or communication channels) are provided for NPFN as a threat actor.
        
- **Attack Methods & Tools**
    
    - **Primary Attack Vectors:** No specific attack methods are attributed to NPFN as a threat actor. General APT activities in the conflict context include DDoS attacks on Israeli websites and services, intrusion attempts on critical infrastructure, malware deployment, and data theft.3
        
    - **Malware/Tools Used:** No specific malware or tools are attributed to NPFN. Mentions of "ransomware and wipers like Shamoon and Deadwood" are generally tied to Iranian state hackers, not NPFN specifically.3 "Data Poisoning" is discussed as a general cyber threat by NPAV, not linked to NPFN.23
        
    - **Exploits & Vulnerabilities Commonly Targeted:** No specific exploits or vulnerabilities are mentioned as being commonly targeted by NPFN.
        
- **Indicators of Attack (IOAs) & Tactics**
    
    - **Behavioral Patterns:** No specific behavioral patterns are attributed to NPFN as a threat actor.
        
    - **Signatures:** No specific file hashes, IPs, domains, or YARA rules are provided for NPFN.
        
    - **TTPs (MITRE ATT&CK Framework mapping):** No specific TTPs are attributed to NPFN. General APT TTPs mentioned in the broader context include social engineering (spear-phishing), malware distribution via Strategic Web Compromise (SWC) operations and malicious attachments, lateral movement, persistence mechanisms, credential harvesting, and data exfiltration.14
        
- **Infrastructure Analysis**
    
    - **C2 (Command & Control) Servers:** No specific C2 server domains or IP ranges are identified for NPFN as a threat actor.
        
    - **Proxy/Pivot Networks:** No information on proxy/pivot networks used by NPFN.
        
    - **Malware Distribution Channels:** No specific malware distribution channels are identified for NPFN.
        
- **Historical Background**
    
    - **Origins & Alleged Affiliations:** No specific historical background for NPFN as a threat actor in the context of the conflict is provided, beyond its listing as a pro-Iran group.3 The Nigeria Police Force - National Cybercrime Center was established to combat cybercrime and protect digital spaces.22
        
    - **Notable Attacks & Campaigns (Timeline of Major Incidents):** No notable attacks or campaigns are attributed to NPFN as a threat actor.
        
    - **Evolution Over Time:** No information on the evolution of tools, targets, or methods for NPFN as a threat actor.
        

### D. Lefaroll

- **Attribution & Threat Intelligence**
    
    - **Suspected Geographic Origin:** Lefaroll is listed among "pro-Iran (65 Groups)".3
        
    - **Alleged Affiliations:** The group is identified as a "non-Iranian hacktivist group now targeting Israel" 3 and is listed among groups associated with "pro-Iran hacktivist goals and commitments".3 This directly contradicts the query's "PRO-ISRAEL" label. The identification of Lefaroll as a "non-Iranian hacktivist group now targeting Israel" while simultaneously being listed among "pro-Iran" groups suggests a complex proxy dynamic. Such groups might operate with ideological alignment or receive indirect support from state actors without being under direct state control, thereby offering a degree of deniability. This highlights the fluidity of alliances and the potential for groups to shift their targets or affiliations in response to evolving geopolitical events, making their long-term tracking challenging.
        
- **Digital Footprint & Presence**
    
    - **Official/Cover Websites:** No specific official or cover websites are attributed to Lefaroll. "Handala's onion website lists all alleged breaches" in a broader context of hacktivist groups, including Lefaroll's listing.3
        
    - **Social Media Accounts:** Lefaroll is listed in Telegram posts alongside other pro-Iran hacktivist groups.3 No specific Telegram or X/Twitter accounts are detailed for Lefaroll.
        
    - **Forums:** No information regarding forums (underground, clearnet, or dark web) used by Lefaroll.
        
    - **Dark Web Links:** No dark web links (marketplaces, leak sites, or communication channels) are provided for Lefaroll, though "Handala's onion website" is mentioned in a related context.3
        
- **Attack Methods & Tools**
    
    - **Primary Attack Vectors:** No specific primary attack vectors are attributed to Lefaroll. General APT activities in the conflict context include DDoS attacks on Israeli websites and services, intrusion attempts on critical infrastructure, malware deployment, and data theft campaigns targeting organizations.3
        
    - **Malware/Tools Used:** No specific malware or tools are attributed to Lefaroll. Mentions of "ransomware and wipers like Shamoon and Deadwood" are generally tied to Iranian state hackers, not Lefaroll specifically.3
        
    - **Exploits & Vulnerabilities Commonly Targeted:** No specific exploits or vulnerabilities are mentioned as being commonly targeted by Lefaroll.
        
- **Indicators of Attack (IOAs) & Tactics**
    
    - **Behavioral Patterns:** No specific behavioral patterns are attributed to Lefaroll.
        
    - **Signatures:** No specific file hashes, IPs, domains, or YARA rules are provided for Lefaroll.
        
    - **TTPs (MITRE ATT&CK Framework mapping):** No specific TTPs are attributed to Lefaroll. General APT TTPs mentioned in the broader context include social engineering (spear-phishing), malware distribution (via Strategic Web Compromise and malicious attachments), lateral movement, persistence mechanisms, credential harvesting, and data exfiltration.14
        
- **Infrastructure Analysis**
    
    - **C2 (Command & Control) Servers:** No specific C2 server domains or IP ranges are identified for Lefaroll.
        
    - **Proxy/Pivot Networks:** No information on proxy/pivot networks used by Lefaroll.
        
    - **Malware Distribution Channels:** No specific malware distribution channels are identified for Lefaroll.
        
- **Historical Background**
    
    - **Origins & Alleged Affiliations:** No specific historical background for Lefaroll is provided beyond its listing as a pro-Iran group 3 and its mention as a "non-Iranian hacktivist group now targeting Israel".3
        
    - **Notable Attacks & Campaigns (Timeline of Major Incidents):** No notable attacks or campaigns are specifically attributed to Lefaroll.
        
    - **Evolution Over Time:** No information on the evolution of tools, targets, or methods for Lefaroll.
        

### E. Predatory Sparrow (Gonjeshke Darande)

- **Attribution & Threat Intelligence**
    
    - **Suspected Geographic Origin:** Predatory Sparrow is widely believed to be affiliated with Israel.7 Iran has also explicitly accused the group of having foreign backing, specifically from Israel.27
        
    - **Alleged Affiliations:** The group self-proclaims as a hacktivist entity 9, asserting its role in defending Iranian citizens against the "aggression of the Islamic Republic".9 However, its demonstrated technical proficiency, strategic targeting, and access to resources suggest it operates as a proxy for a state, most likely the Israeli military.7 The group is also known by its Persian name, Gonjeshke Darande.9 Predatory Sparrow's self-identification as a hacktivist group, despite exhibiting capabilities typically associated with state-level operations (such as customized wiper malware, strategic targeting of industrial control systems, precise operational coordination, and even claims of ethical restraint), exemplifies a sophisticated form of state-sponsored hacktivism. The group's actions, including displaying the "64411" number—a reference to Supreme Leader Ayatollah Ali Khamenei's office—on compromised systems 9, are clearly designed to maximize embarrassment and directly channel public dissatisfaction towards the Iranian regime. This strategic approach indicates a deliberate blend of cyber sabotage and psychological warfare, aimed at eroding public trust in the targeted government and potentially inciting internal unrest.
        
- **Digital Footprint & Presence**
    
    - **Official/Cover Websites:** No specific official or cover websites are directly attributed to Predatory Sparrow. "Handala's onion website lists all alleged breaches" in a broader context of hacktivist groups, including Predatory Sparrow's listing.3
        
    - **Social Media Accounts:** Predatory Sparrow maintains a strong online presence, notably with an account on X (formerly Twitter) under its Persian name, Gonjeshke Darande.9 It also operates a regularly updated Telegram channel, where it posts statements regarding its operations.3
        
    - **Forums:** No information regarding forums (underground, clearnet, or dark web) used by Predatory Sparrow.
        
    - **Dark Web Links:** No specific dark web links (marketplaces, leak sites, or communication channels) are provided for Predatory Sparrow, though "Handala's onion website" is mentioned in a related context.3
        
- **Attack Methods & Tools**
    
    - **Primary Attack Vectors:** Predatory Sparrow's primary attack vectors involve direct cyberattacks targeting critical infrastructure systems.9
        
    - **Malware/Tools Used:** The group notably employs a custom customizable wiper malware, which has been dubbed "Meteor".9 This malware is specifically designed to delete or overwrite data on target devices and networks, rendering them unusable.9 A distinctive characteristic of their operations is their claim of acting responsibly, including providing warnings to emergency services before an operation and ensuring that a portion of targeted systems (e.g., gas stations) remain operational, despite having the capability for complete disruption.29
        
    - **Exploits & Vulnerabilities Commonly Targeted:** No specific exploits or vulnerabilities are explicitly mentioned as being commonly targeted by Predatory Sparrow in the provided material.
        
- **Indicators of Attack (IOAs) & Tactics**
    
    - **Behavioral Patterns:** Predatory Sparrow exhibits highly strategic target selection and precise internal coordination in its operations.9 A recurring behavioral pattern is their public claims of ethical restraint, such as timing attacks to minimize harm to workers or deliberately ensuring partial functionality of disrupted services.9 Their operations are consistently designed to maximize visibility and embarrassment for the Iranian regime.9
        
    - **Signatures:** A notable signature of their attacks is the display of the digits "64411" on affected systems, directing frustrated users to call Supreme Leader Ayatollah Ali Khamenei's office.9 Cybersecurity firm Check Point's research team has also identified code in the malicious software used by Predatory Sparrow that matches code from previous attacks, such as the 2021 hacking of Iranian train stations.31
        
    - **TTPs (MITRE ATT&CK Framework mapping):** While no direct MITRE ATT&CK mapping is provided for Predatory Sparrow, their attacks on industrial control systems (ICS) and operational technology (OT) 9 align with the MITRE ATT&CK for ICS framework.35 Specific tactics observed would include:
        
        - **Impact (TA0040):** This is evident through their use of wiper malware to destroy or overwrite data, rendering systems unusable (T1499.001 - Data Destruction, T1499.002 - Data Manipulation) and causing physical damage to industrial machinery.9
            
        - **Disruption of Services (T1531):** The attacks on fuel distribution and railway systems directly disrupt critical services.9
            
        - **Command and Control (TA0011):** While not explicitly detailed, the coordination required for such precise and impactful attacks implies sophisticated C2 mechanisms.
            
        - **Lateral Movement (TA0008):** The scope of their attacks across multiple facilities suggests lateral movement capabilities within targeted networks.
            
- **Infrastructure Analysis**
    
    - **C2 (Command & Control) Servers:** No specific C2 server domains or IP ranges are directly attributed to Predatory Sparrow in the context of their attacks. It is important to distinguish "Predatory Sparrow" from "Predator spyware," which is a distinct entity. Information on "Predator spyware infrastructure" describes a multi-tiered design to hide its origin, with Tier 4 often pointing to in-country IPs linked to customers and Tier 5 connected to a Czech company.36 This information is not directly linked to Predatory Sparrow, and the name similarity should not lead to conflation.
        
    - **Proxy/Pivot Networks:** No specific proxy or pivot networks (e.g., TOR, bulletproof hosting, compromised devices) are identified for Predatory Sparrow.
        
    - **Malware Distribution Channels:** No specific malware distribution channels are mentioned for Predatory Sparrow.
        
- **Historical Background**
    
    - **Origins & Alleged Affiliations:** Predatory Sparrow has been active since at least mid-2021.9 While it presents itself as a hacktivist group, it is widely suspected to be a proxy for the Israeli military.7
        
    - **Notable Attacks & Campaigns (Timeline of Major Incidents):**
        
        - **July 2021:** Targeted Iran's Ministry of Roads and Urban Development, disrupting train schedules and displaying the "64411" message on digital information boards.9
            
        - **October 2021:** Attacked Iran's network of petrol stations, temporarily disabling state-subsidized fuel smart cards. This attack also incorporated the "64411" number.9
            
        - **January 2022:** Interrupted Iran's state-run television network, inserting a 10-second clip that called for the death of the Supreme Leader and displayed images of leaders from the Mujahedin E-Khalq (MEK).9
            
        - **June 2022:** Reportedly caused a failure in a steel plant in Khuzestan province, southwest Iran, resulting in machinery malfunction that spewed fire and molten steel. The group claimed the attack was timed to minimize risks to workers.9
            
        - **December 2023:** Again disrupted Iran's fuel distribution system, reportedly affecting nearly 70% of the country's petrol stations. This solidified the group's focus on infrastructure critical to daily life.9
            
        - **June 2025:** Claimed responsibility for a cyberattack targeting Bank Sepah, one of Iran's oldest financial institutions, alleging the destruction of all data. The group stated the bank was targeted for its alleged role in financing military programs and circumventing international sanctions.27
            
    - **Evolution Over Time:** Predatory Sparrow has consistently utilized wiper malware and targeted critical infrastructure. Its evolution demonstrates a shift from primarily disruptive attacks on train and fuel systems to operations with a direct physical impact, such as the steel plant incident.9 The group's recurring claims of ethical restraint in its operations are also a notable and consistent theme.9
        

### F. Israeli Gladiator

- **Attribution & Threat Intelligence**
    
    - **Suspected Geographic Origin:** Israeli Gladiator is listed among "pro-Iran (65 Groups)".3
        
    - **Alleged Affiliations:** The group is consistently identified as a pro-Iranian hacktivist group.3 This directly contradicts the query's "PRO-ISRAEL" label. Furthermore, other pro-Palestinian groups like "Israel Exposed" are mentioned in the context of leaking information about Israeli soldiers.37 The name "Israeli Gladiator" itself is highly misleading given its consistent identification as a "pro-Iran" hacktivist group. This highlights the deliberate use of deceptive naming conventions in information warfare, which can be intended to confuse attribution or sow discord among target populations. For threat intelligence analysts, this means that group names cannot be taken at face value and necessitate thorough vetting against their operational patterns and confirmed affiliations to avoid mischaracterizing threats.
        
- **Digital Footprint & Presence**
    
    - **Official/Cover Websites:** No specific official or cover websites are attributed to Israeli Gladiator. "Handala's onion website lists all alleged breaches" in a broader context of hacktivist groups, including Israeli Gladiator's listing.3
        
    - **Social Media Accounts:** Israeli Gladiator is listed in Telegram posts alongside other pro-Iran hacktivist groups.3 However, no specific Telegram or X/Twitter accounts are detailed for Israeli Gladiator. Mentions of "Gladiator II" and associated actors/films on social media are irrelevant to the cyber threat group.38
        
    - **Forums:** No information regarding forums (underground, clearnet, or dark web) used by Israeli Gladiator.
        
    - **Dark Web Links:** No dark web links (marketplaces, leak sites, or communication channels) are provided for Israeli Gladiator, though "Handala's onion website" is mentioned in a related context.3
        
- **Attack Methods & Tools**
    
    - **Primary Attack Vectors:** No specific primary attack vectors are attributed to Israeli Gladiator. General APT activities in the conflict context include DDoS attacks on Israeli websites and services, intrusion attempts on critical infrastructure, malware deployment, and data theft campaigns targeting organizations.3
        
    - **Malware/Tools Used:** No specific malware or tools are attributed to Israeli Gladiator. Mentions of "ransomware and wipers like Shamoon and Deadwood" are generally tied to Iranian state hackers, not Israeli Gladiator specifically.3
        
    - **Exploits & Vulnerabilities Commonly Targeted:** No specific exploits or vulnerabilities are mentioned as being commonly targeted by Israeli Gladiator.
        
- **Indicators of Attack (IOAs) & Tactics**
    
    - **Behavioral Patterns:** No specific behavioral patterns are attributed to Israeli Gladiator.
        
    - **Signatures:** No specific file hashes, IPs, domains, or YARA rules are provided for Israeli Gladiator.
        
    - **TTPs (MITRE ATT&CK Framework mapping):** No specific TTPs are attributed to Israeli Gladiator. General APT TTPs mentioned in the broader context include social engineering (spear-phishing), malware distribution (via Strategic Web Compromise and malicious attachments), lateral movement, persistence mechanisms, credential harvesting, and data exfiltration.1
        
- **Infrastructure Analysis**
    
    - **C2 (Command & Control) Servers:** No specific C2 server domains or IP ranges are identified for Israeli Gladiator.
        
    - **Proxy/Pivot Networks:** No information on proxy/pivot networks used by Israeli Gladiator.
        
    - **Malware Distribution Channels:** No specific malware distribution channels are identified for Israeli Gladiator.
        
- **Historical Background**
    
    - **Origins & Alleged Affiliations:** No specific historical background for Israeli Gladiator is provided beyond its listing as a pro-Iran group.3 General Iranian-linked groups like Moses Staff and CyberAv3ngers have been noted for leaking data and attacking Israeli infrastructure.3
        
    - **Notable Attacks & Campaigns (Timeline of Major Incidents):** No notable attacks or campaigns are specifically attributed to Israeli Gladiator.
        
    - **Evolution Over Time:** No information on the evolution of tools, targets, or methods for Israeli Gladiator.
        

## IV. Conclusions

The comprehensive analysis of the six specified APT groups reveals a nuanced and often contradictory landscape within the Israel-Iran cyber conflict. A primary conclusion is the significant discrepancy in the initial categorization provided: only Garuna Ops and Predatory Sparrow align with the "PRO-ISRAEL" designation.4 Conversely, NPFN, Lefaroll, and Israeli Gladiator are consistently identified as pro-Iranian or anti-Israel hacktivist groups.3 For Eagle7, the available intelligence does not provide any relevant cyber activity within this conflict context.10

The groups exhibit a wide spectrum of operational sophistication. At one end, groups like Garuna Ops appear to engage primarily in hacktivist-style DDoS attacks.3 At the other, Predatory Sparrow demonstrates capabilities indicative of a sophisticated, potentially state-sponsored entity, engaging in cyber-physical sabotage using custom wiper malware and strategic targeting of critical infrastructure.9

This disparity in capabilities and the deliberate misdirection in group affiliations underscore the blurring lines between genuine hacktivism and state-sponsored operations. Nation-states frequently leverage hacktivist "cutouts" to conduct disruptive operations while maintaining plausible deniability.3 This practice significantly complicates attribution efforts for defenders, as the public-facing identity of a group may not accurately reflect its true backing or resources. Consequently, a deeper, more analytical approach is required to assess the true nature of the threat, moving beyond superficial labels.

The cyber conflict between Israel and Iran is characterized by its dynamic and rapidly escalating nature. Attacks often surge in direct response to physical geopolitical events, and threat actors continuously adapt their TTPs to circumvent evolving defenses.1 This necessitates continuous monitoring, proactive threat intelligence integration, and adaptive defensive strategies to detect subtle anomalies and respond effectively.

Finally, the challenges encountered in attributing and profiling these groups highlight the inherent difficulties in open-source intelligence. Issues such as name overlaps, lexical ambiguities, and deliberate misdirection by threat actors create a complex environment for intelligence gathering. This underscores the critical importance of rigorous critical analysis, cross-referencing information from multiple sources, and maintaining a skeptical approach to self-proclaimed identities to build an accurate and actionable understanding of the cyber threat landscape.