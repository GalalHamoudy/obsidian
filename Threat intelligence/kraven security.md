## Data vs Information vs Intelligence

Data is raw. A log entry, a file hash, a packet capture. It tells you something happened, but not what it means. Think of it like CCTV footage with no timestamps and no labels. You’ve got the recording, but you can’t tell the story.

Information is structured data. You parse the logs. You enrich the IP address. Now you can answer who connected, from where, and when. You’re moving from “something happened” to “here is what happened.”

Intelligence is where the real value lives. This is the step most organizations haven’t built yet. This is where your analysts take that structured information, apply context about the adversary (their intent, their capability, and their past behavior), and produce something that answers the question you actually need answered: What does this mean for us, and what should we do about it?




_The Data-Information-Knowledge-Wisdom (DIKW) pyramid illustrates the progression of raw data to valuable insights_
https://www.datacamp.com/cheat-sheet/the-data-information-knowledge-wisdom-pyramid

_dwell time. How long does an attacker sit inside your environment before your team detects them?_

---

## F3EAD intelligence loop:

The F3EAD loop (or F3EAD cycle) is an alternative intelligence loop to the traditional [CT lifecycle](https://kravensecurity.com/what-is-cyber-threat-intelligence-a-quick-guide/). It was initially created for military, counterterrorism, and special forces operations to [target high-value individuals](https://mipb.army.mil/documents/12618257/17282447/F_Alternate+Targeting.pdf/53b4699f-a2b4-40eb-8e92-892a2284eea7) for “kill or capture.”  ,CTI has replaced “kill or capture” with “remove or restrict.”

The [CTI lifecycle](https://kravensecurity.com/the-threat-intelligence-lifecycle/) is excellent for providing a high-level overview of generating an intelligence product, from planning to dissemination. However, it fails to include key stakeholders in the intelligence process, define key operational tasks, or incorporate the specialist knowledge and skills required to fulfill some intelligence requirements.

The F3EAD intelligence loop fills these gaps using a target-centric approach that provides a more granular description of what is required to collect, process, and analyze the data needed to generate actionable intelligence. It can even be used in conjunction with the traditional CTI lifecycle, specifically between the Collection and Analysis stages.

![[Pasted image 20260328094833.png|701]]

- Stakeholders focus on making decisions using the OODA loop.
- CTI managers focus on generating intelligence from a tactical perspective with the CTI lifecycle.
- CTI analysts focus on the day-to-day operations required to generate the intelligence product using the F3EAD cycle.

These stages are Find, Fix, Finish, Exploit, Analyze, and Disseminate.

Find : 
you perform “target nomination” by deciding what you must find out about a target to answer the intelligence requirement you have been tasked with.
identify a target for collection

Fix :
Fix the collection to a "space and time"

Finish :
gathering additional malware samples, gathering information about a threat actor, or downloading the logs of an infected machine.

Exploit :
Exploit it to turn the data into information you can analyze.
send data to malware analist or DFIR or Reverse engineering

Analyze :
Once the raw data has been converted into information, a CTI analysis can examine it and extract actionable intelligence, allowing a stakeholder to develop a comprehensive understanding of the threat.
This stage will involve performing quantitative (e.g., data analytics, pattern recognition, etc.) or qualitative analysis using [Structured Analytical Techniques](https://kravensecurity.com/courses/structured-analytical-technqiues/) (SATs), such as the [Analysis of Competing Hypotheses](https://kravensecurity.com/analysis-of-competing-hypotheses/) (ACH).

Disseminate :
once you have produced your intelligence product, you must share it with relevant stakeholders and decision-makers to help them decide on an appropriate [course of action](https://kravensecurity.com/the-courses-of-action-matrix/) (CoA).

The [Cyber Threat Intelligence (CTI) lifecycle](https://kravensecurity.com/the-threat-intelligence-lifecycle/) has five main stages:

1. **Direction and Planning**: You define the goals and objectives of your threat intelligence activity.
2. **Collection**: Gather information that addresses the intelligence requirements you previously defined. This involves identifying relevant [data sources](https://kravensecurity.com/intelligence-collection-sources/) from which to collect information and storing it in a suitable location.
3. **Processing**: Once raw data is collected, it needs to be processed to transform it into information for analysis, which involves cleaning, normalizing, and verifying it.
4. **Analysis**: Turning your collected information into actionable intelligence by identifying patterns, trends, and insights.
5. **Dissemination**: Sharing the intelligence generated with key stakeholders.

D3A and F3EAD are both targeting methodologies used by military and intelligence personnel. D3A is a strategic planning tool useful at higher levels of military command, while F3EAD is helpful at the operational and tactical levels.

F3EAD has emerged as a prominent methodology used in cyber threat intelligence (CTI) to fulfill [intelligence requirements](https://kravensecurity.com/what-are-intelligence-requirements/) that require specialist skill sets, such as malware analysis, forensics, and reverse engineering. Meanwhile, D3A has remained a prominent planning tool in the military.

---

[FlowViz](https://www.flowviz.io/) is an open-source, web-based application designed to analyze [cyber threat intelligence reports](https://kravensecurity.com/cti-report-writing/) and generate interactive attack flow visualizations. Created by [David Johnson](https://feedly.com/ti-essentials/contributors/david-johnson), a Threat Intelligence Advisor at Feedly, it represents a significant shift in CTI tooling.

The entry point for any FlowViz workflow is the analysis module. You can input a direct URL to a public threat report (from sources like [The DFIR Report](https://thedfirreport.com/), [Mandiant](https://cloud.google.com/security/consulting/mandiant-services), [Red Canary](https://redcanary.com/), or [CISA](https://www.cisa.gov/)) or paste raw text directly.

## Unified Kill Chain:

The Three Cycles: In, Through, and Out

The In Cycle (Phases 1-8): Gaining Access and Establishing a Foothold
1. **Reconnaissance** – Gathering information about the target
2. **Weaponization** – Preparing attack tools and payloads
3. **Social Engineering** – Manipulating human targets (an explicit phase the original model lacks)
4. **Delivery** – Transmitting the weaponized payload
5. **Exploitation** – Triggering vulnerabilities to gain execution
6. **Persistence** – Maintaining access across reboots and credential changes
7. **Defense Evasion** – Avoiding detection by security controls
8. **Command & Control** – Establishing communication channels

The Through Cycle (Phases 9-14): Internal Propagation and Positioning
9. **Pivoting** – Using compromised systems as a launching point
10. **Discovery** – Mapping the internal network, identifying assets
11. **Privilege Escalation** – Obtaining higher-level access rights
12. **Execution** – Running malicious code on additional systems
13. **Credential Access** – Harvesting passwords and authentication materials
14. **Lateral Movement** – Spreading across the network to reach targets

The Out Cycle (Phases 15-18): Achieving Strategic Objectives
15. **Collection** – Gathering target data from compromised systems
16. **Exfiltration** – Moving collected data out of the environment
17. **Impact** – Disrupting operations, destroying data, or deploying ransomware
18. **Objectives** – Achieving the overarching strategic goal

---

A framework called **information disorder** that provides precise classification based on two questions: accuracy and intent.


|**Information Type**|**Accuracy**|**Intent to Harm**|**Example in CTI**|
|---|---|---|---|
|**Misinformation**|False|No|Analyst unknowingly shares outdated malware analysis.|
|**Disinformation**|False|Yes|Leaked internal security docs were published to embarrass the organization.|
|**Malinformation**|True|Yes|Leaked internal security docs published to embarrass the organization.|














