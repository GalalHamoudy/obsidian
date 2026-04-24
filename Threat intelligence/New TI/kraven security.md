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

 it fails to 
1- include key stakeholders in the intelligence process
2- define key operational tasks
3- incorporate the specialist knowledge and skills required to fulfill some intelligence requirements.

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

A classic is [Analysis of Competing Hypotheses](https://kravensecurity.com/courses/structured-analytical-technqiues/lessons/analysis-of-competing-hypotheses/) (ACH)—it’s a simple method where you list _all_ possible explanations (not just your favorite one) and systematically try to _disprove_ each one. What’s left is your most likely and defensible answer. It’s the scientific method for spies.

The simplest way to think about it is in terms of “artifacts vs. behaviors.” Tactical CTI addresses the artifacts of an attack (IPs, hashes, domains) that are easily modified and have a short lifespan. Artifacts are like a disposable lighter. Operational CTI deals with the behaviors of the attacker (their TTPs), which are much harder for them to change. Behaviors are the attacker’s knowledge of how to start a fire.

OSINT includes:

- **Security News & Blogs:** Sites like [Bleeping Computer](https://www.bleepingcomputer.com/) and [Krebs on Security](https://krebsonsecurity.com/), which break news on major breaches and actor tactics.
- **Government Alerts:** Bulletins from agencies like [CISA](https://www.cisa.gov/)  in the US or the [NCSC](https://www.google.com/aclk?sa=L&ai=DChsSEwjm6bSvnsSQAxWSmlAGHXgGJX8YACICCAEQABoCZGc&co=1&ase=2&gclid=Cj0KCQjwsPzHBhDCARIsALlWNG3m4KkfFV3yij8Tz-fn4xF_GZJ4-G_CVuGfn2MyyzGBCb9NxowxUdUaAr_9EALw_wcB&cce=2&category=acrcp_v1_32&sig=AOD64_1xMXPciVJ-pT_4jd0yYS-thJUWTQ&q&nis=4&adurl&ved=2ahUKEwiFiKuvnsSQAxUdVkEAHW7pFHYQ0Qx6BAgLEAE) in the UK. These are often your “official source of truth” for major, widespread vulnerabilities (like [Log4j](https://www.ibm.com/think/topics/log4j)).
- **Community Platforms:** Free platforms like [AlienVault OTX](https://otx.alienvault.com/), where anyone can submit, browse, and consume threat data “pulses.”
- **Social Media:** Researchers sharing findings, YARA rules, and hot-takes in real-time on X (formerly Twitter), Mastodon, and LinkedIn. This is where you’ll often see the _very first_ mention of a new attack.
- **Public Repositories:** [GitHub repos packed with IOCs](https://github.com/kraven-security/hunting-packages), malware samples, and analysis scripts. These are invaluable for building out your own analysis toolkit.

### Information Sharing and Analysis Centers (ISACs)

ISACs are non-profit, members-only organizations built to serve specific industry sectors (e.g., FS-ISAC for finance, H-ISAC for healthcare, E-ISAC for energy).

---

|**Feature**|**Unstructured Threat Intelligence**|**Structured Threat Intelligence**|
|---|---|---|
|**Format**|Free-form, narrative-driven, and without a strict schema (e.g., PDFs, blogs, news articles, text).|Follows a predefined, consistent data model with a rigid schema (e.g., STIX/TAXII, JSON, XML, CSV).|
|**Audience**|Primarily human analysts who use experience and intuition to interpret nuance and intent.|Primarily machines (SIEM, Firewall, TIP) that require a predictable format for automated parsing and action.|
|**Key Value**|Provides rich, strategic context—the “why” and “how”—that informs proactive defense and planning.|Delivers operational speed, scalability, and automation, enabling defense against threats at machine speed.|
|**Pros**|Often the most timely source of new threats; provides deep, detailed understanding of adversary TTPs.|Fully machine-readable, enabling near-instantaneous response and drastically reducing MTTD/MTTR.|
|**Cons**|Difficult and slow to process automatically; often contains “noise” and requires significant effort to validate.|Lacks narrative context, which can lead to simplistic actions (e.g., blocking a shared IP) without understanding the “why.”|
|**Example**|A detailed analysis of a FIN7 campaign on a vendor blog, with attack chain diagrams and adversary quotes.|A STIX 2.1 JSON object defining the relationship between the ‘FIN7’ threat actor and the C2 domains it uses.|

---

to perform CTI project planning by creating the five key pieces of documentation every CTI project needs.

- Structured brainstorming to generate ideas.
- Terms of Reference (ToR) to solidify those ideas and align with customer expectations.
- A Work Breakdown Structure (WBS) to map your CTI project to a timeline.
- Intelligence Requirements to turn objectives into requirements your CTI team can fulfill.
- A Collection Management Framework (CMF) will turn requirements into questions your CTI team can answer and map these to collection capabilities that will provide those answers.

a Work Breakdown Structure (WBS) for a CTI project could be broken into four phases:
1. **Direction**: You can cover this phase during the project scoping call with the client and your structured brainstorming session. You should be able to create a list of objectives to turn into intelligence requirements. The phase should end with delivering the ToR, WBS, and intelligence requirements to the consumer.
2. **Collection and Processing**: This is where the real intelligence work begins. You must seek out data that will allow you to fulfill the intelligence requirements defined using various [collection sources](https://kravensecurity.com/intelligence-collection-sources/).
3. **Analysis**: This phase should overlap with the collection and processing phase in your WBS. Often, you must revisit the collection phase after your initial analysis.
4. **Dissemination and Feedback**: Once you share the intelligence product with your consumer, it is a good place to call the project closed. You should “pad” this phase with time to allow for a product draft, revisions, and quality assurance.

The intelligence requirements (IRs) you define for your CTI project come from the objectives, deliverables, and success criteria outlined in the ToR you signed with the client. They are a list of questions (or topics) that your CTI team must focus on answering.

A Collection Management Framework (CMF) systematically tracks intelligence requirements by mapping each IR to a data source or collection capability that can be used to answer it.

---

To manage risks, you can perform two types of assessments:

1. A **risk assessment**: This assesses an organization’s vulnerabilities in relation to the threat it faces. It is organization-specific and focuses on how the organization’s uniqueness would be of interest to a threat (e.g., what technology is used, what data the company holds, etc.).
2. A **threat assessment**: This considers the overall capability and intent of the threat. It is threat-focused and separate from the organization, often including a threat actor’s tactics, techniques, procedures (TTPs), or kill chain.

---

In a CTI report, this usually takes the following form:

1. Headline
2. Executive summary
3. Key details or evidence
4. Supporting evidence
5. Technical details (e.g., malware analysis details)
6. Recommendations
7. Background information and appendices (e.g., IOCs, TTPs, detection rules).

The MITRE [CTI Blueprints project](https://kravensecurity.com/mitre-cti-blueprints/) defines four main types:

- **Threat Actor Report**: This report type is a living encyclopedia about a threat actor or category of activity that is updated whenever new intelligence about an adversary is generated. It is a reference for tactical teams to understand how an adversary operates.
- **Intrusion Analysis Report**: These reports support threat hunting and incident response operations by providing actionable indicators that these teams can use to search for threats within your environment. They are iterative and based on [intrusion analysis](https://kravensecurity.com/intrusion-analysis/) findings.
- **Campaign Report**: This report highlights new information about threat actors, campaigns, and capabilities. It is concise and conveys changes that your intelligence consumers should be aware of.
- **Executive Report**: This report informs key decision-makers (non-technical stakeholders) about threats. It is clear and precise to support a strategic decision, focusing on the why and how rather than the what and when.

To write an effective CTI report, you should follow these five steps:

1. **Research** the topic, event, or outcome for which you are writing an intelligence assessment. You must provide context, allowing the reader to get up to speed on the threat landscape quickly. 
2. **Prep the page** by outlining the main parts of your report, such as the headline, introduction, main points, and conclusion. Next, list the ideas you wish to cover under each of these main components.   
3. **Fill in the content** using your outline. Add connecting sentences to join each component and transform your bullet points into sentences.
4. **Add details, visuals, and citations** to your report to enhance its content and make it more appealing to read.
5. **Review, revise, and publish** your CTI report. Ensure it is free of mistakes and poor grammar, with all the key details included.



