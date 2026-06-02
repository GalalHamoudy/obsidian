# The key points

1. Intrusion Analysis is the Foundation
- **The Most Important Skill:** Intrusion analysis is considered the most basic and important skill for any Cyber Threat Intelligence (CTI) analyst.
- **Where Intelligence Comes From:** Almost all good threat intelligence starts with looking at "intrusions" (attempts to break into a network).
- **Look Inside First:** The most valuable information you can find is often the data from attacks happening against your own organization.

2. CTI and Incident Response (IR) Work Together
- **Partnership:** People who respond to incidents (IR) and people who analyze threats (CTI) need each other. CTI analysts use the data collected by IR teams to understand the attacker.
- **Better Defense:** Intelligence should guide how a company defends itself. By understanding how an attacker works, teams can "hunt" for them more effectively.

3. Key Terms to Know
- **Intrusion:** This is any attempt by an attacker to get into a system. It doesn't matter if they succeed or fail—both give you useful information.
- **Compromise:** This is a specific type of intrusion where the attacker successfully reaches their final goal.
- **Key Indicators:** These are the clues (like IP addresses or file names) that stay the same across different attacks. They help you uniquely identify a specific group or campaign.

4. Using Models to Organize Information
   Analysts use two main models to make sense of an attack:
- **The Kill Chain:** This looks at the **steps** an attacker takes, from the first research (Reconnaissance) to their final goal (Actions on Objectives).
- **The Diamond Model:** This looks at four **parts** of every attack event: the Adversary (who), the Capability (the tools they used), the Infrastructure (the computers they used), and the Victim (who was attacked).

5. Courses of Action (CoA)
- **The Defender’s Menu:** For every step an attacker takes in the Kill Chain, defenders have a list of options to fight back. These include **Discovering** the threat, **Detecting** it, **Denying** access, **Disrupting** the attacker's work, and **Degrading** their tools.
- **Stopping the Attack:** You can stop an attacker even after they are inside your network if you react fast enough to block their final goals.

---

Intrusion Analysis is the Foundation
- **The Basic Skill:** Intrusion analysis is the most fundamental and important skill for a Cyber Threat Intelligence (CTI) analyst.
- **Definition of Intrusion:** This includes any attempt by an attacker to break into a system, whether they succeed or fail.
- **The Best Data:** The most valuable information usually comes from attacks happening against your own organization (incident response data).
- **CTI and Incident Response (IR):** These two teams work together. CTI analysts use the data collected by IR teams to understand how attackers work.

The Cyber Kill Chain (The 7 Steps)
The Kill Chain describes the specific steps an attacker must take to successfully steal data. If a defender stops them at any step, the attacker fails.
1. **Reconnaissance:** The attacker researches the target to find weaknesses.
2. **Weaponization:** They create a malicious tool (like malware) for the attack.
3. **Delivery:** They send the tool to the victim, often via email or USB.
4. **Exploitation:** The malicious code triggers a weakness in the victim's system.
5. **Installation:** They install software (like a "backdoor") so they can stay inside the system.
6. **Command and Control (C2):** The system "calls home" to the attacker to receive orders.
7. **Actions on Objectives:** The attacker reaches their final goal, such as stealing files.

The Diamond Model (The 4 Parts)
While the Kill Chain looks at **steps**, the Diamond Model looks at the **four parts** of any single attack event:
- **Adversary:** The person or group behind the attack.
- **Capability:** The tools, malware, or techniques used.
- **Infrastructure:** The physical or virtual resources used (like IP addresses).
- **Victim:** The target, which could be a person, a computer, or a whole company.

Important Rules (Axioms) for Analysis
Axioms are accepted assumptions that help analysts think correctly about threats:
- **Axiom 1:** Every attack event must have all four parts (Adversary, Capability, Infrastructure, Victim).
- **Axiom 2:** There is always a human adversary with a specific reason (intent) for the attack.
- **Axiom 3:** Every computer and network has weaknesses.
- **Axiom 4:** Attacks always happen in steps, and every step must succeed for the attacker to move forward.
- **Axiom 5:** Attackers need resources (like tools and networks). These are also their vulnerabilities.
- **Axiom 6:** A relationship always exists between the attacker and the victim.
- **Axiom 7:** Some attackers are skilled enough to stay active for a long time even if you try to stop them.

Merging the Models
Analysts often put a Diamond Model inside **every step** of the Kill Chain.
- **Finding Gaps:** This helps you see what you know and what information is missing (intelligence gaps).
- **Flexibility:** A clue can move categories. For example, a malicious file might be a **Capability** in one step, but it might lead you to a new **Infrastructure** (like a URL) in another.

The Courses of Action (CoA) Matrix
This matrix tells defenders what their options are for every phase of the Kill Chain. It uses the **7 Ds of Action**:
- **Discover:** Find past evidence of an attack.
- **Detect:** Find the attack as it is happening.
- **Deny:** Stop the attack from happening at all.
- **Disrupt:** Interfere so the attacker fails.
- **Degrade:** Slow down or weaken the attacker's tools.
- **Deceive:** Give the attacker false information.
- **Destroy:** Completely remove the attacker's ability to operate (rarely used by private companies).

Passive vs. Active Actions
- **Passive Actions:** Actions like "Discover" and "Detect" do not interfere with the attacker. You can do both at the same time.
- **Active Actions:** Actions like "Deny" or "Disrupt" stop the attacker. You usually have to pick just **one** active action because they can interfere with each other.
- **Trade-offs:** If you "Deny" (block) an attacker immediately, they are stopped, but you might lose the chance to learn more about them. This is called the "intelligence gain/loss" calculation.

---

The MITRE ATT&CK Framework
- **What it is:** A globally used documentation of adversary tactics and techniques based on real-world observations.
- **Tactics vs. Techniques:** In ATT&CK, **Tactics** represent the attacker's technical goals (like "Initial Access"), and **Techniques** represent how they achieve those goals (like "Phishing").
- **Standard Language:** It provides a common language for analysts to communicate about attacker behaviors rather than just sharing simple clues like IP addresses.
- **Specialized Models:** There are different versions of ATT&CK for different environments, such as **Mobile**, **Cloud**, and **Industrial Control Systems (ICS)**, because attackers behave differently in those areas.

Practical Application: Exercise 2.1
- **The Task:** Analysts practice identifying disconnected pieces of data from several different intrusions to see if they are related.
- **Finding Connections:** By mapping indicators to the Kill Chain and Diamond Model, you can determine if an attack was successful or where it was stopped.

CTI and Incident Response (IR)
- **Partnership:** Cyber Threat Intelligence and Incident Response depend on each other; IR teams collect the data that CTI analysts use to understand patterns.
- **Guiding the Defense:** Intelligence helps responders know what to look for next during an active investigation.

Identifying Knowledge Gaps
- **Asking the Right Questions:** Analysts must constantly ask, "Where are we now?" and "What is missing?".
- **Spotting Gaps:** If you only have an IP address for an attack, you have an "intelligence gap" because you don't yet know what tool or capability the attacker used.
- **Tracking Progress:** Using a matrix helps show which actions (like "Discovery") have been finished and which ones are still needed.

Kill Chain Completion Strategy
- **Prioritizing the "Worst":** When you detect an attack, you should first look to the **right** on the Kill Chain (toward "Actions on Objectives"). This helps you find the worst possible damage first.
- **Working Backward:** Once the damage is understood, you then work **backward** (to the left) to find all the steps the attacker took to get in.
- **Deterministic Rule:** Because the Kill Chain is a set process, if an attacker reached a late stage (like Stage 6), you know they **must** have completed all the earlier stages, even if you haven't found the evidence for them yet.

Phase 7: Actions on Objectives
- **The Final Step:** This phase covers anything the attacker does once they have control. To understand this, analysts use two main strategies: **Network Pivoting** (looking at communication patterns) and **Host Pivoting** (looking at what happened on the actual computer's memory or disk).
- **Forensics is Required:** Completing an analysis of this stage almost always requires **host-based forensics**. If a company cannot analyze its own computers, its threat intelligence will be incomplete or even unusable.

Identifying Attacker "Fingerprints"
- **Human Patterns:** Attackers are humans who make choices. Analysts look for "human fingerprints," such as an attacker's **specific work hours** or the specific ways they register their domains.
- **Example (APT10):** By tracking when malware was compiled or domains were registered, analysts can guess the attacker's time zone and typical work week.

The "Rule of 2" for Grouping Attacks
- **A Shortcut for Clustering:** Instead of complex analysis, you can use the **Rule of 2**. If two different attacks share at least **two parts** of the Diamond Model (like the same tool and the same target type), you can start to group them together as a single "Activity Group".
- **Managing Groups:** Clusters are labeled as **Active, Inactive, or Dormant**. You should never delete this data, because a new attack in the future might explain an old attack from years ago.

Moving from Consuming to Generating Intel
- **Making the Switch:** Organizations move from just reading other people's reports ("consuming") to creating their own ("generating") when their specific **Intelligence Requirements** are not being met by outside sources.
- **Organizational Readiness:** This switch requires "buy-in" from leadership and a team ready to do deep analysis.

Using Tools for Analysis
- **Mind Mapping:** Tools like **MindMup** are used for brainstorming and organizing research variables.
- **Visual Linking:** Analysts use tools like **Maltego** or **MISP** to see connections between indicators. For example, a "Circular Layout" in a graph can quickly show if multiple malicious files are all talking to the same IP address.

Assessments vs. Facts
- **A Golden Rule:** The course emphasizes that **assessments are not facts**. Assessments are professional judgments based on evidence and sources, but they are still "tentative" and can change as new information arrives.

Practice and Forensics
- **Host-Based Analysis:** Practical exercises (like Exercise 2.3) focus on pivoting to **computer memory** to find hidden clues left by attackers.
- **Reverse Engineering:** While analyzing malware is powerful, it is described as both "art and engineering" and can be very time-consuming.

Case Study: Ukraine 2016
- **The Scenario:** This section highlights the December 2016 attack on Ukraine's electric grid, which occurred almost exactly one year after a similar attack in 2015.
- **Organizational Concern:** In the lab scenario, the company "Edison Power" needs to know if this specific grid-focused malware could impact their own power systems or their R&D manufacturing subsidiaries.

Internal Collection Management Framework (ICMF)
- **Mapping Data to the Attack:** Analysts use a framework to see which security tools (like Firewalls or Windows Logs) cover different parts of the **Kill Chain**.
- **Finding Gaps:** For example, Network Firewalls are great for seeing **Command and Control (C2)**, while Host-Based Logs are better for seeing **Actions on Objectives**.

Systems Analysis and Target-Centric Models
- **Understanding Yourself:** **Systems Analysis** is the process of intentionally building a mental model of your own organization to understand its weaknesses and how an attacker might target it.
- **Target-Centric Intelligence:** Developed by Robert Clark, this approach treats the intelligence cycle as a **nonlinear, living process** where everyone (analysts and customers) works together around a central "Target" model to avoid information being "stovepiped" (hidden in separate teams).

Building a Threat Model
- **Reviewing Critical Assets:** To protect an organization, you must first identify its most important resources, such as **Financial Data**, **Intellectual Property**, and **System Availability**.
- **Collaborative Research:** Getting the right information requires working with other teams in the company to identify what has been targeted in the past and what adversaries are currently targeting your specific industry.

Strategic Threat Modeling
- **Positioning for the Future:** Exercise 1.4 focuses on using previous incident data and industry reports (like those from Dragos or Symantec) to create a high-level model for executives and the CEO.

Finalizing the Intrusion (Exercise 2.5)
- **Satisfying Requirements:** The goal of this final intrusion exercise is to document findings and answer **Priority Intelligence Requirements (PIRs)**.
- **Key Findings:**
    - **Success of the Attack:** Only one intrusion (the "Top Energy" set) was a successful compromise because the attacker reached Stage 7 (Actions on Objectives).
    - **Adversary Fingerprints:** Analysts noted specific human behaviors, such as the attacker using the **target's own company name as a password** for stolen files (out.rar).
    - **The TTPs:** The attacker used a mix of "Living off the Land" tools (like **PowerShell** and **ipconfig.exe**) and common malicious software like **Meterpreter**.
- **Analytical Flexibility:** The course emphasizes that what an analyst chooses to highlight in an intrusion report is subjective and depends entirely on the specific needs of the people receiving the intelligence.
