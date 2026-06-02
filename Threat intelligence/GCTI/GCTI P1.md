# the key parts of chapter 1:

1. Understanding Intelligence and CTI: 
	1. CTI is analyzed information regarding an adversary's intent, opportunity, and capability.
	2. The Intelligence Life Cycle: This is a repeating process consisting of five stages: Planning and Direction, Collection, Processing and Exploitation, Analysis and Production, and Dissemination
2. The Analyst’s Mindset and Tools: 
	1. A major part of being a good analyst is understanding how we think and avoiding biases (mental shortcuts that can lead to mistakes)
	2. Analysts must move from intuitive, fast thinking (System 1) to slow, methodical, and analytical thinking (System 2)
	3. Structured Analytic Techniques (SATs): These are methods, like decomposition (breaking a problem into parts) and visualization, that help analysts evaluate information transparently while reducing bias
3. Key CTI Terminology
4. Consuming and Generating Intelligence
	1. Organizations can either consume intelligence (use information provided by others) or generate it (create their own analysis from raw data)
	2. The Sliding Scale of Cyber Security: Intelligence is one part of a scale that includes Architecture, Passive Defense, Active Defense, and Offense. Good intelligence should drive value back into defense and architecture
	3. Intelligence Requirements: Before starting analysis, an organization must define what it needs to know. These are categorized as Tactical, Operational, or Strategic requirements
	4. Collection Management Framework (CMF): This is a plan that helps an organization understand what data they have access to and what questions that data can (and cannot) answer
5. Advanced Analysis Frameworks
	1. Target-Centric Analysis: This focuses on building a model of the target (the organization's assets) and then determining who might attack those assets and why
	2. VERIS Framework: A standard vocabulary for recording incident details including the Action, Asset, Actor, and Attribute involved in a breach
6. Case Studies (Lessons from History)
	1. Moonlight Maze: An early example of state-sponsored digital espionage that showed the importance of tracking long-term patterns
	2. Operation Aurora: A major campaign targeting many companies that highlighted the challenges of attribution (identifying who is responsible)
	3. Carbanak: A massive cyber crime operation where attackers stole up to $1 billion from banks, showing that "Advanced Persistent Threats" (APTs) are a style of attack, not just a label for nation-states

---

# Moonlight Maze 

Moonlight Maze is described as "The Dawn of State-Sponsored Digital Espionage". It represents one of the first major public cases of a highly sophisticated, long-term foreign intelligence operation targeting sensitive networks.
Here are the comprehensive details of the case:

### **Overview and Discovery**
*   **Timeline:** The intrusions into U.S. military and government networks began as early as **1996**. While the attack had been ongoing for years, it only broke into the news in 1999.
*   **Initial Detection:** In November 1996, an administrator at the Colorado School of Mines reported suspicious activity. Later, in 1997, the Department of Energy logged over 300 attempts to access their systems.
*   **Scope of Targets:** The operation targeted high-value entities, including the **Pentagon, NASA**, Department of Energy Nuclear Weapons and Research labs, defense contractors, and various national labs and universities.

### **The Investigation**
A vast investigation was launched involving the FBI, NSA, and military intelligence. 
*   **Connecting the Dots:** Analysts initially thought the intrusions were isolated events. However, by tracking strange traffic from the Air Force’s network to a **command-and-control (C2) server in the UK**, investigators recovered FTP transfer logs that revealed the connected nature of the activity occurring over several years.
*   **Strategic Targeting:** Investigators noticed that every university targeted or used as a "hop point" was listed in the "Militarily Critical Technologies List" (MCTL). This victim-centric analysis proved the strategic nature of the espionage.

### **Attribution to Russia**
The investigation pointed strongly toward **Russia** based on several key artifacts:
*   **Code Clues:** Analysts found the Russian word for "child process" within the code running on some compromised servers.
*   **Activity Patterns:** During the 1998 Christmas holiday, the activity continued; however, the attackers went suspiciously quiet for three days during the following week—which aligned perfectly with the **Orthodox Christmas** holiday.

### **2016 Reanalysis and Modern Connections**
In 2016, researchers from Kaspersky Labs and King’s College London reanalyzed a relay server named **"HR Test"** that had been used by the Moonlight Maze actors and monitored by the FBI.
*   **A Gold Mine of Data:** The server contained artifacts spanning decades. Analysis showed the attackers' evolution from an "amateur skill level" (characterized by typos and errors) to a more sophisticated group that developed its own toolkit based on **LOKI2**, an open-source backdoor.
*   **Connection to Penquin Turla:** This reanalysis linked Moonlight Maze to a modern toolkit called **"Penquin Turla"**. Evidence for this link included C2 protocol overlaps, shared code compiled for specific Linux Kernel versions from 1999, and strategic goals that aligned with the original Moonlight Maze operation.

### **Key Lessons Learned**
The sources highlight several critical CTI lessons from this case:
*   **Intrusions are not isolated:** Suspicious activity must be analyzed as part of a larger cluster that may span years.
*   **Value of "Old" Data:** Artifacts and indicators can prove useful for identifying and linking threat actors even decades after the original event.
*   **Adversary Evolution:** Just as defenders learn, adversaries also learn from these incidents to improve their operational security (OPSEC) and C2 infrastructure.

---

# Operation Aurora

Operation Aurora is a landmark case study in Cyber Threat Intelligence (CTI), recognized for changing how the industry views state-sponsored threats against the private sector.

### **Overview and Discovery**
Publicly disclosed in **January 2010**, the operation came to light after Google released a report stating they had been targeted. While Google was the most prominent victim, their internal investigation revealed that the campaign was much broader, targeting the **Gmail accounts of Chinese human rights activists**.

The scope of the attack was massive, involving multiple intertwined campaigns against over 30 major U.S. companies, including **Northrop Grumman, Morgan Stanley, Dow Chemical**, and others. By 2011, researchers realized that several other major intrusion sets—such as the Elderwood Project, Operation Shady RAT, and the RSA SecurID breach—were all linked to this same activity.

### **Tools and Tradecraft**
The attackers demonstrated a high level of sophistication through their technical methods:
- **Zero-Day Exploits:** The campaign utilized an unprecedented number of zero-day exploits—initially eight were identified—targeting vulnerabilities in applications like Internet Explorer and Adobe.
- **Malware Families:** The exploits were used to deliver various malware, most notably **PoisonIvy** and **Hydraq**.
- **Tactics:** The actors combined **spear-phishing emails** with **"watering hole" style exploitation** to gain access to target networks.
- **The Name "Aurora":** The name was not given by the attackers; rather, it was a common file folder path found within the malware used in the campaign.

### **Attribution to China**
The sources state that analysis across these campaigns placed attribution on **China’s PLA Unit 61398**. Key evidence included:
- **Infrastructure:** Forensics revealed a string of command-and-control (C2) servers leading back to IP addresses owned by the Chinese government.
- **Operational Failures:** The attackers made frequent operational security (OPSEC) mistakes, such as using the same "call signs" (nicknames) in their attacks as they used on social media and gaming platforms.
- **Leaked Communications:** Intercepted and leaked communications reportedly showed Chinese government officials directing the campaign.

### **Key Lessons Learned**
Operation Aurora was a "wake-up call" for the cybersecurity industry for several reasons:
- **Private Sector as a Target:** It proved that state-sponsored digital espionage was not just a threat to military and government networks, but also to civilian and private companies.
- **Value of Victim Data:** It highlighted that the most valuable data for understanding an intrusion is often found **within the victim's own network logs**, not in classified government documents.
- **Cross-Sector Analysis:** The case showed that sharing threat information across different industries (cross-sector) is essential, as attackers often target multiple verticals simultaneously.

---

# **How an analyst should think** and the mental processes involved in turning information into intelligence.

1. Kent’s Analytic Doctrine 
Sherman Kent, a famous intelligence figure, created a set of rules for analysts to ensure their work is professional and accurate. The key points are:
- **Focus on what leaders need:** Intelligence must be useful for decision-makers.
- **Avoid personal agendas:** Don't let your own opinions change the facts.
- **Be rigorous and admit mistakes:** Always check your work carefully and be honest if you get something wrong.

2. Analysis vs. Synthesis
- **Analysis:** This is the act of **breaking something down** into small pieces to understand how it works (e.g., looking at the specific steps of a single hack).
- **Synthesis:** This is **putting the pieces together** to see the "big picture," such as identifying a long-term campaign or a specific group's profile.

3. Analytical Judgment
Analysts almost never have all the facts. **Analytical judgment** is the process of using a **repeatable method** to make a smart guess (hypothesis) even when information is missing. A good analyst "shows their work" so others can see how they reached their conclusion.

4. Two Types of Analysis
- **Data-Driven:** Used for simple problems where you have plenty of accurate data (e.g., counting how many times an IP address appeared).
- **Conceptually-Driven:** Used for complex problems with many unknowns. It relies on **mental models** and is very common in cyber intelligence because information changes so fast.

5. Perception and The Brain
- **Active Perception:** Our brains are not cameras; we often **see what we expect to see**. The "Paris in the the spring" exercise shows that our brains might ignore a mistake (like a double word) because we expect the sentence to be correct.
- **Working Memory:** This part of the brain processes new information and decides if it should be saved as a long-term memory.
- **Pattern Recognition:**
    - **Template matching:** Looking for an exact match.
    - **Prototype matching:** Looking for something that is "close enough".
    - **Top-down matching:** Using context to **"fill in the gaps"** when information is missing, which can sometimes lead to mistakes.

6. Biases and Mental Shortcuts
- **Everyone has biases:** It is impossible to be 100% objective. Our brains use shortcuts to make quick decisions, but these shortcuts can lead to errors.
- **Example:** In the 2020 US Election, people saw ransomware and immediately assumed it was "election hacking" because that fit their fears (confirmation bias), even though there wasn't enough evidence yet.
- **Solution:** Using diverse teams with different backgrounds helps reduce the impact of these biases.

7. System 1 vs. System 2 Thinking
- **System 1 (Fast):** This is "intuitive" thinking or autopilot. It is fast and often accurate for daily life (like checking the sky for rain).
- **System 2 (Slow):** This is **"analytic" thinking**. It is slow, methodical, and requires effort. Intelligence analysts must train themselves to use System 2 for complex problems to avoid jumping to the wrong conclusions.

8. Mental Models
Mental models are the **"mindsets" or frames of reference** we develop over time based on our experiences.
- **How they help:** They allow analysts to quickly process vast amounts of information and get into productive habits.
- **The Risk:** A mental model can cause a responder to focus only on what they _perceive_ is important, potentially missing small but critical details.
- **The Solution:** Analysts must constantly review and update these models as they gain new experience.

9. Structured Models: "Data into Buckets" 
Structured models help analysts organize information so it can be analyzed more easily.
- **Cyber Kill Chain:** A military concept used to understand the specific steps an adversary must take to be successful in an attack.
- **Diamond Model:** A model used to categorize information into four main components: **Adversary, Infrastructure, Capability, and Victim**.

10. Structured Analytic Techniques (SATs) 
SATs are specific methods used to evaluate information while **reducing the impact of bias**.
- **Goal:** To make analytic judgments transparent, testable, and easy to defend.
- **Two Key Tasks:**
    - **Decomposition:** Breaking a big problem into small parts so they can be looked at separately.
    - **Visualization:** Creating a visual map of a problem to see how different parts relate to each other.

11. The Intelligence Life Cycle
This is the standard five-stage process used by the intelligence community (including the NSA and CIA):
- **Planning and Direction:** Identifying what information is missing and creating a plan to find it.
- **Collection:** Executing the plan to gather raw data (e.g., setting up network logs).
- **Processing and Exploitation:** Cleaning the raw data and turning it into a usable format.
- **Analysis and Production:** Evaluating the information to answer the original questions.
- **Dissemination:** Delivering the final "intelligence product" to the customer who needs it

12. Field of View Bias
Every organization has a limited "field of view" based on where they collect data.
- **Example:** A security company with mostly U.S. customers will see different threats than a company with customers in the Middle East. This is not a "bad" thing, but analysts must be aware of it when performing strategic analysis.

13. Data vs. Information vs. Intelligence
It is critical to know the difference between these three levels:
- **Data:** Raw facts (e.g., an IP address).
- **Information:** Data with context (e.g., "This IP address is a command-and-control server").
- **Intelligence:** **Analyzed information** that meets a specific requirement (e.g., "We assess that this adversary is not targeting us directly; this is an incidental infection").

14. Defining Cyber Threat Intelligence
The course provides a specific definition of CTI:
**"Analyzed information about the hostile intent, opportunity, and capability of an adversary that satisfies a requirement"**.
The key takeaway here is that the focus must always be on the **threat** and the **customer's needs**, not just on what "looks cool".

---

**Essential CTI Terminology**
Understanding these specific terms is the foundation of professional CTI work:

- **Adversary/Threat:** The human behind the keyboard. A threat is not just malware; it is someone with the **intent, opportunity, and capability** to do harm.
- **Intelligence Requirement:** A straightforward question that identifies a "knowledge gap" an organization needs to fill.
- **Intrusion:** Any successful or failed attempt to compromise a system.
- **Victim vs. Target:** A **target** is the ultimate goal of the attacker, while a **victim** is anyone compromised along the way (for example, hacking a service provider to get to their customers).
- **Persona:** A fake name or identity used by an adversary.
- **TLP (Traffic Light Protocol):** A standard for sharing sensitive information using colors: **Red** (no sharing), **Amber** (limited sharing), **Green** (community sharing), and **White** (public)

**Modeling the Adversary**
Analysts use different ways to "group" attacks together:

- **Activity Group:** A cluster of intrusions linked by similarities in their features (infrastructure, capability, victim, etc.). This is a formal model used for tracking "how" attacks are done.
- **Threat Actor:** A loosely defined term for the "who" behind an attack (e.g., "Russia" or a specific group name like APT1). Analysts often use Activity Groups because identifying the exact person/group is very difficult.
- **Campaign:** A series of intrusions with a specific **mission objective**, such as targeting financial networks for a set period.

**TTPs and Tradecraft**
- **TTPs (Tactics, Techniques, and Procedures):**
    - **Tactics:** High-level goals (e.g., "get passwords").
    - **Techniques:** How the goal is achieved (e.g., "spear-phishing").
    - **Procedures:** The exact, granular steps taken (e.g., the specific commands typed).
- **Tradecraft:** The overall "M.O." (Modus Operandi) or "style" of the adversary. It is broader than TTPs and includes the specific tools and infrastructure they leverage.

**Indicators and Their Life Cycle**
- **Indicator Formula:** **Data + Context = Indicator**. For example, an IP address (data) by itself is not an indicator. It only becomes one when you add context, such as "this is a command-and-control server".
- **Indicator Life Cycle:** Indicators move through states: **Revealed** (discovered), **Vetted** (checked for accuracy), **Mature** (ready to use), and **Utilized** (deployed in defense).
- **The Snowball Analogy:** Indicators are like a snowball rolling downhill—the more you detect and utilize, the more new indicators you will find through "pivoting" and analysis.
- **Key Indicators:** These are the "best" indicators that remain consistent across different attacks and uniquely identify a specific campaign.
- **Indicator Fatigue:** Having too many indicators (like 10,000 alerts a day) can overwhelm staff. Analysts should focus on high-quality indicators specific to their own intrusions rather than just "collecting them all".

---

## Case Study: PROMETHIUM and NEODYMIUM

**Background and Shared Links**
- **The Groups:** PROMETHIUM (operating since 2012) and NEODYMIUM (operating since 2016) are two distinct entities.
- **The Target:** Unlike many state-sponsored groups that target organizations to steal intellectual property, these groups targeted **individuals in Europe (specifically Turkey)** to access personal information.
- **The Smoking Gun:** Despite their differences, both groups used the **same zero-day exploit (CVE-2016-4117)** in Adobe Flash before it was publicly known.
- **Analytic Conclusion:** Analysts believe these are separate teams—likely because their day-to-day methods (tradecraft) differ—but they probably report to the **same government agency** that provides them with expensive tools like zero-day exploits.

**Observable Characteristics**
Each group had a very specific "style" of attacking:
- **PROMETHIUM:**
    - **Malware:** Used a tool called **Truvasys** that often disguised itself as common computer utilities (like WinRAR).
    - **Delivery:** Sent links through **instant messenger apps** that led victims to download malicious documents.
- **NEODYMIUM:**
    - **Malware:** Used **Wingbird** malware, which is very similar to the "FinFisher" surveillance software often sold to governments.
    - **Delivery:** Used **highly tailored spear-phishing emails** with malicious attachments (RTF documents).

**NEODYMIUM Intrusion Flow**
The source provides a visual map of a NEODYMIUM attack:
1. **Spear-phishing email** is sent to a specific victim.
2. The victim opens a **malicious RTF attachment**.
3. The attachment triggers the **Flash zero-day exploit** (CVE-2016-4117).
4. The exploit runs **shellcode** that connects to a remote server.
5. This server downloads additional code to eventually install the final **malicious payload** used to steal data.

**4. Analyzing with the Diamond Model**
Using the **Diamond Model**, Microsoft was able to "cluster" these intrusions into two groups.
- **Clustering:** They focused on two points of the diamond: **Victims** (both targeted individuals in Turkey) and **TTPs/Capability** (both used the same exploit but different malware).
- **Value for Defenders:** This analysis shows that "one size does not fit all" in defense. If an organization is told to protect against PROMETHIUM, they would focus on blocking instant messenger links. If they are protecting against NEODYMIUM, they would focus on better email security.

---

**Generation vs. Consumption**
It is important to distinguish between these two roles:

- **Generation:** This is the act of **creating** intelligence by analyzing intrusions and finding strategic value.
- **Consumption:** This is **using** that intelligence to defend a specific organization. Defenders take analyzed information and apply it to their firewalls, detection rules, and security plans.
- **The Goal:** Analysts should focus on producing intelligence in formats that security personnel can quickly and easily use.

**The Sliding Scale of Cyber Security**
The course uses a "sliding scale" to show the different parts of a security program:
- **Architecture:** Building and maintaining a secure network.
- **Passive Defense:** Systems like firewalls that work without human interaction.
- **Active Defense:** Humans monitoring, responding, and learning from adversaries (like Threat Hunting or Incident Response).
- **Intelligence:** Collecting and analyzing data to produce knowledge.
- **Offense:** "Hacking back" or legal countermeasures. The sources strongly advise **against** this for most organizations because it is expensive, often illegal, and provides a poor return on investment (ROI).

**Driving Value to the Left**
The most important goal for a CTI team is to **"drive the lessons to the left"**. This means taking what you learn from an attack (Intelligence) and using it to fix the Architecture or improve Passive Defenses. It is much cheaper and more effective to fix a network's design than to constantly fight off attackers in "Active Defense".


**The Four Types of Threat Detection**
Analysts use four main ways to find "bad guys" on a network:
- **Configuration Analysis (Known/Environmental):** Finding things that shouldn't be there based on your own system rules.
- **Modeling (Unknown/Environmental):** Finding "strange" behavior that doesn't match the normal patterns of your environment.
- **Indicators (Known/Threat):** Searching for specific "fingerprints" left by attackers, like an IP address or file hash.
- **Threat Behaviors (Unknown/Threat):** Looking for the **style** of an attack (like "lateral movement") rather than a specific file.

**Behavioral Analytics vs. Indicators**
- **Indicators:** These are simple, like a single IP address. However, they are easy for an attacker to change.
- **Behavioral Analytics:** This involves looking for a **sequence of actions**. For example, "An external VPN login followed by a file being dropped in a temp folder followed by a command to move through the network". This is much harder for an attacker to hide from.

**The Pyramid of Pain**
This famous model shows how much "pain" you cause an attacker when you detect their different indicators:
- **Hash Values:** Trivial. Attackers can change these in seconds.
- **IP Addresses:** Easy. Attackers can easily switch servers.
- **Domain Names:** Simple. Buying a new domain is cheap.
- **Network/Host Artifacts:** Annoying. Now the attacker has to change how their malware talks to the server.
- **Tools:** Challenging. The attacker has to learn or build a brand-new tool.
- **TTPs (Tactics, Techniques, and Procedures):** **Tough!** This forces the attacker to completely change their "how-to" behavior and training. This is the ultimate goal of CTI.

**Preparing to Generate Intelligence**
While many organizations start by **consuming** (using) intelligence, there comes a point where they need to **generate** (create) their own.
- **Making the Switch:** To justify a dedicated CTI team, an organization must ensure it has clear requirements that can't be met by just buying external feeds, and it must have the resources (people, data, and systems) to do the work.
- **Stakeholder Buy-in:** Success requires support from leaders and a culture where different teams (like the SOC and incident responders) collaborate.

**Priority Intelligence Requirements (PIRs)**
Not all questions are equal. **PIRs** are the most critical intelligence requirements that are essential to the mission's success.
- **Dynamic Nature:** PIRs are not permanent; they change over time as new threats emerge or business goals shift.
- **Senior-Level Focus:** They require the highest level of buy-in from decision-makers, as they often drive significant resource prioritization.

**Different Audiences for Intelligence**
Intelligence must be tailored to the person receiving it:
- **Strategic:** For executives. It focuses on long-term business risks and high-level trends (e.g., "Which business units are most at risk?").
- **Operational:** For middle management and security leads. It focuses on specific threats to the industry (e.g., "Which groups are targeting our competitors?").
- **Tactical:** For technical staff (SOC analysts). It focuses on immediate, actionable data like indicators and specific adversary behaviors.

**Structuring a CTI Team**
A CTI team should ideally be an independent focal point with ties to all parts of the organization, rather than being "hidden" inside another team like the SOC.
- **Diversity:** Teams should have people with different backgrounds (malware analysis, international relations, policy, etc.) to reduce bias.
- **Core Functions:** A CTI team supports **Prevention** (enriching alerts), **Response** (helping during an active hack), and **Strategy** (informing business decisions).

**Case Study: Ukraine Electric Grid Attack**
In December 2016, the Ukrainian power grid was attacked for the second time.
- **Unique Malware:** Unlike the 2015 attack, this one used the first-ever malware specifically designed to target electric grid infrastructure.
- **Impact:** Attackers targeted a transmission-level substation, causing three times more power loss than previous incidents, demonstrating a highly scalable method for attacking power grids.

**Case Study: Carbanak "The Great Bank Robbery"**
This is a landmark case of highly organized cyber-crime:
- **Origins:** Criminals took a common toolkit called **Carberp** and heavily modified it into a sophisticated intrusion set named **Carbanak**.
- **The Heist:** They targeted over 100 banks worldwide, infiltrating internal networks to record employee screens and learn how money was moved.
- **Modus Operandi:** Once inside, they stole up to **$1 billion** by remotely commanding ATMs to dispense cash, transferring money to fake accounts, and inflating account balances.
- **Evolution:** By late 2016, the group evolved to target retail, hotels, and restaurants, even using **Google Apps/Sheets** as a sneaky way to control their malware.

**Key Lessons from Carbanak**
- **APT is a Style:** The term "Advanced Persistent Threat" (APT) is a style of behavior, not just a label for nation-states. Sophisticated criminals can be just as persistent and capable.
- **Malware is Just a Tool:** The threat is the **human** behind the attack. They can take "commodity" (common) malware and use it in highly advanced ways.

**Generating Requirements and the CMF**
- **Starting with Needs:** To create good requirements, analysts must seek input from their "customers" (decision-makers) and use their organization’s threat model and "pain points" as a starting point.
- **Collection Management Framework (CMF):** A CMF is a strategic plan for how you collect data. It helps analysts understand which data sources are available, what questions those sources can answer, and the technical limitations of the data.
- **Sample Frameworks:**
    - **External CMF:** Includes sources like VirusTotal or malware domain lists to identify external threats.
    - **Internal CMF:** Includes data from endpoint protection, host logs, and firewalls. It also tracks how long data is stored (e.g., 30 or 60 days) and which part of the Cyber Kill Chain it covers.

**Systems Analysis and Threat Modeling**
- **Systems Analysis:** This is a method for analyzing an organization as an "orderly grouping of interdependent components" working toward a goal. It examines four key areas: structure, information technology, tasks, and the individuals or roles involved.
- **The Threat Model:** A threat model helps align a team around a common understanding of threats and highlights gaps in security where more resources are needed.
- **The Human Factor:** Analysts must remember that while they can use patterns to predict behavior, adversaries are human and can choose to do things that do not align with past behavior.

**Target-Centric Intelligence Analysis**
- **A Nonlinear Approach:** This method builds a flexible, conceptual model of a "target" (the organization's assets) as a foundation for analysis.
- **Building the Model:**
    - **Step 1:** Identify critical systems and information, such as financial data, intellectual property, and system availability.
    - **Step 2:** Add potential adversaries (Activity Groups) to the model based on who might want those specific assets.
    - **Step 3:** Pivot off the data to find more granular details, like specific software versions or the tools and triggers an adversary might use.
- **Granularity:** Analysts should go as deep as needed—from the overall system down to specific software versions—to properly inform vulnerability management and patching.

**The VERIS Framework**
- **Standardized Vocabulary:** The **Vocabulary for Event Recording and Incident Sharing (VERIS)** is a framework used to capture metrics on security incidents in a consistent way. It is the foundation for major reports like the Verizon Data Breach Investigations Report (DBIR).
- **The Four A’s:** VERIS records four main categories of data for every incident:
    - **Action:** What the attacker did (e.g., hacking, social engineering, malware).
    - **Asset:** Which assets were affected.
    - **Actor:** Who was behind the incident (Internal, External, or Partner).
    - **Attribute:** How the asset was affected, usually focusing on **Confidentiality, Integrity, and Availability**.
- **Tracking Trends:** By using VERIS, organizations can track their own internal trends and compare them against external data from the rest of their industry.
