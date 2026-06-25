# Section4: Sock Puppets, OPSEC, Dark Web, and Cryptocurrency

1. Sock Puppets and OPSEC
2. The Dark and Hidden Web
3. Cybercrime, Markets, and Forums
4. Cryptocurrency and Financial OSINT

---
## Topic 1: Sock Puppets and OPSEC


%% 
### **Understanding Sock Puppetry**

A **sock puppet** is defined as a fictitious identity used on platforms such as forums, marketplaces, or social networks. Using an assumed identity is a fundamental part of operational security because it prevents investigators from sharing their real identity, their organization’s name, or their actual investigative purpose with targets like criminals or terrorists. While there are effective ways to operate these accounts, many sock puppets are eventually identified and removed from websites.

### **Authorization and Legal Warnings**

Before creating any fictitious identity or interacting with targets, investigators must obtain **written approval** from their manager and legal department. It is critical to have a comprehensive understanding of what is permitted in your operations, as these activities may violate a platform’s terms of service or run afoul of laws concerning identity theft, fraud, or misrepresentation.

### **Online Undercover Operations**

Understanding how online undercover operations work is a key tool for investigators. Even if you are currently restricted or forbidden from operating sock puppets by your organization, you may still need to coordinate with others who do or be tasked with conducting such operations in the future.

### **Operational Considerations**

Before beginning operations, several strategic questions should be addressed:

- **Longevity:** How long should the sock puppet be kept active?
- **Validation:** Multiple puppets can validate each other, but the compromise of one can potentially expose the entire network.
- **Accessibility:** Should other team members have access to the accounts?
- **Activity:** How often should you conduct actions with the account?
- **Contingency:** What is the plan if the account is "burned" (exposed)?
- **Trust:** How much time is required to position the puppet in a place of trust to access valuable information?

### **Human Intelligence (HUMINT) and Engagement**

**HUMINT** is intelligence gathered through interpersonal contact. In the context of OSINT, this involves direct interaction with individuals on forums and marketplaces via sock puppet accounts. A key element is convincing a human source that you have a "legitimate" reason for wanting information and that sharing it will not harm them.

#### **Engagement Considerations**

Before interacting with targets, you must determine your overall goals, understand what motivates the target to cooperate, identify your "angle" to get specific information, and assess the expected duration of the engagement.

#### **Engagement Tips**

Successful interaction requires specific tradecraft:

- **Jargon:** Learn and understand the slang and jargon of the target group to avoid sticking out as an imposter.
- **Consistency:** Do not disappear immediately after getting information, as this is highly suspicious; maintain a long-term presence to build trust.
- **Validation:** Be wary of information provided to you, as it may be intentionally or unintentionally false, and always try to corroborate it.
- **Empathy:** Attempt to think like the actors you are engaging with to better blend into their environment.

### **Established vs. New Accounts**

Maintaining a long-term presence is a key strategy for gaining trust. Older, established sock puppets with a history of messages and a "reaction score" are seen as far more credible by other users than brand-new accounts.

### **The Future: Virtual Reality Sock Puppets**

As social platforms transition toward virtual reality (VR) worlds, sock puppet operators will need to be prepared for **real-time interactions**. This format will challenge operators who are used to having time to consider their responses. In these spaces, puppets must have well-established "bona fides" and operators must be as prepared as actual undercover agents in the physical world.

### **The Death of Sock Puppets**

Analysts must accept that their fictitious identities will eventually be "killed" or shut down. Common reasons for a sock puppet being burned include:

- **Poor Persona:** Pretending to be something the account obviously is not.
- **Disposable Emails:** Using "10-minute" email addresses that cannot be used for future account verification.
- **Obvious Questions:** Asking questions that are clearly from an "investigator" perspective rather than those a genuine group member would ask.
- **Inactivity:** Long periods of unused accounts can lead to them being flagged or deactivated.
- **Security Failures:** Allowing credentials to be stolen or failing to maintain passwords.

### **Summary of Sock Puppetry**

Creating and operating sock puppets is a complex process that requires constant modification based on the investigation’s needs. Analysts should always have backup puppets ready, as accounts can be lost quickly. Ultimately, failure to practice strict **operational security (OPSEC)** will result in the loss of the sock puppet or the compromise of the mission.

%%

OPSEC Standard Operating Procedure (SOP)
What you can do is create an OPSEC SOP template based on the three known Security Operations Threat Levels:
- Overt Work
- Covert Work
- Clandestine Work

%% 
### **What Is OPSEC?**

**OPSEC** (Operations Security) is an analytical process originally derived from the U.S. military. In the context of OSINT, it is used to deny an adversary information that could compromise the secrecy or security of an investigation. All OPSEC measures should be **documented in detail** so that if a compromise occurs, you can identify exactly when and where it happened.

### **Denying Valuable Information**

The goal of OPSEC is to prevent an adversary from discovering your real identity or location. You must actively work to hide the following:

- **Personal Data:** Full name, date of birth, home address, and national identifiers (like an SSN).
- **Contact Info:** Personal or work telephone numbers and email accounts.
- **Digital Footprint:** Social media posts, family/friend connections, and your **digital device fingerprint**.

### **The "5 Times NO" Rules**

The sources highlight five critical "no-go" areas for practicing good OPSEC:

1. **NO Linking:** Keep work and private life 100% separated.
2. **NO Private Connections:** Never use your home internet for research.
3. **NO Office Connections:** Do not use standard office Wi-Fi or wired connections for OSINT gathering.
4. **NO Office Terminals:** Standard work computers have distinct, recognizable fingerprints that present a huge risk.
5. **NO Work Mobiles:** Never use a provided work phone to verify or manage sock puppet accounts.

---

### **Overt vs. Clandestine OPSEC**

Depending on the mission, the level of protection required varies:

- **OPSEC for Overt Work:** This applies when it is acceptable for an adversary to detect your activity. It requires a dedicated OS or VM, a VPN, and a generic device fingerprint to blend in.
- **OPSEC for Clandestine Work:** This is used when detection is **not** acceptable. It requires hardened hardware, multiple VPNs, **4G or 5G MiFi connections** (which offer non-static IP addresses), multiple custom-tailored device fingerprints, and the disabling of all system logs and crash reports.

### **Risks and Uncontrollable Factors**

OPSEC risks can come from many sources, including curious individuals, law enforcement, Red Teams, or nation-state hackers. Even with perfect discipline, some factors are uncontrollable, such as a partner firm being breached or colleagues accidentally leaking information about you.

---

### **Advanced Tracking and Protection**

#### **1. Correlation Fingerprinting**

Adversaries often use **correlation** to identify investigators. They look for habits and patterns, such as a sock puppet posting at specific intervals, using certain words, or appearing online only during a specific time zone.

#### **2. Browser Incognito Mode**

A common misunderstanding is that **Incognito Mode** makes you invisible. While it doesn't save history locally, it **does NOT** hide your activity from your employer, your ISP, or the websites you visit.

#### **3. Useful Browser Extensions**

To enhance OPSEC, analysts use specific add-ons:

- **HTTPS Everywhere:** Enforces encryption on connections.
- **Privacy Badger:** Blocks third-party trackers.
- **uBlock Origin:** Blocks ads and prevents **WebRTC** from leaking your real IP address.
- **User-Agent Switcher:** Spoofs your browser and OS digital fingerprint (e.g., making a Mac look like a Windows machine).
- **Canvas Defender and Location Guard:** Further hide hardware fingerprints and GPS data.

#### **4. Analyzing Browser Extensions (ExtAnalysis)**

Extensions themselves can be malicious, serving adware or harvesting your data. Analysts use **ExtAnalysis**, a Python-based tool, to examine these extensions.

- **Permissions:** It rates permissions (like `<ALL_URLS>`) as high or critical risk.
- **URLs & Domains:** It shows every server the extension communicates with, allowing you to spot suspicious traffic to unusual countries.

---

### **Mobile Device OPSEC**

Modern investigations often rely on mobile devices, especially when data is only available through mobile apps.

- **Device Fingerprinting:** Every visit to a website leaves a digital fingerprint based on data your device sends to the server, which is subject to analysis.
- **Selection Criteria:** Choosing a device depends on the make, model, OS, and which sensors are activated.
- **NSA Guidance:** In 2020, the NSA released a tip sheet for mobile OPSEC, recommending the use of strong passwords/PINs, minimizing installed applications, and being cautious with attachments and links.

%%


%% 
### **Monitoring Network Traffic for OPSEC**

It is vital for an investigator to know exactly what data their system is transmitting. Analyzing your own network traffic serves several purposes:

- **Security Check:** Ensuring your system is not "phoning home" to inform a company or government about the sites you are visiting.
- **Understanding Applications:** Seeing how websites and apps work under the hood.
- **Discovering APIs:** Identifying hidden methods (APIs) to interface with sites for more efficient data gathering.
- **Identifying Relationships:** Spotting links between a target site and its hosting or advertising providers.

### **What to Look for in Traffic**

Analysts perform traffic analysis by comparing active traffic against a **baseline** (the normal level of traffic before research begins) to spot differences.

- **Inside the Packets:** You can find credentials, advertising IDs, DNS names being resolved, exact search strings, and large blobs of data in XML or JSON formats.
- **Metadata (Non-Packet Data):** This includes packet headers, API endpoints, and the timing of IP address connections.

### **Levels of Traffic Monitoring**

There are three primary levels where you can monitor and gather data:

1. **Application Level:** Using web browser developer tools or specialized proxies like Burp Suite.
2. **Operating System Level:** Using tools like `tcpdump` or **Wireshark** to capture all traffic moving through the OS.
3. **Network Level:** Monitoring traffic after it leaves your host machine.

---

### **Application-Level Monitoring: Browser Developer Tools**

Since most OSINT is conducted in a browser, this is the best place to start.

- **Access:** Press **F12**, `Ctrl-Shift-i`, or `Opt-Cmd-i` (macOS) in Firefox or Chrome.
- **The Network Tab:** This tab shows every request your browser makes (e.g., for images, HTML, or JavaScript) to render a page. It allows you to view HTTP/HTTPS protocols, API traffic, and hostnames.

---

### **OS-Level Monitoring: Wireshark**

**Wireshark** is a free, cross-platform tool used for deep packet analysis with an intuitive graphical interface.

- **Statistics Features:** Wireshark can summarize your capture to help you understand the big picture.
    - **Resolved Addresses:** Shows all IP addresses and their associated domain names found in the capture.
    - **Protocol Hierarchy:** Displays a breakdown of every protocol observed (e.g., DNS, HTTP, SSL/TLS), helping you see what types of activity are most frequent.

#### **Advanced Wireshark Tradecraft**

- **Applying Filters:** You can right-click any protocol in the statistics view to "Apply as Filter," which limits the main display to only those specific packets.
- **Display Filters:** Common logic can be used to narrow results, such as **Negation** (`!dns`), **AND** (`dns && http`), and **OR** (`http || ssl`).
- **Follow TCP Stream:** This specialized filter reconstructs the prolonged "conversation" between two hosts. It allows an analyst to see exactly what one system sent and what the other responded with in a readable format.

### **Summary of Network OPSEC**

By using these tools, analysts can move beyond simple web browsing to "drill down" into the actual content being transmitted. This ensures that your research activities are not being leaked and allows you to harvest even more data from the target’s infrastructure. This concludes the first part of Section 4, leading into the next major topic: **The Dark and Hidden Web**.

%%


%% 

Continuing with **Section 4**, this part transitions from OPSEC and system monitoring into **The Dark and Hidden Web**, covering definitions, the various networks involved, and the challenges of accessing this data.

### **1. Introduction to the Dark and Hidden Web**

The internet is traditionally conceptualized in three broad divisions:

- **Surface Web:** The portion of the internet that is public and indexed by standard search engines.
- **Deep Web:** Portions of the internet with restricted access, such as password-protected databases.
- **Dark Web:** The "hidden" remainder that requires specialized tools to access.

This division is often illustrated by the "iceberg model," a concept popularized by Michael Bergman’s 2001 white paper, which noted that while surface searching catches a great deal, a wealth of information exists deeper and is missed by standard tools. Technically, the dark web is defined as any part of the web that cannot be accessed with a standard, unmodified web browser.

### **2. Defining the Dark Web and Darknets**

The defining characteristic of a dark web system is the **requirement for special software** for access. These are often referred to as **overlay networks**, which are networks built upon existing internet infrastructure (like Tor being built on public IP addresses and web server technologies).

- **Dark Web:** According to the Oxford English Dictionary, this is the part of the web where users and operators can remain anonymous or untraceable through special software. While anonymity is a primary purpose of these networks, it is by no means guaranteed for the user.
- **Darknet (General Definition):** This term is often used interchangeably with "dark web" and refers to specialized networks like Tor that require specific software, configurations, or authorizations to access.
- **Darknet (Underground Definition):** In the cybercrime underground, the term has a more specific meaning, often serving as shorthand for **criminal marketplaces**, particularly those on the Tor network that sell illicit drugs.

### **3. Notable Dark Web Networks**

While Tor is the most popular and has the most resources (such as forums and markets), there are several other dark web networks that an OSINT investigator may encounter:

- **Tor (The Onion Router):** The most common system, utilizing the `.onion` top-level domain.
- **I2P and Freenet:** Alternative networks used by smaller numbers of people.
- **Blockchain DNS:** Systems like **Namecoin** and **Emercoin** that use decentralized ledgers for domain names.
- **Rogue TLDs:** Alternative top-level domain networks such as **NewNations** and **OpenNIC**.

### **4. Accessing the Darknet**

Gaining entry to these networks is typically not difficult once the correct software is installed. However, the real challenge for investigators is **navigating and finding content**.

Unlike the surface web, these environments are not well-indexed or searchable. For example, performing a standard Google "site:" operator search for `.onion` addresses (the unofficial TLD for the Tor network) will return no results because Tor is not directly accessible to surface web crawlers. Investigators usually need a starting point—such as a known address—before they can begin gathering intelligence.

%%










