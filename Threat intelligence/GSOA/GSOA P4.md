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

## Topic 2: The Dark and Hidden Web

%% 
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



OpenNIC operates its own DNS servers, which you can configure your system to use to resolve addresses. The  DNS service covers normal internet domains as well as domains within OpenNIC that are not administered by ICANN.
For more information about OpenNIC, visit https://sec587.info/78

cryptocurrencies have had their blockchains used to create domains resistant to take-downs


%% 
### **1. Challenges of Darknet Access**

While gaining entry to dark networks is usually not technically difficult once the correct software is installed, the primary challenge for investigators is **navigation and discovery**. These environments are not well-indexed; for example, a standard Google search for `.onion` addresses returns no results because standard surface crawlers cannot reach them. Investigators often need to rely on known entry points or specialized search tools to begin gathering intelligence.

### **2. OpenNIC: The User-Controlled Network**

**OpenNIC** is a "user-controlled" alternative top-level domain (TLD) network.

- **Alternative DNS:** It operates its own DNS servers which can resolve standard ICANN domains as well as OpenNIC-specific domains.
- **TLD Examples:** It supports numerous TLDs, including `.bbs` (its first, created in 2000), `.chan`, `.dyn`, `.free`, `.libre`, `.geek`, `.pirate`, and many others.
- **Usage:** While many people use OpenNIC DNS servers for privacy, very few users actually visit specific OpenNIC domains.

### **3. Understanding Blockchain DNS**

Cryptocurrencies like **Emercoin**, **Namecoin**, and **Ethereum** have used their decentralized blockchains to create domain names that are **resistant to take-downs**.

- **Scope of Protection:** This system only protects the **domain name** itself; the actual web server and IP address hosting the content are not afforded any special protection by the blockchain DNS.
- **Major Networks and TLDs:**
    - **Namecoin:** Supports the **`.bit`** TLD (released in 2018).
    - **Emercoin (EmerDNS):** Supports **`.coin`**, **`.bazar`**, **`.emc`**, and **`.lib`** (started in 2014).
    - **Ethereum (ENS):** Supports **`.eth`**, **`.kred`**, **`.luxe`**, **`.art`**, and **`.ceo`** (launched in 2017).
- **Accessibility:** Because these are nonstandard domains, they cannot be reached using a normal web browser and the regular DNS system without specialized configurations.

### **4. Malicious Use of Blockchain DNS**

Criminals and malware operators have transitioned to these nonstandard TLDs to hide their infrastructure.

- **Criminal Hosting:** These domains are used to host marketplaces and malicious files that are difficult for authorities to seize.
- **Botnets:** New botnets have been observed using blockchain DNS to hide their **command and control (C2) servers**, making their communications harder to disrupt.
- **Research:** Analysts like Kevin Perlow have demonstrated how investigators can discover these domains and "pivot" from them to find larger malicious networks.

### **5. Accessing Blockchain DNS Services**

To view content on these networks, investigators use specific methods:

- **Browser Plugins:** Several third-party plugins allow browsers to resolve these addresses, such as **PeerName**, **FriGate**, and **Blockchain DNS**.
- **Plugin Risks:** These tools are often created by small teams rather than large corporations. They can be buggy, may interfere with each other if multiple are installed, and can sometimes perform suspicious activities, so they should be examined carefully before use in sensitive investigations.
- **OpenNIC Integration:** You can configure a device to use **OpenNIC DNS servers** to access EmerDNS addresses. However, OpenNIC **stopped** resolving Namecoin (`.bit`) domains in 2019 because they were being used too heavily by malware operators.

%%

Tor hidden services use the ".onion" top-level domain. Currently, each address within the Tor network is identified by a 56-character value derived from that particular Tor service's public encryption key (only 16-character domain names were used prior to the implementation of Tor version 3). The benefit to using a Tor service for those seeking anonymity is that web servers running Tor services do not use the DNS system and thus the actual IP the services are running on remains unknown unless a misconfiguration or other operational security issues leak this information

A long with the forums and marketplaces, there are other services that are popular uses of Tor:
• ProtonMail (email), protonirockerxow.onion
• SecureDrop (file-sharing site), securedrop.org
• ZeroBin (paste site), https://3g2upl4pq6kufc4m.onion
dark.fail, darkfailllnkf4vf.onion
• webhostingsecretrevealed.net, https://sec587.info/5w
• onionlist.org/, https://sec587.info/5x

%% 
### **1. The Tor Network (The Onion Router)**

The **Tor network** is the most widely used dark web system. It is designed to provide **anonymity** by bouncing user traffic through multiple relay nodes (entry, middle, and exit relays), making it difficult for a destination server to identify the original source IP address. Tor hidden services are uniquely identified by the **`.onion`** top-level domain.

### **2. Notable Tor Services**

Beyond criminal forums and markets, several legitimate organizations maintain a presence on Tor to ensure access for users in restrictive environments.
- **Email:** ProtonMail and TorBox.
- **Drop Services:** SecureDrop (used for anonymous whistleblowing).
- **Mirrored Sites:** Major organizations like the **CIA**, **Facebook**, **DuckDuckGo**, and **The New York Times** maintain Tor versions of their websites.

### **3. Finding and Navigating Tor Links**

Because Tor sites are not indexed by standard engines like Google, analysts rely on **link lists** and directories.
- **Link Lists:** Sites like **dark.fail**, **onionlist.org**, and **Onion List** provide directories of active forums and marketplaces.
- **Status Indicators:** These lists often indicate if a site is online, offline, or has been flagged as a **scam**.
- **OPSEC Alert:** The surface web version of _dark.fail_ was compromised in 2021; analysts are advised to use the Tor-based onion version of such directories to ensure they are getting legitimate links.

---

### **4. Tor Search Engines**

While limited compared to surface web engines, several specialized tools exist for searching the Tor network:
- **Ahmia:** An open-source search engine that indexes both **Tor** and **I2P** pages. It is available on both the surface web and Tor.
- **Tor66:** This engine provides a useful "Fresh Onions" list showing newly discovered sites and can filter popular sites by **language** (e.g., English, Chinese, Russian).
- **DarkSearch:** A reliable engine that claims to have indexed millions of Tor pages.
    - **Advanced Queries:** It supports Boolean operators like **AND**, **OR**, and **NOT** to focus results.
    - **API Access:** DarkSearch offers a simple API that allows up to **30 queries per minute**, making it a prime target for Python-based automation. The API output is returned in a structured **JSON** format.

---

### **5. Tor Proxies: Benefits and Grave Risks**

Surface net proxies (e.g., sites ending in `.onion.ws`, `.onion.sh`, or `.onion.cab`) allow users to view Tor content without using the Tor Browser.

- **The OSINT Benefit:** Because these proxies bring Tor content to the surface web, they allow hidden services to be **indexed by standard search engines** like Google. An analyst can use the operator `site:onion.ws [keyword]` to find relevant Tor sites via a standard browser.
- **The OPSEC Risk:** Using these proxies is **highly insecure**.
    - **Traffic Interception:** Proxies have been caught replacing Bitcoin addresses with their own to steal funds from users.
    - **Code Injection:** Proxies like _onion.cab_ have been found injecting **malicious JavaScript** and tracking code to deanonymize users and harvest system fingerprints (e.g., screen resolution, cookies, and plugins).

### **6. Direct Scanning and Ingestion**

For large-scale investigations, analysts can use automated open-source projects on GitHub to scan the dark web directly. Notable tools include:

- **OnionIngestor:** For collecting data from multiple hidden services.
- **TorBot** and **TorCrawl:** For automated crawling of onion links.
- **OnionScan:** For identifying security leaks or relationships between different onion services.

By utilizing these tools and search engines, an analyst can methodically map out infrastructure on the dark web while maintaining strict operational security to avoid deanonymization by malicious proxies or nodes.

%%


EmerDNS is a system for decentralized domain names supporting a full range of DNS records. EmerDNS operates under the "dns" service abbreviation in the Emercoin NVS.
https://peername.org/

|Zone|Intended Purpose|
|---|---|
|.coin|digital currency and commerce websites|
|.emc|websites associated with the Emercoin project|
|.lib|from the words Library and Liberty - that is, knowledge and freedom|
|.bazar|marketplace|

### Browser extensions

Several 3rd-party browser plugins exist which allow you to easily visit EmerDNS domains:

- [Peername.com browser extension](https://peername.com/browser-extension) (firefox, chrome, opera)
- [Blockchain-DNS.info](https://blockchain-dns.info/) browser extension (firefox, chrome)
- [friGate browser extension](https://fri-gate.org/) (firefox, chrome, opera)

A more updated list of browser extensions that support EmerDNS may be found [here](https://emercoin.com/documentation/links-resources).

Ahmia, Tor66, and DarkSearch are reliable ones, although they are not as thorough as a public internet search engine such as Google.
https://ahmia.fi/
https://darksearch.io/
The website can currently be found on Tor at: 
tor66sewebgixwhcqfnp5inzp5x5uohhdy3kvtnyfxc2e5mxiuh34iid.onion (https://sec587.info/bg)



## Topic 3: Cybercrime, Markets, and Forums


%% 
### **1. The Cyber Underground and Authorization**

As the world moved online in the 1990s, so did criminal activity, leading to a rise in fraud, theft, and extremist organizing. Before investigating these spaces, analysts must adhere to two critical principles:

- **Get Authorization:** You must have written approval from your organization and legal department before viewing or joining criminal or extremist sites.
- **Expect Objectionable Content:** These sites often contain highly offensive and disturbing material. Analysts must be mentally prepared for this before conducting research.

### **2. Underground Criminal Marketplaces and Forums**

Underground platforms are used to sell a vast array of illegal goods and services, including:

- **Technical Services:** Hacking services, exploit development, bulletproof hosting, DDoS-for-hire, and malware-as-a-service.
- **Illicit Goods:** Drugs, stolen credit cards, counterfeit money, and stolen account credentials.
- **Information and Influence:** Doxing services and the sale of social media "likes" or "follows".

Common criminal activities discussed in these forums include **money laundering**, various forms of **fraud**, **identity theft**, and the management of **botnets**.

---

### **3. Investigating Underground Platforms**

Contrary to popular belief, many criminal platforms are not on the dark web (Tor) but exist as restricted-access sites on the "regular" internet.

#### **Key Pivot Points**

Criminals must share contact details to operate, providing investigators with critical data points to "follow":

- **User Identifiers:** Usernames, email addresses, and forum member/seller details.
- **Communication Handles:** Discord and Telegram URLs, ICQ numbers, or Jabber addresses.
- **Financial Data:** Bitcoin and other cryptocurrency wallet addresses.

#### **Market Operations and Case Study**

Underground markets often aim for a "frictionless" experience similar to eBay. Sellers use ratings and customer reviews to build goodwill and repeat business.

- **The Silk Road Case Study:** Founder Ross Ulbricht was caught because he used the same pseudonym ("altoid") on a programming forum—where he included his real email address—as he did while initially building the marketplace.
- **Anonymity and Crypto:** Unlike surface sites, these markets rely almost exclusively on cryptocurrency to maintain anonymity.

---

### **4. Fraud and Protection in the Underground**

Because there is little trust between criminals, fraud is rampant.

- **Rippers:** Sellers or sites that fail to deliver promised goods are labeled "rippers" on popular forums.
- **Mimicry:** Fraudsters create "phishing" versions of famous marketplaces to steal credentials or payments from unsuspecting buyers.
- **Escrow and Guarantors:** To protect themselves, users use **Escrow** services. A trusted forum "guarantor" holds the funds until the buyer confirms the item was received. This service usually costs a commission fee (up to 10%).

---

### **5. Underground Forum Dynamics**

Forums are more complex than markets because they focus on community and information exchange rather than just sales.

- **Entry Requirements:** Many require a referral from a current member, a join fee, or proof of "bona fides" (like sharing stolen data) to gain access.
- **Reputation and Gatekeeping:** Maintaining a high reputation score is vital for access to sensitive info. Analysts may be "gatekept" by being asked to prove technical skills or demonstrate a criminal action.
- **Languages:** While many use English, many others operate in Russian or other languages, requiring translation or linguistic expertise.

### **6. Private Communication Channels**

While initial contact happens in open forum threads, sensitive business quickly moves to private channels:

- **Direct Messages (DMs):** Most platforms have built-in private messaging.
- **Jabber (XMPP):** A highly popular decentralized messaging protocol for criminals.
- **Popular Apps:** Depending on the group and language, targets may use **Telegram**, **Discord**, **WhatsApp**, **WeChat (微信)**, or **ICQ**. Analysts should use the app most popular with the target group to blend in.

%%



Making Payments
Making payments for goods or services can almost always be done with a common cryptocurrency such as 
Bitcoin or Monero. Some like Monero have a private blockchain. But payments with Bitcoin and other open 
blockchain cryptocurrencies should be made using a "mixer" service (also called "tumblers" and "blenders") to 
obfuscate where your funds actually came from. These services charge a fee, but by shuffling your payment 
through many wallets, the source of the payment is hidden from the recipient (and others monitoring the 
blockchain).
Examples of popular mixing and tumbling services are:
• Blender.io
• Blenderbit.com
• Cryptomixer.io



## Topic 4: Cryptocurrency and Financial OSINT

%% 
### **1. Making Payments in the Underground**

In underground markets and forums, making payments is almost exclusively done using **cryptocurrency**, such as Bitcoin or Monero. For an investigator, this is a critical data point because while standard banking records might be unavailable, the nature of many cryptocurrencies allows for a different kind of tracking.

### **2. Fundamentals of Cryptocurrency**

- **Definition:** A cryptocurrency is virtual or digital money in the form of tokens or coins that can be bought, sold, and traded.
- **Technology:** They are based on cryptographic algorithms and a **blockchain** to create and process transactions.
- **The Blockchain:** In simple terms, a blockchain is a type of database that stores information in "blocks" that are chained together in a permanent, chronological order.
- **Mining:** This is the process of verifying transactions before they are added to the blockchain. It involves validating transactions and solving complex cryptographic hash puzzles.

---

### **3. Why Criminals Use Cryptocurrency**

Bad actors prefer cryptocurrency for several key operational benefits:

- **Anonymity:** It allows them to conduct illicit activities without being personally identified.
- **Liquidity:** Funds are easily exchangeable for other currencies or can be "cashed out".
- **Irreversibility:** Once a payment is sent (e.g., for extortion or illegal goods), the sender cannot undo the transaction.
- **Automation:** Almost every aspect, from creating wallets to moving funds, can be automated.

### **4. Money Laundering and Anonymity**

Cryptocurrency is an attractive way to **launder funds**, making it difficult for Anti-Money Laundering (AML) investigators to trace money back to its criminal origin. However, the level of anonymity varies:

- **Monero:** Maintains high privacy through a private blockchain ledger.
- **Bitcoin:** Uses a **public ledger** where every transaction is recorded. As one detective noted, while catching a dealer on the street only proves one crime, uncovering a Bitcoin history is like "discovering their books".

---

### **5. Tracking Cryptocurrency Payments**

For currencies with public blockchains, investigators can "follow the money," though tools like **mixers** are used by criminals to try and obscure these paths.

#### **The Wallet Address**

The starting point for any financial investigation is the **wallet address**, a unique cryptographic ID used to store and use the currency. Because these addresses are part of the immutable blockchain, they provide a permanent record of activity.

#### **Blockchain Investigation Tools**

Since all transactions are visible on a public blockchain, analysts use specialized tools to search for wallet IDs or transaction numbers.

1. **Blockchain.com Explorer:** A free tool for tracking Bitcoin, Ethereum, and Bitcoin Cash.
    - **Transaction View:** Shows the outflow of funds (destination and amount) and the inflow (sender and amount).
    - **Change Addresses:** It helps explain why a transaction might show two recipient addresses—one is the actual recipient, and the other is often receiving "change" from the transaction being returned to a different wallet controlled by the sender.
    - **Summaries:** Provides a clear summary of hashes and fees, with toggles to view values in either USD or the specific cryptocurrency.
2. **WalletExplorer:** A "smart" block explorer that provides **address grouping** and **wallet labeling**.
    - **Organization Identification:** It identifies wallet addresses associated with specific organizations, such as exchanges, gambling sites, and historical marketplaces.
    - **Association:** It automatically links different Bitcoin addresses to the same wallet based on transaction data, saving the analyst from having to make those connections manually.
3. **Bitcoin Who's Who:** A tracker that includes reports of **scam activity**, which is a primary goal of the site. It also provides URLs for any reported associations.
    
4. **Bitcoin Abuse Database:** A crowdsourced database focusing on wallet addresses used by criminals for ransomware and fraud. It features an **API** that can be used to check addresses, look up abuse tags, or submit new reports.
    
5. **Blockchair:** Features a clean graphical interface for showing sending and receiving wallets. The data is displayed in tables that can be scraped and exported as **CSV files**.
    
6. **Intelligence X (intelx.io):** A searchable database for Bitcoin addresses that provides the responsive data found, the date it was collected, and source URLs.
    

---

### **6. Case Study: Investigating a Bitcoin Address**

To demonstrate these concepts, the course provides a case study. The process begins with identifying a specific product or service on a **darknet market** hosted on Tor. By selecting a product and proceeding to the payment stage, an analyst can uncover the specific Bitcoin wallet address where the criminal wants the funds sent, providing the first major pivot point for a deeper investigation.

---

### **1. Case Study: Investigating Darknet Services**

The investigation begins with a listing on a **Tor-based darknet market** for a service offering fake "selfie identification". These services claim to provide fraudulent ID documents, but analysts must determine if the service is legitimate within the underground or merely a scam.

- **Financial Pivoting:** By following the payment instructions, investigators identified a specific **Bitcoin wallet address**. This wallet showed 70 transactions totaling over **$35,000**, acting as a collection point for funds from numerous other wallets.
- **Corroborating Evidence:** Searching for this new wallet address on Google revealed its association with multiple reported **scams**, including ransomware, blackmail, and sextortion.
- **Expanded Investigation:** Through this single pivot point, an analyst can link a seller of fake IDs to broader criminal networks, uncovering related email addresses, additional Tor websites, and IP addresses for further research.

---

### **2. The Cybercrime Underground: Common Fraud Activities**

The sources detail specific categories of fraud discussed and facilitated within underground communities:

- **Travel and Hospitality Fraud:** Criminals use stolen credit cards or hijacked user accounts to obtain car rentals, hotel stays, and flights. They also target loyalty programs to sell or use stolen miles and bonus points.
- **Mules, Shipping, and Drop Services:** Fraudsters often rely on **"mules"**—individuals who transfer illicit goods or funds to obscure the paper trail. **"Drop services"** provide physical addresses for receiving packages bought with stolen funds, helping to move high-value items while keeping the actual criminal anonymous.
- **Bank Fraud:** This broad category includes credit card theft, unauthorized wire transfers, and **Business Email Compromise (BEC)**. Advanced techniques mentioned include:
    - **SIM Swapping:** Stealing a victim's phone number to bypass security controls.
    - **BIN Searching:** Identifying banks that do not support **Mastercard SecureCode (MCSC)** or other 3D secure protocols to find easier targets for transaction fraud.
- **Money Laundering:** Online laundering involves converting illicitly gained funds into a "clean" form to hide their criminal origin. This often requires intermediaries or the use of **cryptocurrencies** and **mixers** (services that scramble transaction paths) to thwart Anti-Money Laundering (AML) investigators.
- **Government Payment Fraud:** This profitable area involves submitting fraudulent claims to government agencies, such as faked tax returns or unemployment benefits, to collect the resulting payments.
- **Confidence Scams:** These tricks rely on psychological manipulation. Examples include **romance scams** on dating sites, **BEC** activities, and the classic **"Nigerian Prince" (419)** email scams. While these actors can be sophisticated, they are sometimes unmasked through their own weak operational security.

### **3. Mobile Malware and Control Panels**

Investigators may also encounter command-and-control (C2) panels for mobile malware. An example provided is the **Anubis** panel, a known Android banking trojan used to manage infected devices ("bots"), monitor contacts, and inject fraudulent screens into banking apps to steal credentials.

%%






