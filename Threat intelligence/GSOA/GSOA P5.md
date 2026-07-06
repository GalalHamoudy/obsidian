# Section5: Automated Monitoring and Vehicle Tracking

1. Advanced Search Techniques
2. Advanced Twitter Analysis
3. Motor Vehicle OSINT
4. Aviation OSINT
5. Maritime OSINT

---

## Topic 1: Advanced Search Techniques

%% 

This section, **Section 5: Automated Monitoring and Vehicle Tracking**, explores how OSINT analysts can build custom tools to find and track data across various platforms more efficiently than using standard search engines.

### **1. Why Custom Searching is Necessary**

OSINT analysts often rely on search engines where they have little to no control over the data being searched. Furthermore, standard search engines present **operational security (OPSEC) risks**, as they may collect your digital fingerprint and track your behavior.

Setting up a **custom search engine** provides several advantages:

- **Data Control:** You decide which data sources to include.
- **Scalability and Flexibility:** Custom tools can be scaled to handle massive volumes of data that might otherwise be unmanageable.
- **Minimized Risk:** By controlling the infrastructure, you can reduce OPSEC risks to a minimum.

### **2. Methods of Custom Searching and Monitoring**

There are three primary methods for setting up custom searching and monitoring systems:

#### **A. Host System**

This involves using your own laptop, desktop, or a virtual machine (VM) with custom software installed.

- **Pros:** You maintain total control over software and algorithms, ensuring you know exactly what traffic is entering or leaving your system. It is generally low cost because much of the necessary software is free.
- **Cons:** You are responsible for all maintenance, and the system may not be easily scalable if you run out of storage space. Additionally, setting this up requires technical knowledge that many OSINT analysts may lack.

#### **B. Proxy Services**

Proxy-based services allow analysts to perform custom searches in specific areas across the dark, deep, and clear web.

- **Pros:** These are easy to set up, usually requiring only a web browser, and offer 24/7 uptime.
- **Cons:** The proxy provider may become aware of your research goals, which is an OPSEC concern. There is also usually a price tag involved.

#### **C. Cloud Services**

Cloud-based searching involves outsourcing the host functionality to a provider like Amazon AWS, Google Cloud, or Microsoft Azure.

- **Pros:** It offers global 24/7 access to data and is highly scalable for team collaboration.
- **Cons:** These systems can be challenging to configure and may be expensive. Additionally, some platforms block cloud-based IP addresses by default, which can hinder data collection.

### **3. The Importance of Automated Monitoring**

Automated monitoring is vital for handling repetitive OSINT tasks and addressing specific intelligence requirements. It allows analysts to:

- Establish **correlations** (e.g., identifying if two users are communicating across multiple platforms).
- Detect **changes** (e.g., monitoring a target's profile picture over time).
- Receive **early warnings** (e.g., setting keyword alerts for natural disasters or active shooter events).

### **4. Key Automation and Aggregation Tools**

#### **IFTTT (If This Then That)**

IFTTT uses "applets"—recipes that trigger a sequence of actions after a specific event. For OSINT, this can be used to monitor target social media accounts or to **automate sock puppets** to make them appear like real, active users.

#### **RSS (Really Simple Syndication)**

RSS is an XML-based format used to share web content. It is powerful for investigators because it **aggregates current information** from a large number of sources into a single feed reader, allowing for much more efficient monitoring than checking individual websites manually.

#### **RSS-Bridge**

For websites that do not have a built-in RSS feed, analysts use **RSS-Bridge**. This open-source project can generate feeds in various formats, including JSON and HTML, by collecting data from source websites using cURL.

### **5. Searx: A Privacy-Respecting Metasearch Engine**

**Searx** is a free, self-hosted metasearch engine that does not track or profile its users. It aggregates data from over **70 different search engines**, including Google, Bing, Yandex, and specialized sources like Shodan and Twitter.

Searx is particularly useful for OSINT because it can output search results in four formats:

1. **HTML:** Standard webpage view.
2. **CSV:** Useful for data preservation.
3. **JSON:** Allows for easy parsing and analysis using Python or other tools.
4. **RSS:** Can be used to set up automated keyword monitoring systems that alert an analyst when new intelligence requirements are met.

This section concludes with **Lab 5.1**, where students practice setting up and using Searx for custom searches.

%%



## Topic 2: Advanced Twitter Analysis





