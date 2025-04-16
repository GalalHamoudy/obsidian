# Section 1 : Disinformation and Coding For OSINT Efficiency

the process to make and spread disinformation or fake news consists of three steps:
the operation, the message, and the target. 
The operation is led by an actor, but this can a group or individual. The actor will craft a message they want to spread. The message will have a specific target audience, whether generalized, opposite, or like-minded. If the operation was successful in meeting the actor's goal(s), the process will end. If the process was not successful, the operation can be refined until the actor has reached their goal(s).


### How to Examine Images (Pictures/videos)
- Context - Does the footage add up with the narrative and the source? Are there sources that support this information? 
- Can we find out if the footage has been altered, manipulated, or edited in such a way that it differs from the source footage? 
- Is the footage staged? 
- Does the footage contain fake or deep fake content? 
- Does the narrative connect to the footage?

-----

### Some tools and Resource to examine information :

#### CrowdTangle
is a tool owned by Meta. CrowdTangle has a free Chrome browser extension that will help you pivot. The extension will give you better insight into how certain links on the internet are being spread and by whom on Facebook, Twitter, Reddit, and Instagram. This is great for examining accounts that are spreading a certain narrative or manipulating a certain web article. To use the CrowdTangle Link Checker extension, you must have a Facebook (sock puppet) account. Once installed, you can visit any page on the internet and then open the CrowdTangle Link Checker extension and examine the results.

CrowdTangle was a public insights tool from Meta to explore public content on social media. As of 14 August 2024, CrowdTangle is no longer available.

Meta Content Library and Content Library API, provide useful, high-quality data to researchers. [Meta Content Library](https://transparency.meta.com/researchtools/meta-content-library/) was designed to help us meet new regulatory requirements for data sharing and transparency, while meeting Meta's rigorous privacy and security standards.

**Best Paid & Free Alternatives to CrowdTangle**

- Hootsuite.
- Sprout Social.
- Meltwater.
- Sprinklr Social.
- Brandwatch Consumer Intelligence.
- Reputation.
- Zoho Social.
- Brandwatch Social Media Management.

#### Hoaxy
You can visualize search results coming from Twitter from the last 7 days or you can visualize the spread of claims collected by [Hoaxy](https://hoaxy.osome.iu.edu/). 

#### Botometer
[Botometer](https://botometer.osome.iu.edu/) is a tool to check if a Twitter account has the characteristics of being a bot or not. The higher the score, the more likely it is that the account is a bot. bot. 
The tool was developed by the Observatory on Social Media and the Network Science Institute. 
Botometer is based on a machine learning algorithm trained to calculate a score to indicate if an account is a bot or not. To calculate the score, Botometer compares an account to tens of thousands of labeled examples. 
Keep in mind that detection of bots by machine learning is hard and never 100% failsafe. Always perform (manual) secondary checks to make sure the presented outcome is correct


Within OSINT, we must check our sources for accuracy and reliability. The sources we are going to discuss are known for their accuracy and reliability. These sources can help you in your information gathering and analysis process :

Snopes.com 
Factcheck.org 
Poynter.org 
Eufactcheck.eu 
Knowyourmeme.com 

---------
the data can generally be classified into two types: 
- Structured data: 
	- Well-defined format 
	- Readily parsed into discrete data elements 
	- like JSON Data, delimited data, Comma-separated Values(CSV)
- Unstructured data: 
	- Format varies 
	- Parsing is more challenging; is specific to the source

note: we use 'jq' unix tool to filter Json data as "cut" tool or we can use this online tool [jqlang](https://play.jqlang.org/)

-----

#### People-Centric Search APIS 
People-oriented paid search providers that provide APIs: FullContact, pipl.  
People-oriented paid search providers that do not provide APIs: Intelius, Spokeo. 
Note: BeenVerified has references to an API service, but it does not appear to be active at this time.  
People-oriented free search providers that do not clearly provide APIs: Radaris. Thats Them, TruePeopleSearch. Xlek. Zabasearch. 
Note: PeekYou has references to an API service, but it does not appear to be active at this time

# Try Public APIs for free

[The Public APIs repository](https://github.com/public-apis/public-apis) is manually curated by community members like you and folks working at [APILayer](https://apilayer.com/?utm_source=Github&utm_medium=Referral&utm_campaign=Public-apis-repo). It includes an extensive list of public APIs from many domains that you can use for your own products. Consider it a treasure trove of APIs well-managed by the community over the years.


----
# Section 2 : Intelligence Analysis and Data Analysis with Python

1- analyze the source :
	A - reliable
	B - usually reliable
	C - fairly reliable
	D - Not usually reliable
	E - unreliable
	F - Cannot be judged
2- The content
	1- confirmed
	2- probably true
	3- possibly true
	4- doubtfully true
	5- improbalbe
	6- misinformation
	7- deception
	8- cannpt be judged

CRAAP Test 
In addition to the reliability rating model, we can do a CRAAP test scoring. For every gathered piece of information, you want to analyze each in detail before putting it in our overall reliability rating model. This is also a time-consuming process but will help you thoroughly analyze and understand the individual pieces of information that are part of the entire analysis puzzle.

CRAAP is an acronym for **Currency, Relevance, Authority, Accuracy, and Purpose**
Per question scoring: 
1 = Poor 
2 = Fair 
3 = Good 
4 = Very Good 
5 = Excellent 
Total score ranges: 
Low 0-38 
Medium 39-76 
High 77-115


Confidence Levels It is tradecraft practice to use confidence levels in your reports. We do this because we are rarely (if not never) 100% sure about the outcome of our findings and analysis.  We all know that new information may be found in a later stage, and with that, our initial analysis may change. To prevent making conclusions that are too strict, we use three confidence levels to label our judgments:
1.High confidence 2. Moderate confidence 3. Low confidence


What is ACH? 
Analysis of Competing Hypotheses (ACH) is a structured process to break down a complex analytical problem based on hypotheses that you test for consistency or inconsistency with evidence. 

What is the value of ACH? 
ACH helps you see information from different perspectives and test those perspectives for reliability based on evidence found in the gathered information


ACH excels in: 
Testing gathered information for relevance before you decide to report on it 
Preventing bias or assumptions from entering your analysis product 
Assessing information for deception 
Approaching a research question from different angles using different hypotheses 
Identifying and highlighting gaps in the gathered information 
Considering many different hypotheses to ensure that potential scenarios have not been overlooked

The ACH Process  
Analysis of Competing Hypotheses (ACH) is an eight-step process. If you make these steps a standard operating procedure (SOP), your ACH analysis will be solid and sound. 
We can embed the previously discussed reliability rating model and CRAAP test to help us make an even more sound analysis, which leads to actionable intelligence. 
1. Produce hypotheses, preferably as many as you can. Research and experience have proven that teams or groups produce more, and higher quality, hypotheses. 
2. Make lists or arguments and evidence based upon available gathered information, including assumptions, for and against each hypothesis. 
3. Build a matrix (spreadsheet) with hypotheses and evidence. 
4. Based on these first findings, refine your hypotheses. 
5. Review the hypotheses for (in) consistency and weigh your conclusions. 
6. Double-check the reliability and validity of your evidence using a reliability rating and/or CRAAP methodology. 
7. Report your conclusions, including the rejected hypotheses. 
8. Repeat steps 1 to 7 based on newly gathered information or analytical insights.
------
# section 3 : sensitive Group Investigations and video and image verification 

the [data.ai](https://www.data.ai/account/login/) service, formerly named app annie , is a great resource to get abetter understanding of what apps are popular in a given country. (like [APPLyzer](https://applyzer.com/))

[Search by Image](https://chromewebstore.google.com/detail/search-by-image/cnojnbdhbhnkbcieeekonklommdnndci) : Search by Image is a browser extension that makes effortless reverse image searches possible, and comes with support for more than 30 search engines.

[InVID](https://www.invid-project.eu/tools-and-services/invid-verification-plugin/) Verification Plugin : project to help journalists to verify content on social networks , allow you to quickly get contextual information on Facebook and YouTube videos, to perform reverse image search on Google, Baidu or Yandex search engines, to fragment videos from various platforms

[AutoStitch](https://mattabrown.github.io/autostitch.html): Panoramic Image Stitching , Panoramic image mosaicing works by taking lots of pictures from an ordinary camera, and stitching them together to form a composite image with a much larger field of view.

[google Video Intelligence API](https://cloud.google.com/video-intelligence) automatically recognize a vast number of objects, places, and actions in stored and streaming video.

---
# section 4 : sock Puppets, OPSEC ,Dark Web and Cryptocurrency

OPSEC, or Operations Security, in cybersecurity refers to the process of identifying and protecting critical information that could be used by adversaries to compromise the security of an organization. The goal of OPSEC is to prevent sensitive information from falling into the wrong hands, thereby reducing the risk of cyber attacks, data breaches, and other security incidents.

### Key Components of OPSEC:

1. **Identification of Critical Information**: 
   - Determine what information is sensitive and could be valuable to an adversary. This could include intellectual property, personally identifiable information (PII), financial data, or operational details.

2. **Threat Analysis**:
   - Identify potential adversaries and their capabilities, intentions, and methods. Understanding who might want to target your organization and how they might do it is crucial.

3. **Vulnerability Analysis**:
   - Assess the vulnerabilities that could be exploited by adversaries to gain access to critical information. This includes both technical vulnerabilities (e.g., software flaws) and human factors (e.g., social engineering).

4. **Risk Assessment**:
   - Evaluate the likelihood and potential impact of different threats exploiting identified vulnerabilities. This helps prioritize which risks need to be mitigated first.

5. **Application of Countermeasures**:
   - Implement measures to protect critical information. This could include encryption, access controls, employee training, and other security practices.

### Common OPSEC Practices:

- **Data Encryption**: Encrypt sensitive data both at rest and in transit to protect it from unauthorized access.
- **Access Controls**: Implement strict access controls to ensure that only authorized personnel can access sensitive information.
- **Employee Training**: Educate employees about the importance of OPSEC and how to recognize potential threats, such as phishing attacks.
- **Regular Audits**: Conduct regular security audits to identify and address vulnerabilities.
- **Incident Response Planning**: Develop and maintain an incident response plan to quickly and effectively respond to security incidents.

### Importance of OPSEC:

- **Protects Sensitive Information**: By identifying and safeguarding critical information, OPSEC helps prevent data breaches and leaks.
- **Reduces Risk**: Proactively addressing vulnerabilities and threats reduces the overall risk to the organization.
- **Enhances Security Posture**: A strong OPSEC program contributes to a robust overall cybersecurity strategy, making it harder for adversaries to succeed.

In summary, OPSEC is a vital component of cybersecurity that focuses on protecting sensitive information from being exploited by adversaries. It involves a systematic approach to identifying critical information, analyzing threats and vulnerabilities, and implementing appropriate countermeasures to mitigate risks.

Tor services :
Email : ProtonMail & TorBox
Drop Services : SecureDrop
ZeroBin  is a minimalist, open source online pastebin where the server has zero knowledge of pasted data. Data is encrypted/decrypted in the browser using 256 bits AES

search engine : Ahmia,tor66 and Darksearch (they are not as thorough as a public internet search engine as Google)

there are several tor web proxies that can be used to visit tor resource via a surface website, such as :
onion.ws / onion.sh / onion.cab / tor2web.fi

---
# Section 5 : Automated Monitoring and Vehicle Tracking

[IFTTT](https://ifttt.com/) 
"If This Then That" (IFTTT) is a tool that, as the name implies, allows a sequence of actions to occur after a triggering event. This is done with "applets." - recipes or directions for actions to take. For example, one could set up an applet to save the text of a Tweet from a specific user to Dropbox whenever they've posted a new Tweet.  
There are many, many ways one could use IFTTT as an OSINT investigator, from automating sock puppet activities to make them appear real to monitoring target social media accounts, websites, or blogs.

Really Simple Syndication  (as [Rss-Bridge](https://rss-bridge.org/))
Really Simple Syndication (RSS) is an XML-based format for sharing web content. It allows for a user to easily receive updates from resources on the world wide web. If an investigator is interested in a particular subject and would like to receive new updates about it from selected websites, RSS is a useful method of doing that. 
The operator of the website that you are interested in needs to establish an RSS "feed" that has a list of new updates and notifications. These can be checked manually; but for the sake of efficiency, subscribing to the feed so that these appear automatically in a feed reader or aggregation application is the best method.

[Searx](https://metasearx.com/) : is free metasearch with no tracking or profiling, and can gives you the result in CSV or Json .


[Poctra](https://poctra.com/) is salvage car auction archive from US and EU markets.
We crawl the web for salvage vehicles and maintain repository on those found. We archive photos and all available information about vehicles

Some resources for vehicle identification number searches include: 
US: autocheck.com 
US: Carfax.com 
US: findbyvin.com 
US: vehiclehistory.com 
US: vincheck.info 
US and EU: poctra.com 
Japan: carvx.jp/chassis-number 

Some of the useful online license/number plate sites include: 
US: autocheck.com 
US: carfax.com 
US: findbyplate.com 
US: faxvin.com 
US: searchquarry.com 
US: licenseplateslookup.com 
Australia: carhistory.com.au 
Australia: checkrego.com.au 
Italy: iTarga app

Rate the Driver" Sites 
These websites provide crowdsourced and other information about drivers observed on the road. Persons submitting information often describe the manner in which a vehicle was being driven but also may include photos, when and where the vehicle was observed, and other information. 
Registration and tax information. mileage,  inspection test results, and more may also be included on some of these websites.
UK: rate-driver.co.uk 
US: rate-driver.com 
Canada: rate-driver.ca 
Australia: rate-driver.com.au 
Germany: fahrerbewertung.de 
France: evaluer-chauffeur.fr 
Poland: tablica-rejestracyjna.pl


Car Spotting Websites  
There are a number of car enthusiast sites where people share information on interesting vehicles they have seen, share photos of them, and provide other information. These sites may also record data such as the plate number and may provide a search capability using the VIN or number plate. 
Some potentially useful car spotting sites that include license/number plate and VIN information and search capability are: 
autogespot.us 
platesmania.com 
exclusivecarregistry.com 


Owner of an Aircraft :
they collected links for civil aviation authorities of most countries.
Skytamer.com
airlineupdate.com
they record this info and have searchable databases :
airframes.org
airfleets.net


There are a number of websites that provide live and historical tracking of aircraft, including mapping and search capabilities. 
Their tracking is based on the reception of radio transmissions, including ADS-B position, speed, and other data, along with the hex ID to identify the particular aircraft. 
Some reliable, free sites include: 
adsbexchange.com 
flightaware.com 
flightradar24.com 
opensky-network.org 
planefinder.net  
radarbox.con 

Planespotter Websites 
There are a number of websites dedicated to "planespotting"-the hobby of monitoring aircraft, taking photos of them, and the like. These sites may be operated by a single individual or consist of a repository of data from multiple sources. They may include searchable databases and content that is not available elsewhere. 
Some civil and military aviation planespotter resources include: 
airfleets.net 

planespotters.net 
jetphotos.com 
planelist.net/
joebaugher.com/usaf_serials/usafserials.html 
aviationdb.com 
scramble.nl/database/military



Some countries, including the United States, Canada, anada, Australia, and others, maintain searchable databases of registered airmen as a public record. This includes commercial pilots, private pilots, flight instructors, mechanics, UAS operators, and others who must be registered with the appropriate national authority. 
The following sites provide a searchable database of the registered pilots of several English-speaking countries: aviationdb.com 


Useful sites that include a free tier of access to ship registration and ownership data include: 
Vesselfinder.com 
Shipfinder.co 
Equasis.org (registration required) 
Fleetmon.com/vessels/
Vesseltracker.com 
Lr.org/en/lrofships (Lloyd's Register-free results are very limited)

There are other privately operated websites that provide vessel registry information for a specific country, such as marinetitle.com for the United States. Governments may also provide information about their naval vessels, for example, the Portuguese Navy's registry site (https://www.marinha.pt/pt/os_meios) or the US Naval Vessel Register (https://www.nvr.navy.mil). Privately operated websites may also provide data on military vessels, some for a fee, including the well-known and comprehensive Jane's (janes.com), as well as many free sources focused on a particular country, such as russianships.info. 
Some of the paid platforms have very thorough information, including shipindex.org and Lloyds Register (https://www.lr.org/en-us/marine-shipping/)

Vessel Databases : 
There are a lot of databases available that provide information based on IMO, AIS, and MMSI look-ups for a specific ship. 
You may need to check multiple databases to determine which has the information you need for any given investigation. 
Some suggested sites: 
vesselfinder.com 
fleetmon.com 
marinetraffic.com 
gisis.imo.org 
aishub.net 
Shipfinder.co 

There are websites that function to connect ships with crew members; they act in essence as LinkedIn and job search sites for mariners.  
There are several such including: 
balticshipping.com 
maritime-connector.com 
maritime-union.com/seafarers 
findacrew.net


Ship Cargo 
There are many resources for searching using container numbers. Many shipping company websites often provide such a service for containers in their care. If one has a container number, there are a number of websites that allow you to search for that container. Some of the free sites include: 
fleetmon.com 
track-trace.com/container 
searates.com/container/tracking/
shipup.net 

Maritime VHF Radio  
Marine radios use very high frequency (VHF) wavelengths. These radios are used to communicate between ships, shore stations, and aircraft when necessary.  
If there is an ongoing event such as a rescue occurring, you may be able to find an internet resource that allows you to listen in to the local marine VHF channels. Those communicating on the radio may include persons involved in an incident, emergency responders, and others operating vessels in the immediate area. 
Resources that have some marine radio live feeds: 
Broadcastify.com 
Bohdaneb 
Dxzone.com