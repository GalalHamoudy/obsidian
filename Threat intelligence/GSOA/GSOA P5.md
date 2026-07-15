# Section5: Automated Monitoring and Vehicle Tracking

1. Advanced Search Techniques
2. Advanced Twitter Analysis
3. Motor Vehicle OSINT
4. Aviation OSINT
5. Maritime OSINT

---

## Topic 1: Advanced Search Techniques

%% 
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

For websites that do not have a built-in RSS feed, analysts use **RSS-Bridge**. This open-source project can generate feeds in various formats, including JSON and HTML, by collecting data from source websites using CURL.

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


%% 

### **1. Searching Twitter Lists**

A **Twitter List** is a curated group of accounts created by users. They are valuable for OSINT because they allow you to find groups and individuals who contribute to a specific group's narrative. Once a list is found, an analyst can pivot by examining the tweets within the list or investigating the individual members.

#### **Finding Lists on a Profile**

If you have identified a target account, you can check if they have created or are members of any public lists:

1. Navigate to the profile.
2. Click the **three dots** (more) icon.
3. Select **"View Lists"** to see which lists the user owns, follows, or is included in.

#### **Using Search Engines to Find Lists**

Since many lists are public, they are indexed by search engines. You can use **Google Dorks** with wildcards to find lists related to specific **Unique Identifying Labels (UILs)**:

- **Operator:** `site:twitter.com/*/lists intitle:[keyword]`
- **Wildcard (*):** Acts as a placeholder for the username of the list owner, which is unknown beforehand.
- **Examples:** `site:twitter.com/*/lists intitle:malware` or `site:twitter.com/*/lists intitle:antifa`.

### **2. Analyzing and Extracting List Members**

When viewing a list on Twitter, you can see the **name**, **description**, **owner**, and the number of **members and followers**.

#### **Extracting Data via Developer Tools**

To perform bulk analysis on list members, you can extract their details using **Firefox Developer Tools**.

1. Log in to Twitter with a **sock puppet account** (required to see list members).
2. Open the Developer Tools (**F12**) and go to the **Network tab**.
3. Scroll to the bottom of the member list to ensure all data loads.
4. Filter the network traffic for **"ListMembers"** to find the JSON data containing the member details.
5. This data can then be saved or converted to a **CSV file** for analysis in tools like LibreOffice or Python.

### **3. Monitoring with Private Lists**

Analysts can create their own **private Twitter Lists** to monitor targets without notifying them. By adding target accounts to a private list, you can use tools like **TweetDeck** to keep tabs on their activity and narrative in near real-time.

### **4. Scraping Twitter with Twint**

**Twint** is a powerful Python-based command-line tool that allows you to scrape Twitter data **without using the official API**.

- **Advantages:** No need for an API key, no rate limits on results, and no requirement to log in (reducing OPSEC risk).
- **Usage Examples:**
    - `twint -u [username]` – Scrapes tweets from a specific user.
    - `twint -s [keyword]` – Searches for tweets containing a specific term.
    - `twint --followers [username]` – Scrapes a user's followers.
- **Output:** Results can be saved directly as **JSON** or **CSV** for further analysis or exported to a database like Elasticsearch.

### **5. Social Network and Graph Analysis**

Large datasets extracted from Twitter (via Twint or lists) are best analyzed using **Graph Analysis**.

- **Nodes and Edges:** In this model, an account is a **node**, and an interaction (like a retweet or mention) is an **edge**.
- **Community Discovery:** Graph analysis helps identify **clusters** or communities of related accounts that may not be obvious through standard searching.
- **Gephi:** This is a free, open-source tool used to visualize these relationships. It is excellent for analyzing large-scale influence operations or mapping infrastructure by clarifying how different entities are linked.


%%


## Topic 3: Motor Vehicle OSINT

%% 

### **1. Introduction to Motor Vehicle OSINT**

Motorized vehicles are primary modes of transport globally and can be central to investigations involving security incidents, property links, or specific targets. Vehicles are identified through their **physical appearance, signage, and registration plates**. Finding a license plate can act as a critical pivot point to uncover a **Vehicle Identification Number (VIN)** or title number for deeper data collection.

### **2. Vehicle Identification Numbers (VIN)**

A VIN is a unique alphanumeric code assigned to modern production vehicles during manufacturing. It is stamped in various locations, most visibly on a dashboard plate near the windshield.

- **Standards:** Most follow the **ISO-3779** standard, where specific characters represent the manufacturer, location of manufacture, and vehicle details.
- **Regional Differences:** Japan uses "chassis" or "frame" numbers instead of ISO standards for domestic vehicles, and pre-1980 vehicles use different serialization structures.
- **Pivot Power:** Unlike license plates, a VIN does **not change** when ownership is transferred or when the owner moves to a new jurisdiction.

#### **Online VIN Decoders:**

- **North America:** [vpic.nhtsa.dot.gov/decoder/](https://vpic.nhtsa.dot.gov/decoder/).
- **International:** [vindecoder.eu](https://vindecoder.eu/).
- **Japan:** [ts-export.com](https://ts-export.com/page.php?page=about_vin_decoders).
- **Older Vehicles:** [vehicleidentificationnumber.com](https://vehicleidentificationnumber.com/vehicle_identification_numbers_vin_decoding.html).

### **3. Searching for VIN Information**

Analysts should check **government motor vehicle departments** first, though some may charge a fee.

- **Government Lookups:** Examples include **Ontario** and **Alberta** (Canada), **Florida** (USA), and various states in **Australia**.
- **Search Engines:** A simple Google search of a VIN can reveal accident history, auction sales, and images.

#### **Private VIN Research Sites:**

These sites often aggregate government records and may require payment for full reports.

- **USA:** `autocheck.com`, `Carfax.com`, `findbyvin.com`, `vehiclehistory.com`, `vincheck.info`.
- **International/US/EU:** `poctra.com`.
- **Japan:** `carvx.jp/chassis-number`.

### **4. License/Number Plates**

Registration numbers are government-issued identifiers displayed on plates or tags.

- **OSINT Utility:** They are unique strings that serve as primary identification points.
- **Search Strategy:** Search engines like Google index plates from text and images, often using **Optical Character Recognition (OCR)** to extract numbers from photos.

#### **Regional Encoding Clues:**

- **Germany:** The first 1–3 letters indicate the city or region of registration.
- **USA (Massachusetts):** Parts of the plate number represent the expiration month.

### **5. Specialized Plate Databases**

Many sites allow searching by plate number to find the associated VIN or basic vehicle history.

- **Example:** Searching a Virginia plate on `faxvin.com` can reveal the vehicle's full VIN.
- **Global Resources:**
    - **USA:** `autocheck.com`, `carfax.com`, `findbyplate.com`, `faxvin.com`, `searchquarry.com`, `licenseplateslookup.com`.
    - **Australia:** `carhistory.com.au`, `checkrego.com.au`.
    - **Italy:** **iTarga** mobile app.

### **6. Government Registration Databases**

- **United Kingdom:** The **Ministry of Transport** allows public searches that return registration dates, tax status, and technical specs (engine size, color, weight) but do **not** identify the owner.
- **Australia:** The **PPSR** ([ppsr.gov.au](https://www.ppsr.gov.au/glossary/vehicle-registration-number-rego)) links to individual state registration databases.
- **Singapore:** The **Land Transport Authority (LTA)** provides a free lookup through **One Motoring** showing registration and road tax expiry.
- **New York (USA):** `howsmydrivingny.nyc` tracks vehicles with parking or driving citations.

### **7. "Rate the Driver" (Crowdsourced) Sites**

These platforms provide comments, photos, and timestamps of vehicles seen on the road. Many use the plate number directly in the URL (e.g., `rate-driver.co.uk/PLATE`), which allows for **automated searching** using tools like cURL.

- **Examples:** `rate-driver` (UK, US, Canada, Australia), `fahrerbewertung.de` (Germany), `evaluer-chauffeur.fr` (France), and `tablica-rejestracyjna.pl` (Poland).

### **8. Car Spotting Enthusiast Sites**

Crowdsourced images from car enthusiasts often include plate numbers, locations, and technical details.

- **High-End Focus:** `autogespot.us` and `exclusivecarregistry.com` cover expensive vehicles globally.
- **General Purpose:** **Platesmania.com** is a premier resource that allows searches of **partial registration numbers** and covers all vehicle types across Europe and other regions.
- **Collectors:** `vintagebentleys.org` and the **Porsche 928 Owner's Club** are useful for antique or collectible searches.


%%


## Topic 4: Aviation OSINT


%% 
### **1. Why Track Aircraft?**

Aircraft traverse the globe constantly, and much of their data is publicly accessible. Analysts track aircraft to:

- Investigate ongoing or past incidents.
- Monitor specific individuals or organizations that operate aircraft.
- Perform **force protection** for organizations.
- Conduct **executive protection** exercises to see what travel information is public.
- Monitor flights near specific geographic areas of concern.

### **2. Aircraft Registration (Tail Numbers)**

By international law, all civil aircraft must be registered with a national aviation authority. These authorities issue a globally unique alphanumeric string known as a **"tail number"** or registration number, which must be prominently displayed on the craft.

- **Country Prefixes:** Each registration starts with a unique alphanumeric prefix identifying the country of registration. For example, "N" is for the USA, "C" for Canada, and "D" for Germany.
- **Prefix Changes:** These codes can change with government shifts (e.g., the Soviet "CCCP" was replaced by "RA" for Russia and "UK" for Uzbekistan).
- **Confidentiality:** While most registries are open, some jurisdictions (like Aruba or the Isle of Man) maintain the confidentiality of owner information.

**Resources for Registries:**

- **skytamer.com** and **airlineupdate.com**: Directories of international civil aviation authorities.
- **airframes.org** and **airfleets.net**: Searchable databases for registration and ownership.

### **3. General Aircraft Identification (Visual Clues)**

When tail numbers are not visible or have been altered, analysts use physical features for identification. Key features include:

- **Engines:** Number, type, and location.
- **Flight Surfaces:** Wing and tail design/location.
- **Fuselage Details:** Cockpit window configuration, number/location of doors and windows, and antenna/radome placements.
- **Paint/Markings:** National flags, company logos, pinstripes, and color schemes.

### **4. Investigating Owners and Personnel**

#### **Ownership Data**

Registration certificates usually identify the owner and the operator (which may be different). Beyond a name, analysts look for:

- Operator addresses, websites, phone numbers, and emails.
- How long they have owned the craft and if they own others.

#### **Drones and Airmen**

- **Drone (UAS) Registration:** Many countries now require unmanned aircraft operators to register. Some authorities share information on commercial licensees searchable by registration numbers.
- **Registered Airmen:** Countries like the US, Canada, and Australia maintain public databases of pilots, instructors, and mechanics.
    - **Resource:** `aviationdb.com` provides a searchable database of registered pilots for several countries.
    - **Pilot Associations:** Organizations like the **Federation of Indian Pilots** (`fipindia.com`) share member lists and photos.

### **5. Technical Tracking: ADS-B, Hex Codes, and Call Signs**

Most modern aircraft use **Automatic Dependent Surveillance-Broadcast (ADS-B)** technology for safety.

- **ADS-B:** Aircraft determine their position via GPS and periodically broadcast unencrypted data (location, altitude, speed, heading) to ground stations and other craft.
- **Hexadecimal (Mode-S) Codes:** Every aircraft is assigned a unique **24-bit hexadecimal ID** issued during registration. In the US and Canada, this hex code often mirrors the tail number.
- **Call Signs:** Radio operators use unique call signs to identify themselves. Civil call signs are often based on the registration number, while commercial flights use ICAO-designated company codes followed by flight numbers.

### **6. Live and Historical Tracking Websites**

Specialized websites aggregate ADS-B data from global receiver networks to provide live maps and flight histories.

**Key Tracking Platforms:**

- **adsbexchange.com**: Known for providing unfiltered flight data without blocking requests from aircraft owners.
- **flightradar24.com**: Popular site for searching by tail number, hex ID, or airport.
- **flightaware.com**: One of the few sites offering a significant amount of historical flight data for free.
- **opensky-network.org**: Provides a free source of ADS-B data and a rate-limited **API** (Python/Java/REST) that returns data in **JSON** or **CSV**.
- **icarus.flights**: Another resource claiming to provide unfiltered, "uncensored" data.
- **planefinder.net** and **radarbox.com**: Reliable tracking alternatives.

### **7. Planespotter and Military Resources**

Enthusiast websites often contain photos and data not available in official government registries.

- **General Spotting:** `planespotters.net`, `jetphotos.com`, and `planelist.net`.
- **Military Focus:** `joebaugher.com` (USAF serials) and `scramble.nl/database/military`.

%%


## Topic 5: Maritime OSINT


%% 
### **1. Foundations of Maritime OSINT**

The maritime world is vast and interconnected, with ships sailing 24/7. Much like aviation, maritime operations are governed by international laws requiring the registration and broadcasting of data for safety and collision avoidance.

#### **Unique Identifiers for Ships**

To find a specific ship, analysts look for unique markers:

- **IMO Number:** A unique seven-digit identifier that stays with a vessel for life, regardless of name or flag changes.
- **MMSI:** A unique 9-digit number assigned to a ship's radio or AIS unit.
- **Call Sign:** A radio-based identifier registered with national authorities.
- **Ship Name:** Registered with the government, though multiple ships may share common names (e.g., "Shark").
- **Physical Appearance:** Visual clues like hull color, logos on smokestacks, and the configuration of cranes or masts.

---

### **2. Ship Registration and Ownership**

International law requires commercial vessels to be registered in a national registry. Some owners use **"flags of convenience"** (e.g., Panama or Liberia) to benefit from lower costs or fewer regulations.

#### **Key Databases for Registration and Ownership:**

- **General Databases:** [vesselfinder.com](https://www.vesselfinder.com/), [shipfinder.co](https://www.shipfinder.co/), [fleetmon.com](https://www.fleetmon.com/), and [vesseltracker.com](https://www.vesseltracker.com/).
- **Official & Professional Records:** [Equasis.org](https://www.equasis.org/) (free registration required) and [Lloyd’s Register (lr.org)](https://www.lr.org/).
- **Government Registries:** The **Australian Maritime Safety Authority** provides downloadable spreadsheets of all registered vessels. In the US, the **FCC** allows searches for radio licenses by call sign or owner name.
- **Naval/Military Vessels:** Specific resources include the **US Naval Vessel Register** ([nvr.navy.mil](https://www.nvr.navy.mil/)), [russianships.info](http://russianships.info/), and the comprehensive [janes.com](https://www.janes.com/).

---

### **3. Tracking Ships: AIS and Beyond**

The **Automatic Identification System (AIS)** is the primary method for tracking vessels in near real-time. It broadcasts location, speed, and heading.

- **AIS Spoofing:** Investigators must be aware that AIS can be intentionally spoofed to hide a ship's true location, a tactic often used by military vessels or those involved in illicit activities.
- **Validating Tracks:** To detect spoofing, analysts use **port webcams**, **satellite imagery**, and crowdsourced **ship-spotting photos**.

---

### **4. Ship Personnel and Crew**

"Seafarers" or crew members often have their own digital footprints. Identifying them can provide inside information about a vessel's status or activities.

#### **Personnel Research Sites:**

- **Professional Networking:** [balticshipping.com](https://www.balticshipping.com/), [maritime-connector.com](https://maritime-connector.com/), [maritime-union.com](https://maritime-union.com/), and [findacrew.net](https://www.findacrew.net/).
- **Credential Verification:** Many countries, like the **Philippines** and the **US Coast Guard**, have databases to verify seafarer certificate numbers.
- **Search Strategies:** Using Google Dorks such as `[Shipname] "crew OR seafarer"` or `[IMO Number] [Rank/Role]` can uncover social media profiles.

---

### **5. Cargo and Container Tracking**

Most maritime cargo is transported in standardized containers, each marked with a unique code.

- **Code Structure:** Codes typically start with four capital letters (the first three identify the owner, the fourth is "U" for unit), followed by a six-digit serial number. For example, **MSKU** indicates a Maersk container.
- **Tracking Tools:** Sites like [shipup.net](https://www.shipup.net/), [track-trace.com/container](https://www.track-trace.com/container), and [searates.com](https://www.searates.com/) allow analysts to view the entire movement history of a specific container.

---

### **6. Advanced Remote Sensing**

- **Satellite Imagery:** Free tools like **Google Earth** and **Sentinel Hub** are useful, while paid providers like **Maxar (Digital Globe)** and **Planet Labs** offer high-resolution, recent images for change detection.
- **Shodan:** Analysts use Shodan to find a ship's internet-connected satellite communication systems (e.g., **Inmarsat**, **Cobham Sailor 900**, or **KVH CommBox**).
- **News & Blogs:** Specialist sites like **H.I. Sutton's Covert Shores** ([hisutton.com](http://www.hisutton.com/)) provide deep analysis of naval developments, such as new submarine variants.

---

### **7. Maritime Radio (VHF)**

VHF radio is used for ship-to-shore and ship-to-ship communication.

- **Frequencies:** Channel **16 (156.8 MHz)** is the international distress frequency.
- **Listening Online:** [Broadcastify.com](https://www.broadcastify.com/) and [Dxzone.com](https://www.dxzone.com/) provide live feeds of maritime radio traffic.
- **Standard Phrases:** Communication is standardized using **IMO Standard Marine Communication Phrases (SMCP)**, which includes specific terms like "Mayday" (distress) or "Pan-Pan" (urgency).


%%


# Plus 

The following is a comprehensive list of websites and platforms for Motor Vehicle, Aviation, Maritime, and Drone OSINT, compiled from the provided sources and enriched with additional research.

### **1. Motor Vehicle OSINT**

Motor vehicle investigations typically pivot from license plates or **Vehicle Identification Numbers (VINs)**.

#### **VIN Decoders & Research**

- **North America (NHTSA):** [vpic.nhtsa.dot.gov/decoder/](https://vpic.nhtsa.dot.gov/decoder/)
- **International Decoders:** [vindecoder.eu](https://vindecoder.eu/)
- **Japanese Chassis Numbers:** [ts-export.com](https://ts-export.com/page.php?page=about_vin_decoders)
- **Older/Pre-ISO Vehicles:** [vehicleidentificationnumber.com](https://vehicleidentificationnumber.com/vehicle_identification_numbers_vin_decoding.html)
- **Commercial VIN Checkers:** `autocheck.com`, `Carfax.com`, `findbyvin.com`, `vehiclehistory.com`, `vincheck.info`, and `poctra.com` (US/EU).

#### **License Plate Lookups & Databases**

- **FaxVIN:** [faxvin.com](https://faxvin.com/) (Pivots from plate to full VIN).
- **Government Portals:** Ontario/Alberta (Canada), Florida (USA), and Australian state registries.
- **UK Ministry of Transport:** [Check MOT/Tax status](https://www.gov.uk/check-mot-history).
- **Singapore Land Transport Authority:** [One Motoring](https://onemotoring.lta.gov.sg/content/onemotoring/home.html).
- **Australia PPSR:** [ppsr.gov.au](https://www.ppsr.gov.au/glossary/vehicle-registration-number-rego).
- **New York Citations:** [howsmydrivingny.nyc](https://howsmydrivingny.nyc/).
- **General Search:** `findbyplate.com`, `searchquarry.com`, `licenseplateslookup.com`, and `iTarga` (Italy mobile app).

#### **Crowdsourced & Enthusiast Sites**

- **"Rate the Driver" (Aggregated Complaints/Photos):** `rate-driver.co.uk` (UK), `rate-driver.com` (US), `rate-driver.ca` (Canada), `fahrerbewertung.de` (Germany), `evaluer-chauffeur.fr` (France), and `tablica-rejestracyjna.pl` (Poland).
- **Platesmania:** [platesmania.com](https://platesmania.com/) (Excellent for partial plate searches and international coverage).
- **High-End/Spotting:** [autogespot.us](https://autogespot.us/) and [exclusivecarregistry.com](https://exclusivecarregistry.com/).
- **Antique/Specialty:** [vintagebentleys.org](http://vintagebentleys.org/) and the Porsche 928 Owner's Club.

---

### **2. Aviation OSINT**

Aviation OSINT focuses on **Tail Numbers (Registration)** and **ADS-B** radio transmissions.

#### **Official Registries & Directories**

- **Global Directories:** [skytamer.com](https://skytamer.com/) and [airlineupdate.com](https://airlineupdate.com/).
- **Searchable Databases:** [airframes.org](http://airframes.org/) and [airfleets.net](https://airfleets.net/).

#### **Live & Historical Flight Tracking**

- **ADSBExchange:** [adsbexchange.com](https://adsbexchange.com/) (Known for providing unfiltered data).
- **FlightRadar24:** [flightradar24.com](https://flightradar24.com/).
- **FlightAware:** [flightaware.com](https://flightaware.com/) (Excellent for free historical data and future flight plans).
- **OpenSky Network:** [opensky-network.org](https://opensky-network.org/) (Includes a rate-limited API for JSON/CSV data).
- **Icarus Flights:** [icarus.flights](https://icarus.flights/) (Uncensored flight data).
- **Other Trackers:** `planefinder.net` and `radarbox.com`.

#### **Planespotters & Military Resources**

- **Enthusiast Photos:** [planespotters.net](https://planespotters.net/), [jetphotos.com](https://jetphotos.com/), and [planelist.net](http://planelist.net/).
- **Military Specific:** [joebaugher.com](http://joebaugher.com/) (USAF serials) and [scramble.nl](https://scramble.nl/database/military).

#### **Airmen & Pilot Records**

- **AviationDB:** [aviationdb.com](http://aviationdb.com/) (Searchable database for US, Canada, and Australia pilots/mechanics).
- **Federation of Indian Pilots:** [fipindia.com](http://fipindia.com/members.asp).

---

### **3. Maritime OSINT**

Maritime OSINT pivots from **IMO Numbers**, **MMSI**, or vessel names.

#### **Vessel Databases & AIS Tracking**

- **General Tracking:** [vesselfinder.com](https://vesselfinder.com/), [shipfinder.co](https://shipfinder.co/), [marinetraffic.com](https://marinetraffic.com/), and [fleetmon.com](https://fleetmon.com/).
- **Official Records:** [Equasis.org](https://equasis.org/) (Free registration required) and [GISIS (IMO)](https://gisis.imo.org/).
- **Ship Status/History:** [vesseltracker.com](https://vesseltracker.com/), [shipindex.org](https://shipindex.org/), and [Lloyd’s Register](https://lr.org/).
- **USA Specific:** [marinetitle.com](https://marinetitle.com/) and the US Coast Guard AIS search.

#### **Naval & Military Vessels**

- **Military Databases:** [janes.com](https://janes.com/), [russianships.info](http://russianships.info/), and the **US Naval Vessel Register** ([nvr.navy.mil](https://nvr.navy.mil/)).
- **Covert Shores (H.I. Sutton):** [hisutton.com](http://hisutton.com/) (Detailed analysis of submarines and naval developments).
- **Portuguese Navy:** [marinha.pt/pt/os_meios](https://marinha.pt/pt/os_meios).

#### **Crew, Cargo, & Communications**

- **Personnel/Seafarers:** `balticshipping.com`, `maritime-connector.com`, `maritime-union.com`, and `findacrew.net`.
- **Seafarer Credential Verification:** Philippines DOT ([stcw.marina.gov.ph/find](https://stcw.marina.gov.ph/find)) and US Coast Guard.
- **Container Tracking:** [track-trace.com/container](https://track-trace.com/container), [searates.com](https://searates.com/), and [shipup.net](https://shipup.net/).
- **Maritime Radio:** [Broadcastify.com](https://broadcastify.com/) and [Dxzone.com](https://dxzone.com/) (Live VHF feeds).
- **Shodan:** Used to find connected satellite systems like `Inmarsat` or `Cobham Sailor 900`.

---

### **4. Drone OSINT**

Drone (UAS) OSINT is an emerging field focusing on registries and real-time signals.

- **Official Registries:** National civil aviation authorities (like the FAA in the US or CAA in the UK) often regulate UAS and may share commercial licensee data.
- **AviationDB:** Includes UAS operators in its searchable databases for specific countries.
- **External Resource (OpenSky/Network):** While primarily for manned aircraft, some high-altitude or commercial drones transmitting ADS-B can appear on trackers like [OpenSky Network](https://opensky-network.org/).
- **External Resource (DroneID/Remote ID):** Platforms like [Dronetag](https://dronetag.cz/) or [AirBureau](https://airbureau.io/) (and various "Remote ID" receiver projects on GitHub) are used to track drones broadcasting FAA-mandated identification signals (This information is not from the sources and you may want to independently verify it).