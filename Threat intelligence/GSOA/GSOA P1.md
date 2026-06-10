# Section1:  Disinformation and Coding for OSINT Efficiency

1. Disinformation and Fake News
2. OSINT Data Types and Data Analysis
3. Understanding JSON
4. Application Programming Interfaces

---
## Topic 1: Disinformation and fake News


Disinformation 
- is information that is being spread on purpose with a specific narrative to influence the reader and it Has some truth and Not 100 % accurate.
- The information is altered or manipulated in such a way that it is tailored to look like an official piece of information, but the purpose is to influence the reader.
- The difference between fake news and disinformation is that disinformation has some truth to it and/or is crafted in such a way as to not be 100% accurate.

Fake news 
- is news that is being spread online that is not true and (100 %) not true and Crafted to influence

---

Information warfare 
- is a need to spread a (manipulated) narrative in pursuit of a competitive advantage over an opponent.
- It can be a technology company trying to gain an advantage over a competitor. It can be a local political party or rebel group trying to spread a certain narrative to make an adversary look bad.

One of the most common forms of information warfare happens in conflict zones and the social/political sphere.

The golden rule to detect disinformation is critical thinking

The Process
Generally, the process to make and spread disinformation or fake news consists of three steps: the **operation**, the **message**, and the **target**.

The **operation** is led by an actor, but this can be a group or individual. The actor will craft a message they want to spread. 
The **message** will have a specific target audience, whether generalized, opposite, or like-minded.
If the operation was successful in meeting the actor's goal(s), the **process** will end. If the process was not successful, the operation can be refined until the actor has reached their goal(s).

The Operation
The operation has the intent to influence the target audience. This can be anything from a single message being spread by a single bot or fake account. It could be an automated army of bots spreading messages and replying to a target group to spread a narrative that attempts to change or influence the target audience. 
In short, the operation is the playbook that is being used by an actor based upon their scope and goals.

the actor
the actor must have access to certain resources to craft their message(s) for the target audience. In that regard, spreading disinformation and/or fake news follows a path similar to that of legitimate marketers and advertisers. They set a goal, gather resources to achieve the goal, and then target the intended audience with the message. The main difference is the motivation

the message
the goal of the campaign and the message is to influence a specific target audience. 
From the actor's perspective, it is essential that the message be crafted to look legitimate.
The wording must be consistent with what the target audience uses and understands. 
The pictures, videos, and overall layout of the message must be in line with what the target audience commonly sees when spending time online within their group or community.
Timing is of great importance, particularly on social media platforms, as the information flow moves rapidly, and a campaign can quickly lose momentum.
The actor needs to know the language, common usage, and how phrases are used by native speakers of that language.

The Target 
It is common tradecraft practice for actors to research where their targets have an online presence. 
Once that is known, they will seek the place or platform (Facebook or Twitter, for example) where the target feels highly comfortable sharing information and communication with like-minded and often trusted other sources.

---
Operation

Actor (official or unofficial)
Organized - how well organized this actor - (Strict, network, loose)
Motivation (Political, Financial)
Automated (manual, bots)
Audience (Individual, group, Society)
Intention (Harm, mislead)


message

Duration (short, long)
Accuracy (Misleading, Manipulated)
Impostor type (Brand, Individual, Group)
Target type (Individual, group, Society)


Target

Like-minded (Ignore, Accept, Support)
Opposite (Ignore, Accept, Support)

---

Psychological Operations (PSYOP)

A PSYOP campaign is in essence running an information warfare campaign against a target (individual, group, organization, government) to influence that target in your favor. 
PSYOP goals are to influence emotions, motives, andobjective reasoning to change the behavior of an adversary.

---

Forms of Disinformation

Impostor
Fabricated
Misleading
Satire
Context
Manipulated

Impostor
Official or genuine sources can be impersonated.
This can be done using Deep Fake computer algorithms, as well as the editing of a photo. 

There are even programs1, 2 that can make a piece of audio sound like someone else’s voice, based upon audio samples of the original living person
https://www.resemble.ai/
https://www.descript.com/regenerate


Fabricated
Information that has been newly made
Fabricated news is, on average, easier to detect since most official sources will not speak or write about the same information.


Misleading
The general purpose of misleading information is to frame someone or something.


Satire
Satire has no intention to cause harm. It is meant to be funny


Context
Genuine information gets shared with a false or manipulated context.
Correct headline
Correct picture
False or manipulated parts
Propaganda


Manipulated
This is most common with images and video. The original footage can be altered or manipulated to deceive


---

How to Examine Images (Pictures / Videos)
Context
Altered – Manipulated – Edited
Staged
Fake/Deep fake
Correct video, wrong narrative


If we sum up the examination of this account, we have found five tells that this might be a fake account and two pieces of information that might tell us that this is not a fake account. The next step could be to examine the overall behavior of this account, rather than the account characteristics

Nonhuman behavior:
Always online (never sleeps)
Instant reply/share/like (bot)
Strange sentence structure or wording
Lack of personal information
No real (human) interaction


Tools and Techniques
Critical thinking
CrowdTangle
Hoaxy
Botometer
Reverse image search
Evaluating websites
Archiving tools


CrowdTangle
CrowdTangle is a tool owned by Meta. CrowdTangle has a free Chrome browser extension that will help you pivot. The extension will give you better insight into how certain links on the internet are being spread and by whom on Facebook, Twitter, Reddit, and Instagram
To use the CrowdTangle Link Checker extension, you must have a Facebook (sock puppet) account. Once installed, you can visit any page on the internet and then open the CrowdTangle Link Checker extension and examine the results.


Hoaxy
Hoaxy is a tool that visualizes the spread of articles online. 
It’s great for pivoting into who spread a certain message and analyzing who connects to whom.


Botometer
Botometer1 is a tool to check if a Twitter account has the characteristics of being a bot or not. The higher the 
score, the more likely it is that the account is a bot


Archiving Tools
Sources like archive.org1, archive.is2, and archive-it.org3 keep archives of pages over years.


Resources for Disinformation and Fake News
Snopes.com
Factcheck.org
Poynter.org
Eufactcheck.eu
Knowyourmeme.com

---

## Topic 2: OSINT Data Types and Data Analysis


However, the data can generally be classified into two types:

Structured data:
Well-defined format
Readily parsed into discrete data elements
OSINT-relevant data retrieved via APIs will typically be returned in a structured format.
JavaScript Object Notation (JSON) data
Delimited data
Relational data

Unstructured data:
Format varies
Parsing is more challenging; is specific to the source


Characteristics of JSON data:
Often seen as data enclosed in curly braces { }
Name/value pairs
Name/value separated by a colon :
Name/value pairs delimited by a comma ,
Values can be numbers, strings, or complex data structures called objects.
Lightweight data interchange format
Language independent
Easy to parse with common tools
Common data format encountered when using APIs


Delimited data
Delimited data is a structured data type with fields separated by a fixed character.
The fields are consistent in number and in sequence.
Data may be enclosed inside double quotes.
This format may include a header row with the field names
Comma-separated values (CSV) is a common format for delimited data.
Database output is commonly in a delimited format.

Relational Data
Relational databases extend the familiar tabular data model.
Data is organized into tables with rows and columns.
Each row is a record, and the columns define the attributes of the record.
Data is typically normalized and stored in multiple tables.
Databases provide concurrency control and support simultaneous use by multiple users.
Relational database systems include MySQL, Oracle, SQL Server, and SQLite.
A lesser common data source for OSINT investigations


timestamp
For consistency, it is strongly recommended to use the ISO 8601 format so that there is no ambiguity as to the month and day position in the date, and the time zone information is included. Normalizing to Universal Coordinated Time (UTC) is a best practice for any type of logging,


Create Cryptographic Hash
Best practice is to use SHA-2, the Secure Hashing Algorithm 2. SHA-2 has an output length of 256 bits, but it can also generate longer outputs. SHA-2 is the successor to SHA-1, which has a fixed output length of 160 bits. 
MD5 is a legacy protocol that has a fixed output length of 128 bits. MD5 has been deprecated but is still commonly used.

---

## Topic 3: Understanding JSON

JSON has multiple 
forms:
A set of name/value pairs delimited by commas enclosed in curly braces
A comma-separated list of values enclosed in square brackets

Compact JSON is stored as a single line, so utilities such as grep, head, or tail are not effective.
`cat illy-compact.json | json_pp` 
It can use the shell pipeline to format the output.

Parsing JSON with jq
`jq <filter> <input_file>`

the dot (.) means that the contents of the file should be displayed without filtering any results
`jq '.' simple.json`

Note the use of a new option for jq [-c ]. This tells jq to use compact output.
CSV data can be read using jq and converted into JSON.

There are many ways to leverage jq to modify data formats:
JSON input to a different JSON output
JSON input to CSV output
CSV input to JSON output
CSV input to CSV output


Note that the input to the @csv operator must be an array—if JSON is passed directly to that operator, it will throw an error.
The -r parameter tells jq to output in raw format. This is necessary when converting to CSV

`jq -r '.sites[] | [.name, .category, .valid] | @csv' Galal.json`


to practice with jq tool: https://play.jqlang.org/


---

## Topic 4:  Application Programming Interfaces (APIs)

APIs hide the complexity of the implementation and focus on what it is that you are asking the software to do

For OSINTers, a RESTful API is often much easier to access and to understand.
RESTful APIs can return data in many different formats, such as JSON, YAML, and XML.

RESTful APIs are stateless:
• There is no memory of previous calls.
• Each call must contain all required information to complete the request


Six constraints must be met if an interface is to be considered RESTful:
1. Client-server 
2. Stateless
3. Cacheable
4. Uniform Interface
5. Layered system
6. Code on demand (optional)


usage of the API may require pre-approval and registration to obtain an API key, and the number of API calls that you make in a given time period may be limited

People-Centric Search APIs
People-oriented paid search providers that provide APIs: FullContact, pipl.
People-oriented paid search providers that do not provide APIs: Intelius, Spokeo
People-oriented free search providers that do not clearly provide APIs: Radaris, ThatsThem, TruePeopleSearch, Xlek, Zabasearch.

Other services with APIs that have OSINT use cases:
• Shodan
• Censys
• Hunter


There are also specialized websites for testing API calls such as https://reqbin.com/ but these should only be used in accordance with your OPSEC requirements. 


Internet Storm Center and DShield
The Internet Storm Center (ISC) is a long-running community service in support of information security. Sponsored by SANS, it features a must-read handler diary that covers current trends and topics in information security. However, attack trends and emerging threats may not be interesting to an OSINT analyst. There are other parts to the ISC that can play a role in OSINT investigations. DShield is a project that collects traffic from sensors around the world and then makes that data available for review and analysis. DShield is a distributed intrusion detection system, so it contains a rich set of network data.


DShield API
The DShield API is a free, unauthenticated API that offers many useful API calls.

The -s option for curl makes the tool run in silent mode, so any messages such as progress bars or status messages are silenced, and only the data is shown. This is a standard practice when making API calls to make sure that the output is only the requested data. 

Adding the -A option to curl customizes the User-Agent string. 


Enumerate all email addresses for a specific domain. > Register for a free account at hunter.io

