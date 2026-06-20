# Section3: Sensitive Group Investigations and Video and Image Verification

1. Unique Identifying Labels 
2. OSINTing Sensitive Groups 
3. Image and Video Verification

---

## Topic 1: Unique Identifying Labels

Sensitive groups 
sensitive groups can be defined as groups that have two or more people who are gathered or classed by society that differ from the vast majority (the norm)
Their thoughts or actions are what make us label them as sensitive

%% 
### **1. Defining Sensitive Groups**

Sensitive groups are defined by their desire to **change, influence, disrupt, or dominate** others based on a specific **ideology**. These groups are often categorized by the number of people involved, their location, and how they are classified in society.

In OSINT work, these groups are generally divided into two types:
- **Attackers:** Those who rely on group dynamics to dominate others and do not accept people outside their circle.
- **Victims:** Individuals or groups targeted by attackers.
Understanding the **group dynamics** is vital; often, wars or major conflicts start because different groups refuse to accept each other's existence or beliefs.

---

### **2. Unique Identifying Labels (UILs)**

A core part of this section is the concept of **Unique Identifying Labels (UILs)**. Because humans naturally want to belong to a community, groups create symbols and logos to give their members a sense of acceptance.

#### **What are UILs?**

UILs are logos or symbols found in various places:
- **Physical Items:** Clothing, merchandise, and vehicles.
- **Digital Presence:** Website avatars, social media taglines, and "About Me" pages.
- **Art:** Drawings, graffiti, and propaganda posters.

#### **Where to Find UILs (The Three Formats)**

Analysts look for UILs in three primary media types:
1. **Pictures:** Investigators look for faces (who is with whom), specific logos, and text/comments within or around the photo.
2. **Videos:** Video provides a better perspective than a photo because you can see different angles and hear sounds. Frame-by-frame analysis can reveal small details that might be missed at normal speed.
3. **Text:** Labels can be hidden in hashtags, specific phrasing (verbiage), and the background info of the author. Identifying who posted a message and who replied helps map the **relationships** between group members.

---

### **3. Broadening the UIL Concept (Cyber Intelligence)**

The concept of "labels" isn't just for political groups; it is also used in **Cyber Threat Intelligence (CTI)** and **Malware Analysis**.
- **Malware Analysis:** Analysts look for **uncommon misspellings** in code (like "Recoursive" instead of "Recursive"), which can be a UIL that links a piece of malware to a specific developer or group.
- **Network Intelligence:** Unusual traffic patterns, specific **IP addresses**, and device fingerprint information are all considered UILs.
- **Infrastructure Analysis:** Analyzing the patterns in malicious email infrastructure (like registration fingerprints or domain generation algorithms) is very similar to analyzing how political extremist groups organize online.

### **Summary of the Initial Steps**

Identifying these unique labels allows an analyst to **pivot** from a single piece of evidence to find entire networks of individuals. This process is the foundation for the upcoming labs, where you will use these labels to track sensitive groups across different platforms.

%%

## Topic 2: OSINTing Sensitive Groups 


%% 
### **OSINTing Sensitive Groups**

Sensitive group investigations are conducted worldwide for several critical reasons:
- **Tracking Terrorism:** Monitoring extremist groups to understand their reach.
- **Preventing Attacks:** Identifying threats before they happen.
- **Establishing Correlations:** Finding links between different groups or events.
- **Analyzing Behavior:** Understanding the overall habits and communication styles of a group.

### **Finding the Victims and Their Platforms**

Often, the best way to find "attacker" groups is to find the people they are targeting. Bad actors frequently hide in plain sight, sometimes using their real names or specific "sock puppet" accounts to interact with victims.
- **Popular Apps:** Younger generations are often targeted on mobile apps like **TikTok, Snapchat, Kik, and Instagram**. Because users on these platforms are often more interested in being popular or getting "likes," they may accept friend requests from unknown people, which bad actors exploit.
- **Tracking Trends:** An OSINT analyst must keep track of new and upcoming platforms. This is where both the attackers and the victims can be found.

### **Group Dynamics and Leadership**

Online content is a powerful tool for identifying specific individuals within a group.
- **Leadership Structures:** Almost every group has "leaders" with a large following. Both supporters (like-minded) and opponents (opposites) follow these leaders to stay informed about the group's activities.
- **Organizational Maps:** The sources provide an example of the complex structure used by groups like the **Islamic State**, showing how they divide tasks into departments like technology, weapons, and intelligence cells.

### **The OPSEC Model of Sensitive Groups**

Most groups are aware of the risks of being monitored and use **Operational Security (OPSEC)** to protect themselves.
- **Identity Protection:** They avoid revealing their true identities and often refuse to communicate with members outside of a specific chosen platform.
- **Digital Fingerprinting:** To stay hidden, they may encrypt their messages, periodically shift to new apps, or use tools to blur their digital fingerprint (such as removing metadata and IP addresses).

### **Tools for Finding Popular Apps**

To understand where groups are migrating, analysts look at which apps are trending in specific regions.
- **data.ai (formerly App Annie):** This service helps you see which social networking apps are being downloaded most in a specific country, such as Germany or the US.
- **Applyzer.com:** This is a similar resource that provides ranking data for the App Store. Comparing data from both sites is a standard practice to ensure accuracy. Analysts can even download these results as a **CSV file** for deeper analysis.

### **Echo Chambers and Filter Bubbles**

Groups often live in "Echo Chambers"—online spaces where they only see information that agrees with their existing beliefs.
- **Filter Bubbles:** Algorithms on sites like Facebook and Google create "Filter Bubbles" based on a user's past search history and location. This limits the new information they are exposed to.
- **Targeting:** Disinformation spreads most effectively in these environments because the content is crafted to fit the group’s specific narrative. When targets are reached in their "comfort zone," they are more likely to believe the lie.

### **Hashtags and Recruiting Tactics**

Bad actors use specific tactics to gain reach and find new members:
- **Hashtag Hijacking:** Groups will often use trending hashtags or breaking news topics to spread their own ideology or cause chaos.
- **Gamification:** Recruiting often involves "gamification," where propaganda is made to look like a video game (e.g., using "Call of Duty" style imagery) to attract younger people.
- **Propaganda:** They use high-quality posters, videos, and music to evoke fear or a sense of duty.

### **Legal Considerations**

Before starting any investigation, you must follow the "golden rule": **Always consult legal counsel**. Analysts should ask themselves two questions before pivoting into a new research area:
1. **Can I?** (Do I have the technical skills and tools?)
2. **May I?** (Am I legally allowed to perform this monitoring or privacy-invasive search?).

%%


## Topic 3: Image and Video Verification


Reverse Image Search resources

Google Images https://google.com/images Large set of relevant results, right-click access to reverse search in Chrome browser
Bing Images https://bing.com/images Visual search feature, OCR extraction from images
Yandex Images https://yandex.com/images Visual search feature, OCR extraction of text and links, translation of extracted text
TinEye https://tineye.com/ One of the original reverse image search resources, offers an API (paid service)
Image Identification Project https://www.imageidentify.com/ Identifies objects, project of Wolfram Alpha, AI based tool
Karma Decay http://karmadecay.com/ Reverse image search focused on Reddit
Social Catfish https://socialcatfish.com/reverse￾image-search/ Paid service focused on online dating, offers reverse image search in addition to other tools
PimEyes https://pimeyes.com/en/ Focus on faces and images of people. Service has shifted to a paid access model so no longer free

%% 
### **What Is Image and Video Verification?**

Verification is the process of fact-checking an image or video to determine its **authenticity**, exact **location**, and whether the **narrative** (the story being told) is true. In an era of digital warfare and troll campaigns, analysts must be able to debunk disinformation by looking closely at what can be seen and heard in the footage.

The goal is to find the truth for **accountability** and to understand exactly what happened in a specific event.

---

### **The OSINT Cycle and Methodology**

Like any investigation, verification starts with the **OSINT Cycle**:
1. **Requirements:** Set a specific research question, such as "What is the exact location of this video?".
2. **Gathering:** Find where the footage is hosted and if it is openly accessible.
3. **Analysis:** Use verification techniques to check the data.
4. **Reporting:** Present your findings based on analyzed evidence.

Analysts often use the **"W?" Methodology** to verify footage:
- **Who** took and posted the footage?
- **What** is shown in the content?
- **Where** was it taken and where was it posted?
- **When** was it captured and when was it posted?
- **With what** device was it taken/posted?
- **Why** was it posted (intentions)?

---

### **Reverse Image Searching**

This is a cornerstone of image analysis. It involves using specialized search engines to find identical or similar images online.
- **Google Images:** A well-known tool that uses algorithms to find similar photos.
- **Bing Images:** Features **Visual Search**, which allows you to crop an image after uploading to focus on a specific detail. It can also extract text (OCR).
- **Yandex Images:** Often yields excellent results. Analysts sometimes switch VPN locations to see if the Russian search engine provides different data.
- **TinEye:** One of the original reverse search tools.
- **Karma Decay:** A search engine specifically focused on images shared on **Reddit**.

#### **Browser Extensions**

To speed up the process, analysts use extensions like **Search by Image**, which can check over 30 different search engines at once. Another vital tool is **InVID**, a "Swiss army knife" designed to help journalists and researchers debunk disinformation by analyzing video keyframes and metadata.

---

### **Tradecraft Techniques for Searching**

Sometimes, a standard search doesn't work because the image has too much "noise" (generic items like trees or cars). Analysts use these tricks to get better results:
- **Cropping:** Focus only on a unique landmark, such as a specific tower or building.
- **Flipping/Mirroring:** Rotating or mirroring an image can sometimes help search algorithms recognize the content.
- **Blurring:** Blur out the generic, non-unique parts of a photo to help the algorithm focus on the point of interest while keeping the original color scale.
- **Text Extraction:** Use **OCR** (Optical Character Recognition) to "read" signs, license plates, or street names to find location clues.

---

### **Using Metadata (EXIF)**

Images often contain hidden **EXIF metadata** that includes **timestamps**, camera models, and even **GPS coordinates**.
- **The Challenge:** Most social media platforms automatically strip this data when a photo is uploaded.
- **The Opportunity:** If the data hasn't been removed, it can provide the exact "smoking gun" evidence needed for an investigation.
- **Tools:** **InVID** can extract software and GPS info. On the command line, **ExifTool** is a powerful utility for extracting metadata from large numbers of images at once.

---

### **Temporal and Chronolocation**

**Chronolocation** is the process of determining **when** a photo was taken.
- **Weather History:** Check historical reports to see if the rain or clouds in a photo match the reported conditions for that date and location.
- **Shadows:** If the sun or moon is visible, you can use the angle of the shadows to calculate the approximate time of day.
- **Environment:** Look for clues like seasonal events, construction projects, or the blooming of specific trees.

---

### **Case Study: The Berlin Street**

The sources walk through an investigation of a tweet from "@bayer_julia" asking for a street name.
1. **Initial Search:** A broad reverse image search on Bing initially returned generic tree-lined streets.
2. **Focusing:** Using **Visual Search** to crop the unique tower in the background identified it as the **Berliner Fernsehturm** (Berlin TV Tower).
3. **Geolocation:** By aligning the "sight line" of the street on a map toward the tower, the analyst narrowed the location to **Strelitzer Str.** in Berlin.
4. **Validation:** Using **Google Street View** and satellite imagery confirmed the buildings and landmarks matched the original photo.
5. **Chronolocation:** The clouds in the photo matched historical weather data for mid-May 2020, and the foliage on the trees confirmed it was taken after the spring blooming period.

%%


Reverse video Search 

AutoStitch is a free tool for Windows and Apple macOS that you can use to “stitch” together a series of photos from the same location to generate a panorama

%% 
### **1. Foundations of Video Analysis**

Video analysis is fundamentally similar to image analysis, but it presents a challenge of scale because a video is essentially a sequence of thousands of still images. To analyze video effectively, investigators must "drill down" into the specific frames of interest.

A key technique is transforming video into a **Panoramic Image**. By combining multiple frames, an analyst creates a single overview that provides much better context than any individual capture. This panoramic view makes it easier to identify **Unique Identifying Labels (UILs)**, such as building names, street signs, license plates, and specific clothing.

---

### **2. InVID Video Analysis Tools**

The **InVID browser extension** serves as a "Swiss army knife" for video verification. Its video toolbox offers several critical features:
- **Video Analysis:** By submitting a URL from YouTube, Facebook, or Twitter, the tool extracts contextual metadata, such as the device used for the upload (e.g., "Twitter for iPhone") and direct links to download the raw mp4 file.
- **Metadata Extraction:** This module attempts to extract **EXIF data** from video files, though social media platforms usually strip this information upon upload.
- **Keyframes:** This module uses an algorithm to fragment a video into its most significant or unique still images.
- **User Information:** It displays details about the account that posted the video, including their handle, profile location, and account creation date, which helps assess **source reliability**.

---

### **3. Image Tools for Extracted Frames**

Once keyframes are extracted from a video using InVID, they can be treated as individual images for deeper analysis using right-click tools:
- **Image Magnifier:** To see small details.
- **OCR (Optical Character Recognition):** To extract text from signs or license plates.
- **Image Forensic:** To check for digital manipulation.
- **Reverse Image Search:** To find where else that specific frame or similar footage appears online.

---

### **4. Generating Panoramas with AutoStitch**

After saving unique, overlapping keyframes from InVID, analysts use a tool called **AutoStitch**.
- **Process:** The user selects a folder of extracted frames, and the software automatically aligns and "stitches" them together.
- **Outcome:** This results in a wide panoramic view that can reveal the entire environment of a recorded incident, aiding in geolocation and event reconstruction.

---

### **5. Advanced Automation: Google Video Intelligence API**

Manual analysis does not scale well when dealing with massive volumes of video data. To solve this, analysts can leverage **Artificial Intelligence (AI)** and **Machine Learning (ML)** via the **Google Cloud Video Intelligence API**.

**Capabilities of the API:** The API can automatically process video to detect and track:

- **Faces and People.**
- **Objects and Logos.**
- **Shot/Perspective changes.**
- **Text (OCR) and Speech (transcription).**
- **Explicit content.**

#### **The Workflow for Automated Analysis:**

The course provides a step-by-step process for using this automation:
1. **Clone the Repository:** Download the `video-intelligence-api-visualiser` project from GitHub.
2. **Setup Google Cloud:** Create a Google Cloud account, enable the API, and download a JSON API key file.
3. **Cloud Storage:** Create a "bucket" in Google Cloud Storage and upload the target video.
4. **Python Scripting:** Customize the `run_video_intelligence.py` script with your API key and video location, then execute it.
5. **Visualize Results:** The script produces a JSON annotation file. Both the video and this JSON file are then loaded into a local **Visualiser dashboard** (`index.html`).
6. **Analyze:** The dashboard allows the investigator to click on detected objects or labels to skip directly to the exact timestamp in the video where they appear.

### **6. Practical Demonstrations**

To support these technical steps, SANS provides video walkthroughs by instructor **Nico Dekens**, which demonstrate the application of these tips and tools for real-world image and location verification.

%%


