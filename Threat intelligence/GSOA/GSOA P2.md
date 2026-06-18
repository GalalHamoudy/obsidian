# Section2: Intelligence Analysis and Data Analysis with Python

1. Intelligence Analysis
2. Introduction to Python
3. Python Essentials
4. Open-Source Software and Git
5. Python and the Web
6. Data Analysis with Python

---

## Topic 1: Intelligence Analysis

Source Types

Primary sources:
• Documents, media, or persons with direct knowledge related to the investigative topic
Secondary sources:
• Built upon primary sources
• May be articles, commentaries, or histories


fact
A fact is verified information that is proven to be correct.

facts can be divided into three sections of facts:
1. True – Based upon the goals, scope, and requirements, the gathered information to a specific research question is analyzed to be true.
2. False – Based upon the goals, scope, and requirements, the gathered information to a specific research question is analyzed to be false.
3. Unknown – Based upon the goals, scope, and requirements, the gathered information to a specific research question is analyzed to be unknown. This means the research question cannot be answered based upon this information and analysis, and thus is neither true nor false.


You can always use the four quick scan steps to briefly analyze the gathered information.
1. Examine the source structure. Does it look real or fabricated?
a. Look at the URL/TLD
b. Page layout
c. Overall content
d. Wording
e. Pictures and videos
2. Summarize the claims and supporting data.
a. What is the narrative or message?
b. Is corroborating data available?
3. Scan for compelling items. 
a. What other information has been gathered that confirms or denies this data?
4. Does the information answer research questions?



We analyze two parts for reliability:
1. The source
2. The content

For the source: 
The six reliability rating scores are:
1. A = Reliable
No doubt of authenticity, trustworthiness, or competency; has a history of complete reliability
2. B = Usually reliable
Minor doubt about authenticity, trustworthiness, or competency; has a history of valid information most of the time
3. C = Fairly reliable
Doubt of authenticity, trustworthiness, or competency, but had provided valid information in the past
4. D = Not usually reliable
Significant doubt about authenticity, trustworthiness, or competency, but had provided valid information in the past
5. E = Unreliable
Lacking authenticity, trustworthiness, and competency; history of invalid information
6. F = Cannot be judged
No basis for evaluating the reliability of the source


For the content: 
The are eight potential rating scores you need to look for within that specific piece of content:
1. Confirmed
Confirmed by other independent sources; logical in itself; consistent with other information on the subject
2. Probably true
Not confirmed; logical in itself; consistent with other information on the subject
3. Possibly true
Not confirmed; reasonably logical; agrees with some other information on the subject
4. Doubtfully true
Not confirmed; possible but not logical; no other information on the subject
5. Improbable
Not confirmed; not logical in itself; contradicted by other information on the subject
6. Misinformation
Unintentionally false; not logical in itself; contradicted by other information on the subject; confirmed by other independent sources
7. Deception
Deliberately false; contradicted by other information on the subject; confirmed by other independent sources
8. Cannot be judged
No basis for evaluating the validity of the information

%% 

This section focuses on **Intelligence Analysis**, specifically how to evaluate the information you gather to ensure it is accurate and trustworthy.

### **Why Rate the Reliability of Information?**

To create **actionable intelligence**, you must analyze the information you find for consistency and completeness. Assigning a **reliability rating** is a standard part of investigative work. It helps you identify which sources consistently provide high-quality data and which ones provide false information. While this takes time, it makes your final analysis much stronger.

### **The Evaluation Process**

There is no single "correct" way to analyze information; different types of data require different methods. For example, a social media post is evaluated differently than a formal research paper.

#### **1. Source Types**

- **Primary Sources:** These are original documents or people with direct knowledge of an event (like a photographer at a scene). Analysts must still watch for **bias** in primary sources.
- **Secondary Sources:** These are works that analyze or build upon primary sources, like news articles or books. They can be very useful for finding errors or omissions in the original data.

#### **2. Defining Facts**

A fact is information that has been proven correct. In OSINT, facts are generally divided into three categories:

1. **True:** The information is verified as correct.
2. **False:** The information is verified as incorrect.
3. **Unknown:** The information cannot be proven true or false based on current evidence.

### **The Four Quick Scan Steps**

If you are under time pressure and cannot do a full analysis, you can use these four steps to quickly check a source:

1. **Examine the structure:** Look at the URL, page layout, and wording to see if it looks real or fake.
2. **Summarize claims:** Identify the main message and see if there is supporting data.
3. **Scan for compelling items:** Check if other gathered info confirms or denies this data.
4. **Check research questions:** Does this info actually help answer your specific investigation goals?.

---

### **The Reliability Rating Model (Admiralty/NATO Code)**

Analysts often use a standardized system to rate both the **Source** and the **Content**.

#### **Rating the Source (A-F)**

The source includes both the **platform** (like Twitter) and the **user**.

- **A – Reliable:** No doubt about trustworthiness; has a history of complete reliability.
- **B – Usually Reliable:** Minor doubts, but usually correct.
- **C – Fairly Reliable:** Some doubt, but has provided valid info in the past.
- **D – Not Usually Reliable:** Significant doubt, even if it was correct before.
- **E – Unreliable:** History of invalid information.
- **F – Cannot Be Judged:** No basis for evaluation.

#### **Rating the Content (1-8)**

The content is the actual message being spread.

- **1 – Confirmed:** Logical and confirmed by other independent sources.
- **2 – Probably True:** Logical and consistent with other info, but not confirmed.
- **3 – Possibly True:** Reasonably logical and agrees with some other info.
- **4 – Doubtfully True:** Possible but not logical; no other info exists.
- **5 – Improbable:** Not logical and contradicted by other info.
- **6 – Misinformation:** Unintentionally false.
- **7 – Deception:** Deliberately false.
- **8 – Cannot Be Judged:** No basis for evaluation.

### **Case Study: Social Media Analysis**

The sources provide an example of a tweet from a user named "@sherrycville".

- **Source Platform (Twitter):** Rated as **A (Reliable)** because the platform itself is generally trusted.
- **Source User:** Rated as **D (Not Usually Reliable)**. The user showed "inhuman" behavior, only shared links to biased sources, and many of their followers were identified as bots.
- **Content:** Rated as **7 (Deception)**. Many users tweeted the exact same text at the same time, and Twitter itself flagged the link as unsafe.
- **Combined Rating:** The platform was **A1**, but the specific user and their message were **D7**.

### **Assessment Templates**

It is good practice to use spreadsheets to track your ratings. Templates help you record **why** you gave a specific score so you can revisit it if new information is found later.

### **Confidence Levels**

Because you can never be 100% sure, OSINT reports use **confidence levels** to label judgments:

1. **High Confidence:** Based on high-quality, trustworthy information.
2. **Moderate Confidence:** Information is plausible but lacks enough corroboration for a higher rating.
3. **Low Confidence:** Credibility is questionable, information is fragmented, or sources are problematic.

%%


---

CRAAP Test
For every gathered piece of information, you want to analyze each in detail before putting it in our overall reliability rating model.

Currency - How timely is the information? When was the information published?
Relevance - How important is the information to your analysis?
Authority - What is the source information?
Accuracy - How reliable, truthful, and correct is the content?
Purpose – What is the reason the information exists?


Per question scoring:
1 = Poor
2 = Fair
3 = Good
4 = Very Good
5 = Excellent



Confidence Levels
When you report, you are never 100% sure about the outcome, as things may change over time or when new information becomes available.
1. High confidence
2. Moderate confidence
3. Low confidence


Analysis of Competing Hypotheses (ACH)
Analysis of Competing Hypotheses (ACH) is a structured process to break down a complex analytical problem based on hypotheses that you test for consistency or inconsistency with evidence.

ACH helps you see information from different perspectives and test those perspectives for reliability based on evidence found in the gathered information
When using the ACH process, you identify a set of (alternative) hypotheses, and then you assess whether the gathered data is either consistent or inconsistent with each hypothesis. The more inconsistent a hypothesis is, the more likely it is for you to reject that hypothesis within your research.

ACH excels in: 
• Testing gathered information for relevance before you decide to report on it
• Preventing bias or assumptions from entering your analysis product
• Assessing information for deception
• Approaching a research question from different angles using different hypotheses
• Identifying and highlighting gaps in the gathered information
• Considering many different hypotheses to ensure that potential scenarios have not been overlooked

The ACH Process
Analysis of Competing Hypotheses (ACH) is an eight-step process. If you make these steps a standard operating procedure (SOP), your ACH analysis will be solid and sound.
We can embed the previously discussed reliability rating model and CRAAP test to help us make an even more sound analysis, which leads to actionable intelligence.
1. Produce hypotheses, preferably as many as you can. Research and experience have proven that teams or groups produce more, and higher quality, hypotheses.
2. Make lists or arguments and evidence based upon available gathered information, including assumptions, for and against each hypothesis.
3. Build a matrix (spreadsheet) with hypotheses and evidence.
4. Based on these first findings, refine your hypotheses.
5. Review the hypotheses for (in)consistency and weigh your conclusions.
6. Double-check the reliability and validity of your evidence using a reliability rating and/or CRAAP methodology.
7. Report your conclusions, including the rejected hypotheses.
8. Repeat steps 1 to 7 based on newly gathered information or analytical insights.

%% 

This section continues the discussion on intelligence analysis, focusing on the **CRAAP Test** for evaluating information and the **Analysis of Competing Hypotheses (ACH)** method for testing different theories.

### **1. The CRAAP Test**

The **CRAAP Test** is a detailed checklist used to score the quality of individual pieces of information before they are used in a larger analysis.

- **Currency:** Check if the info is timely. When was it published? Is it outdated for your current investigation?.
- **Relevance:** How important is this info to your specific research question? Is it written for the right audience?.
- **Authority:** Who is the source? Are they credible, and is there evidence to support their background?.
- **Accuracy:** Is the content truthful and verified by other data? Does it contain obvious biases or grammar errors?.
- **Purpose:** Why was this information created? Does the author have a hidden political, religious, or financial motive?.

---

### **2. CRAAP Test Scoring**

To make the analysis transparent, each sub-question in the test is scored from **1 (Poor)** to **5 (Excellent)**.

- **Total Reliability Rating:**
    - **High:** 77–115
    - **Medium:** 39–76
    - **Low:** 0–38. By recording **why** each score was given, analysts can revisit their judgment if new information is found later.

---

### **3. Confidence Levels**

Since OSINT analysts are rarely 100% certain, they use **Confidence Levels** to label their judgments in reports.

- **High Confidence:** Based on high-quality, trustworthy information where the evidence is strong.
- **Moderate Confidence:** The information is credible and plausible, but there isn't enough corroboration to be fully certain.
- **Low Confidence:** The credibility is questionable, the information is too fragmented, or the source has significant problems.

---

### **4. Analysis of Competing Hypotheses (ACH)**

**ACH** is a structured process used to break down complex problems. Developed by CIA veteran **Richard Heuer**, it helps analysts avoid "confirmation bias" (the habit of only looking for info that proves what you already believe).

- **The Concept:** Instead of trying to prove one idea is true, you come up with multiple possible explanations (**hypotheses**) and test them against the evidence.
- **The Goal:** You look for evidence that **disproves** (is inconsistent with) a hypothesis. The hypothesis with the most inconsistent evidence is the one you reject.

---

### **5. The ACH Process**

The ACH method follows an **eight-step process**:

1. **Produce Hypotheses:** Brainstorm as many possible explanations as you can.
2. **List Evidence:** Record arguments and evidence for and against each theory.
3. **Build a Matrix:** Create a grid (spreadsheet) with your hypotheses and evidence.
4. **Refine:** Adjust your hypotheses based on initial findings.
5. **Review for Inconsistency:** Weigh your conclusions based on how much evidence contradicts each hypothesis.
6. **Double-Check:** Use the CRAAP test to re-verify the reliability of your evidence.
7. **Report:** State your conclusions and explain why certain theories were rejected.
8. **Repeat:** If new data appears, go back and update the analysis.

---

### **6. Case Study: The Macron Video**

The sources apply ACH to a viral video involving French President **Emmanuel Macron**.

- **The Incident:** A video circulated on social media appearing to show Macron ending a greeting to the public and then walking away from his computer in his underwear, supposedly having forgotten the camera was still on.
- **The Investigation:** As an analyst, you must examine the YouTube channel (the source) and the video itself (the content).
- **Applying ACH:** Before deciding if it is real, you must brainstorm several hypotheses—such as "the video is genuine," "the video is a deep fake," or "the video is someone else edited to look like Macron"—and then test them against the evidence in the footage.

%%

---


## Topic 2: Introduction to Python


%% 

This section introduces **Python** as a powerful tool for OSINT analysts to automate repetitive tasks and manage the massive amounts of data collected during investigations.

### **1. Unlocking Automation with Python**

While earlier parts of the course showed basic automation using shell utilities, those methods have limitations and may not work on every platform. **Python** is the solution because it is cross-platform and allows analysts to tailor tools to their specific environment. Instead of manually performing every step of a data assessment, Python can be used to automate the entire workflow.

### **2. Python and OSINT**

Data is the lifeblood of OSINT, but collecting and organizing it manually is exhausting. Python is a popular choice for information security professionals because:

- It is **straightforward to use** and easy to learn.
- There is a vast amount of **existing code and documentation** available to reuse.
- It allows you to build custom solutions that pre-built tools might not provide.

### **3. What Is Python?**

Python is a free programming language created by **Guido van Rossum** in 1991. It is an "interpreted" language, meaning the code is readable and easy to understand compared to other languages.

- **Capabilities:** Python scripts can act as a web browser, parse thousands of files, and interrogate DNS servers.
- **Examples:** Tools like **DNSRecon** are written in Python to rapidly retrieve OSINT data, allowing analysts to spend more time on analysis rather than collection.

### **4. Using Python 3**

The course emphasizes using **Python 3**.

- **Python 2 Sunsetting:** Python 2 reached its "end of life" in January 2020, meaning it no longer receives security updates or bug fixes.
- **Standardization:** While some old projects still require Python 2, all new OSINT projects should use Python 3.

### **5. How to Get Python**

Python 3 is often **preinstalled** on Linux and macOS. Windows users can download it from the official website.

- **Checking the Version:** You can check your version by typing `python3 --version` in a terminal. For the work in this course, any version **3.6 or higher** is sufficient.

### **6. Course Goals for Python**

The goal of this course is **not** to turn you into a professional software developer. Instead, the focus is on being a **"code hacker"** who can:

1. **Decode** what a script does by reading it.
2. **Piece together** code snippets to achieve specific goals.
3. **Alter** existing scripts to work on target sites or retrieve data in a specific format.

### **7. Understanding and Customizing Others' Code**

Most Python code is written to be comprehensible. By opening a script in a text editor, you can learn new OSINT techniques, extract useful URLs, and validate if the code is safe to run. Many people share their code publicly on platforms like **GitHub**, **GitLab**, and **Bitbucket**. You can take these tools, extend them with features your team needs, and even contribute your improvements back to the community.

### **8. Python Modules and the Standard Library**

Python is built on a **modular design**. This means you don't have to write code for every task from scratch; you can "import" modules that others have already built.

- **The Standard Library:** These are modules that come pre-packaged with Python for tasks like networking, file access, and data compression.
- **Useful OSINT Libraries:** Some of the most common standard libraries you will use include:
    - **json:** To encode and decode JSON data.
    - **csv:** To read and write CSV files.
    - **hashlib:** To create secure hashes (like SHA-256) for evidentiary integrity.
    - **argparse:** To allow your scripts to accept command-line arguments.
    - **datetime:** To handle timestamps correctly.

%%


---

## Topic 3: Python Essentials

While Python supports these styles, it is recommended in the PEP 8 standard that you use lowercase words for your variable and function names. If you need to use multiple words in the name, separate the lowercase words with underscores.

%% 

Continuing from the previous section, here is the explanation for executing Python code and the essential concepts needed for OSINT automation.

### **Methods for Executing Python Commands**

There are two primary ways to run Python code: using an interactive interpreter or running a script from a file.

- **The Interactive Interpreter:** This is a mode where you type commands one by one and see immediate results. It is identified by a distinctive `>>>` prompt. This environment stays active until you type the `exit()` command.
- **IPython Shell:** This is an enhanced version of the default Python shell. It is much friendlier for analysts because it offers features like **Syntax Highlighting**, **Tab Completion** for commands, and a **Command History** that allows you to reuse previous entries easily. It also provides "Contextual Help" if you add a `?` to the end of a command.
- **Executing a Command Directly:** You can run a single Python command directly from your terminal using the `-c` flag (e.g., `python3 -c 'print("Hello World")'`).
- **Executing a Python File:** This is the most common method for OSINT work. Commands are saved in a file ending in `.py` and executed by typing `python3 filename.py` in the terminal. You can also pass specific parameters, such as a target domain, which the script will use during its operation.

---

### **Python Essentials for OSINT**

To automate OSINT tasks, you need to understand how Python represents and groups data.

#### **1. Variables and Naming**

Variables are used to store information so you can use it later in your script. They are created the moment you assign a value to them.

- **Naming Standards:** While Python is flexible, the course follows the **PEP 8 standard**, which recommends that variable names be all **lowercase** with words separated by **underscores** (e.g., `target_first_name`).

#### **2. Data Types and Objects**

Python uses several basic data types that should match the information you are collecting:

- **Integers:** Whole numbers.
- **Floats:** Decimal numbers.
- **Strings:** Text characters, which can be held in either single or double quotes.
- **Booleans:** Values that are either `True` or `False`.

In Python, these are all considered **objects**. Every object has **methods**, which are built-in functions used to manipulate that specific object.

---

### **Data Structures: Lists and Dictionaries**

Managing large collections of OSINT data requires specific structures.

#### **1. Lists**

A list is a collection of items separated by commas and held inside **square brackets `[ ]`**.

- **Flexibility:** A single list can contain a mix of different types, such as strings, integers, and even other lists.
- **Indexing:** Every item in a list has a position called an **index**. The first item is always at **index 0**, and the last item can be quickly reached using **index -1**.
- **Slicing:** You can extract a range of items by using a colon (e.g., `my_list[0:2]`).
- **Modification:** Lists are "mutable," meaning you can add items using `.append()`, insert them at specific spots, or delete them using the `del` command.

#### **2. Dictionaries**

Dictionaries are better than lists for complex OSINT data because they store information in **key/value pairs** inside **curly braces `{ }`**.

- **Direct Access:** Unlike a list, you don't have to search through everything to find a value; you can retrieve it directly by its "key" name (e.g., searching for 'phone' to get the number).
- **Widespread Use:** Dictionaries are extremely common in OSINT because they mirror the structure of **JSON data** used by web APIs.
- **Usage:** You can retrieve a value using `dict[key]`, modify it by assigning a new value to that key, or remove it using `del`.

---

### **Containers and Iteration**

"Containers" is a general term for objects like lists and dictionaries that store other objects. **Iteration** is the process of going through everything inside a container to perform a task.

- **The 'For' Loop:** Analysts frequently use `for` loops to process collections. For example, a script might take a list of 1,000 usernames and use a loop to check each one against various social media sites one by one.
- **Iterating Dictionaries:** When looping through a dictionary, you can choose to look at just the **keys**, just the **values**, or **both** at the same time.

### **Summary of Core Concepts**

Understanding **variables**, **data types**, **lists**, **dictionaries**, and **loops** provides the foundation for effective data analysis. These elements allow an OSINT analyst to handle the massive flood of information encountered during modern investigations through customized automation.

%%



---

## Topic 4: Open-Source Software and Git


%% 

Continuing from our previous discussion, this section introduces **Git** and **GitHub**, which are essential tools for finding, downloading, and managing the OSINT scripts and software created by the global research community.

### **1. Git Version Control**

**Git** is an open-source "version control" system. While it was originally created for software developers to collaborate on code, it is incredibly useful for OSINT analysts.

- **Purpose:** It tracks changes in files and allows multiple people to work on the same project without overwriting each other's work.
- **Key Goals:** The creators of Git focused on making it **fast**, **simple** in design, and **distributed** (meaning every user has a full copy of the project history).

### **2. Why OSINT Analysts Use Git**

Most OSINT analysts are not professional programmers, but they still need to know how to use Git because:

- **Tool Access:** Many of the best OSINT tools and scripts are hosted in public **code repositories**.
- **Customization:** If you find a script on Git, you can download it and modify it to fit your specific investigation needs.

### **3. Installing Git**

Git is available for all major operating systems:

- **Linux/macOS:** It is often pre-installed. If not, it can be added easily using package managers like `apt` or `brew`.
- **Windows:** You can download a graphical installer or use a package like **GitHub Desktop**.

### **4. GitHub and Repositories**

**GitHub** is a website that hosts millions of Git "repositories" (folders containing code and documentation).

- **Interaction:** You can interact with GitHub through the command line (most common), the website, or a desktop application.
- **Searching:** You can use the GitHub search bar to find specific tools, such as a "Snapchat map scraper".

### **5. Key Git Operations**

To use Git effectively, you should understand a few basic commands:

- **`git clone`:** This is the most important command for analysts. It downloads a complete copy of a repository from the internet to your local computer.
- **`git init`:** Creates a brand-new repository.
- **`git add` & `git commit`:** These are used to save changes you make to your local files.
- **`git push`:** Sends your local changes back to a remote server (like GitHub).

### **6. How to Clone a Repository**

Downloading a tool from GitHub usually follows these steps:

1. **Find the URL:** On the project page, click the green **"Code"** button and copy the URL ending in **`.git`**.
2. **Run the Command:** Open your terminal, type `git clone`, and paste the URL.
3. **Result:** A new folder will appear on your computer containing all the tool's files.

### **7. "Some Assembly Required" (The README File)**

Simply downloading the code is often not enough to make it work. Most repositories include a file called **`README.md`**.

- **Importance:** This file contains the "instruction manual" for the tool. It tells you how to install dependencies and how to run the script.
- **Evaluation:** A tool with a poor or missing README might be too difficult or risky to use in a professional investigation.

### **8. Updating Your Tools**

Code on GitHub changes frequently as developers fix bugs or add features. Your local copy does **not** update automatically.

- **`git fetch`:** Checks the remote repository for any changes.
- **`git pull`:** Downloads those changes and merges them into your local files.

### **9. GitHub Pitfalls to Avoid**

While GitHub is a treasure trove of tools, you must be careful:

- **No Quality Guarantee:** Just because code is "open source" does not mean it is high quality or that it works correctly.
- **Malicious Code:** Anyone can post to GitHub. You should always read through a script to ensure it isn't designed to steal your data or infect your system before running it.

%%




---

## Topic 5: Python and the Web


%% 

This section explains how to use **Python** for the full lifecycle of OSINT data: from retrieving it from the web to storing and validating it for your investigation.

### **The OSINT Automation Process**

While previous lessons focused on assessing data already on your computer, this part introduces a complete **Model OSINT Automation Process**. The workflow follows these steps:

1. **Select Data Source:** Identify where the target information lives.
2. **Perform Web Call:** Use code to "fetch" the data from the internet.
3. **Save and Hash:** Store the output in a file and immediately create a digital fingerprint (hash) to prove the data hasn't been changed.
4. **Verify:** Check the file type and ensure the hash matches before performing your final analysis, such as keyword searches or record counts.

---

### **Making Web Requests with Python**

To get data from the web, analysts use the **Requests** library. While Python has built-in tools for this, the third-party `requests` module is much more popular because it is easier to read and use.

- **How it works:** You "import" the library and use a command like `requests.get('URL')`.
- **Beyond Text:** When you make a call, Python doesn't just get the text of a page; it creates a **Response Object**. This object contains:
    - **Status Code:** (e.g., 200 means success, 404 means not found).
    - **Headers:** Metadata about the web server and the data sent.
    - **Content:** The actual data (HTML, images, or JSON).
    - **JSON:** If the source is an API, you can use `.json()` to automatically turn the data into a Python dictionary.

---

### **Handling and Validating Data**

Once you have retrieved information, you must handle it professionally to ensure it can be used as evidence.

#### **1. Writing to Disk**

You can save API results directly to a file using only a few lines of code. This ensures you have a local copy of the evidence that you can analyze offline without making repeated calls to the web server.

#### **2. Calculating Hashes**

Integrity is vital in OSINT. Using the **`hashlib`** library, you can create a **SHA-256 hash** of your saved file. By recording this hash immediately after download, you can prove later that your analysis did not accidentally modify the original evidence.

#### **3. Verifying File Types**

Bad actors sometimes try to hide files by giving them the wrong extension (like naming a script "image.jpg"). The **`python-magic`** library identifies a file by its internal "magic bytes" rather than its name, allowing you to verify exactly what you downloaded.

---

### **Python vs. Shell Scripting: The Hunter API**

The course compares the Linux shell script created earlier for the **Hunter.io API** with a new Python version.

- **Why switch to Python?** Linux shell scripts only run on Linux. **Python is cross-platform**, meaning the same script will work for a team using a mix of Windows, Mac, and Linux computers.
- **The Python Approach:** While the Python script is longer, it is more "extensible" (easier to add new features to). It uses three main components:
    1. **`argparse`**: To let the user type the target domain (like `illy.com`) directly into the terminal when running the script.
    2. **`requests`**: To handle the connection to the Hunter.io servers.
    3. **`json`**: To format the messy web data into a "pretty-printed" version that is easy for a human to read.

### **Section Summary**

Collecting and storing data correctly is the foundation of OSINT. By using Python libraries like `json`, `hashlib`, and `requests`, an analyst can build a fully automated system that fetches data, proves its integrity, and organizes it for analysis. This approach is much faster and more reliable than manual copy-pasting.

%%


## Topic 6: Data Analysis with Python

One of the core data elements in the pandas library is the DataFrame. This is a row and column-based data structure, which lends itself to set operations. That means that even large sets of data can be quickly processed



%% 

This section of the course covers **Data Analysis with Python**, focusing on how specialized libraries make it much easier and faster to analyze OSINT data compared to standard programming methods.

### **Introduction to Data Analysis with Python**

While Python’s standard library is great for fetching and saving files, it has limitations when it comes to deep analysis. Replicating a simple Linux command like `sort | uniq -c` (which counts how many times each item appears) using only basic Python requires complex nested loops.

For large data sets, these basic loops are "computationally expensive," meaning they are slow and use too much computer power. To solve this, analysts use **Data Science techniques** to load and process information more efficiently.

---

### **Using Data Science Libraries**

Python is the most popular choice for data science because it is easy to use and has massive libraries specifically designed for analysis. Using these tools is essential for OSINT analysts to progress their investigations.

**Key libraries include:**

- **NumPy:** For advanced math.
- **pandas:** The most important tool for OSINT analysis, designed to handle large, complex data sets.
- **Jupyter/IPython:** Environments for writing and sharing interactive code.

---

### **The pandas Library and DataFrames**

The **pandas** library is the ideal solution for OSINT because it can handle very high volumes of data. Its core feature is the **DataFrame**, which is a row-and-column structure that looks and acts like a spreadsheet. Because it uses "set operations," it can process thousands of records almost instantly.

#### **1. Loading CSV Data**

Loading a spreadsheet into pandas is a simple one-line operation using `pd.read_csv()`. Even if a file has thousands of lines, pandas automatically recognizes the **header row** (column names) and separates them from the actual data records.

#### **2. Loading and Flattening JSON**

JSON data often has "nested" values (information hidden inside other information). To analyze this in a spreadsheet format, pandas uses a process called **flattening** or **normalization**. The `json_normalize()` function converts these nested values into their own columns in the DataFrame.

---

### **Analyzing Data with pandas**

Once data is in a DataFrame, you can perform powerful assessments with very little code.

- **Inspecting Data:** You can use `.head()` to see the first few rows or `.tail()` to see the last few.
- **Counting Records:** The `len()` function tells you exactly how many rows of data you have. Analysts should avoid using `.size`, as that counts every single individual piece of data (rows multiplied by columns) rather than the number of records.
- **Unique Values:** The `.unique()` function extracts a list of all unique items in a column (like every unique password in a breach file).
- **Frequency Counts:** The `.value_counts()` function creates a histogram, showing which values appear most often. You can even use `normalize=True` to see the **percentage** of times a value occurs rather than just the raw number.

---

### **Searching and Querying Data**

The `.query()` method allows you to search across your data using logic. You can use familiar Python string methods like:

- **`startswith()`**: To find emails beginning with "ant".
- **`endswith()`**: To find accounts from specific regions, like ".kr".
- **`contains()`**: For a broad search of any keyword in any position.
- **Searching Lists:** You can load a text file full of keywords into a Python list and have pandas loop through your data to find matches for every word in that list automatically.

---

### **Data Transformation**

A major part of OSINT is **enriching** your data by breaking it down into more useful parts.

- **Splitting Columns:** You can take an email address and use `.str.split('@')` to separate the **username** from the **domain**.
- **Creating New Columns:** You can then save these separate parts into brand new columns in your DataFrame, making the data much easier to filter or use in other tools.

---

### **Saving Your Results**

After you have cleaned and enriched your data, saving it back to your computer is a simple step.

- **`to_csv()`**: Saves the data as a spreadsheet.
- **`to_json()`**: Saves the data as a JSON file.

---

### **Advanced Operations: Joins**

A "Join" is a technique used to connect two different data sources based on a common value. **Example:** If you have one file containing Instagram users and another file containing Twitter users, you can "join" them using their email addresses as the common link. This allows you to instantly see which people have accounts on both platforms and groups their identities together.

---

### **Section Summary**

Python provides the flexibility to fully automate the OSINT data lifecycle. While the standard library handles basic file operations, third-party libraries like **requests** (for fetching web data) and **pandas** (for analysis) provide the high-performance tools needed for modern investigations. By tailoring these scripts to specific data sources, an analyst can significantly enhance their investigative efficiency.


Continuing from the summary of Section 2, the following explanation covers the detailed **Python Appendices**, which provide the specific coding skills needed for OSINT automation, focusing on strings, numbers, and collections (lists and dictionaries).

### **1. Appendix: Python Strings**

Strings are sequences of characters, including letters, numbers, and symbols, typically held within single (') or double (") quotes. Analysts use many built-in "methods" to manipulate this text:

- **Changing Case:** You can use `.upper()`, `.lower()`, `.capitalize()`, or `.title()` to standardize text (e.g., making all usernames lowercase for consistent searching).
- **Concatenation:** To join strings together, you can use the `+` sign or the `.join()` method. For example, joining a username string with a domain string to create a full email address.
- **Searching Strings:**
    - **`find('x')`**: Returns the position of a character.
    - **`startswith()` and `endswith()`**: Return `True` or `False` based on the start or end of the string.
    - **`'substring' in string`**: A simple way to check if a specific word exists inside a larger block of text.
- **Indexing and Slicing:** Every character has a number (index) starting at **0**. You can use `` to get the first character or `[-1]` to get the last.
- **"IS" Tests:** Methods like `.isdigit()`, `.isalpha()`, or `.islower()` allow you to test if a string consists only of numbers, letters, or lowercase characters.
- **Essential Utilities:**
    - **`len()`**: Returns the total number of characters.
    - **`replace()`**: Swaps a specific character or word for another.
    - **`strip()`**: Removes extra white space or specific characters from the beginning or end of a string.
- **Printing:** The `print()` function displays output. Using **f-strings** (e.g., `print(f'Hello {name}')`) is a powerful way to embed variables directly into text.

---

### **2. Appendix: Python Numeric Types and Booleans**

Automation often requires mathematical calculations or logical decision-making.

- **Numbers:** Python supports **Integers** (whole numbers) and **Floating-point numbers** (decimals).
- **Math Operators:** Beyond basic addition and subtraction, analysts use:
    - **`**`**: Exponents (raising to a power).
    - **`//`**: Floor division (returns the whole number, dropping the remainder).
    - **`%`**: Modulo (returns only the remainder, useful for finding patterns in data).
- **Booleans:** Variables set to `True` or `False`. These can be combined using logical operators: **`and`**, **`or`**, and **`not`**.

---

### **3. Appendix: Python Collections**

Collections are "containers" used to store multiple pieces of data together.

#### **Lists**

A list is a sequence of items separated by commas inside square brackets `[ ]`.

- **Nesting:** Lists can contain other lists or dictionaries, creating complex structures.
- **Modification:** You can change items using their index, add to the end with `.append()`, or remove items with the `del` command.
- **Membership:** Use `in` to check if an item is in a list, or `.count()` to see how many times it appears.
- **Sorting:** You can use `.sort()` to permanently change the order or `sorted()` to create a sorted copy.

#### **Dictionaries**

Dictionaries are better for complex OSINT data because they store information in **key/value pairs** inside curly braces `{ }`.

- **Efficiency:** Unlike lists, you don't need to loop through everything to find a value; you can retrieve it directly using its unique "key" (e.g., `dict['phone']`).
- **Keys and Values:** Keys are usually strings or numbers, while values can be any Python data type, including nested lists or even other dictionaries.
- **Accessing Data:**
    - **`.keys()`**: Returns a list of all labels.
    - **`.values()`**: Returns a list of all data entries.
    - **`.items()`**: Returns both keys and values as **tuples** (immutable sequences).

---

### **4. Widespread Use of Dictionaries and JSON**

Understanding dictionaries is the most critical skill for modern OSINT automation because they mirror **JSON data**.

JSON (JavaScript Object Notation) is the standard format for data returned by most web **APIs** (like Twitter, Shodan, or Hunter.io). Since JSON is built on name/value pairs, Python can instantly turn it into a dictionary. This allows an analyst to fetch messy data from the web and immediately use Python's dictionary methods to extract exactly what they need, such as an email address or a location coordinate, with very little code.


%%


