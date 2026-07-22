The command `grep -v 'email,password' breach.csv` will search the file `breach.csv` and output every line **except** the ones that contain the exact phrase `email,password`.

This is most commonly used to **strip out the header row** of a CSV file before processing the data.

`cut -d, -f2 | sort -u`
- **`cut -d,`**: Uses a comma as the delimiter to split each line into columns.
- **`-f2`**: Selects and extracts only the second field (the password column).
- **`sort`**: Alphabetizes the extracted passwords (required for the next step to work).
- **`-u`**: Removes all duplicate lines, leaving only unique values.

`sort | uniq -c | sort -rn`
- **`sort`**: Groups identical values together (this is a mandatory prerequisite for `uniq`).
- **`uniq -c`**: Collapses identical adjacent rows and prefixes each unique line with its **occurrence count**.
- **`sort -rn`**: Sorts the counted list **numerically (`-n`)** and in **reverse (`-r`)** order, placing the largest numbers at the top.


`grep -i 'kennedy'` investigation-targets.csv to perform a case insensitive search forthe string kennedy in the evidence file investigation-targets.csv



`grep -f search_emails.txt instagram.csv`
search about some emails in csv file


`cat illy-compact.json | json_pp | more`

To suppress that undesired output, use the --raw-output parameter for the jq command
The -c parameter for jq specifies that output be presented in compact form


`jq -c '.data.emails[] | select(.first_name == "Adam") |.......`

---

What is the Python code to save the contents of response object to a JSON file named web_response.json ?

``` python
import json
with open('web_response.json','w') as output_file:
 json.dump(response.json(),output_file)
```


What is the SHA-1 hash value of the file web_response.json ?

``` python
import hashlib
hash = hashlib.sha1()
with open('web_response.json','rb') as file:
 buffer = file.read()
 hash.update(buffer)
print(hash.hexdigest())
```

What are the JSON names (keys) in the response object?
`response.json().keys()`

What is the data type of the value field for the key sites ?
`type(response.json()['sites'])`
How many records are contained in the value field for the key sites ?
`len(response.json()['sites'])`

``` python
# imports from Python Standard Library
import hashlib
import json
# imports from third party modules
import requests
# declare global variables
source_url = 'https://raw.githubusercontent.com/kravp00L/WhatsMyName/master/web_accounts_list.json'
# retrieve JSON data
response = requests.get(source_url)
# store JSON data in file
with open('web_response.json','w') as output_file:
 json.dump(response.json(),output_file)
# create hash value of file
hash = hashlib.sha1()
with open('web_response.json','rb') as file:
 buffer = file.read()
 hash.update(buffer)
print(hash.hexdigest())
# add any desired analysis output below
# print category of item 10
print(response.json()['sites'][9]['category'])
```

---

Load the contents of the 'sites' key from the input_json object into a pandas DataFrame named df_sites

``` python
#imports for pandas library
import pandas as pd
from pandas.io.json import json_normalize
# load into DataFrame and flatten JSON
df_sites = json_normalize(input_json['sites'])
```


---

. What information can you find doing a reverse IP lookup?

. What information can you find by reverse DNS lookup?

. Is the IP address known for being on a spam list?

To find answers to the above questions we suggest that you use the following resources:

https://www.viewdns.info

. https://www.domainbigdata.com
· https://www.google.com






