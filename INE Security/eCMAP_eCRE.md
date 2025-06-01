All Files :
1- ASCII (plain text) files 
- .txt .html .xml
2- Structured (binary) files

Malware modify itself (Polymorphism)

---
Here are the **most important values** in the **PE File Header** and **Optional Header** (without deep technical explanations):

### **1. File Header (IMAGE_FILE_HEADER)**
Key fields in the `IMAGE_FILE_HEADER` (located after the **DOS stub** and PE signature):
- **`Machine`** → CPU architecture (e.g., `0x014C` = x86, `0x8664` = x64).
- **`NumberOfSections`** → How many sections (e.g., `.text`, `.data`) the PE has.
- **`TimeDateStamp`** → Compilation timestamp (useful for forensics).
- **`PointerToSymbolTable`** → Rarely used (debugging symbols).
- **`NumberOfSymbols`** → Rarely used.
- **`SizeOfOptionalHeader`** → Size of the next header (critical for parsing).
- **`Characteristics`** → Flags (e.g., `0x0002` = Executable, `0x2000` = DLL).

### **2. Optional Header (IMAGE_OPTIONAL_HEADER)**
Critical fields (even though it's "optional," it’s **always present** in executables):
#### **Standard Fields (First 9 fields)**
- **`Magic`** → `0x010B` (PE32), `0x020B` (PE32+ for 64-bit).
- **`AddressOfEntryPoint`** → **RVA** of the first executed instruction (OEP).
- **`ImageBase`** → Preferred load address (e.g., `0x00400000` for EXEs).
- **`SectionAlignment`** → Alignment in memory (e.g., `0x1000`).
- **`FileAlignment`** → Alignment on disk (e.g., `0x200`).

#### **Windows-Specific Fields**
- **`MajorOperatingSystemVersion`** → Minimum OS version required.
- **`SizeOfImage`** → Total size of the loaded PE in memory.
- **`SizeOfHeaders`** → Size of all headers (DOS + PE + Section headers).
- **`Subsystem`** → `1` = Native, `2` = GUI, `3` = Console.
- **`DllCharacteristics`** → Flags (e.g., `0x0040` = ASLR enabled).

#### **Data Directories**
- **`NumberOfRvaAndSizes`** → Number of data directories (always `16` in PE).
- **`DataDirectory[16]`** → RVAs & sizes of critical tables (e.g., Imports, Exports, Relocations).

### **Most Important Data Directories (Indexes)**
1. **`0` Export Directory** → For DLL exports.
2. **`1` Import Directory** → Lists imported functions (critical for analysis).
3. **`2` Resource Directory** → Icons, strings, menus, etc.
4. **`5` Base Relocation Table** → Needed if ASLR relocates the PE.
5. **`9` TLS Directory** → Thread Local Storage callbacks (malware abuse).
6. **`14` CLR Runtime Header** → For .NET executables.

### **Quick Summary**
| Header Part          | Critical Fields                          | Why It Matters? |
|----------------------|------------------------------------------|----------------|
| **File Header**      | `Machine`, `NumberOfSections`, `Characteristics` | Defines arch, sections, and type (EXE/DLL). |
| **Optional Header**  | `AddressOfEntryPoint`, `ImageBase`, `Subsystem` | Where execution starts, load address, GUI/Console. |
| **Data Directories** | Imports (`[1]`), Exports (`[0]`), Relocs (`[5]`) | Key for reversing, patching, and malware analysis. |

These values are the **bare minimum** needed to understand a PE file’s structure and behavior. For deeper analysis (e.g., malware reversing), you’d examine sections, imports, and relocations next.

---

In the **PE (Portable Executable)** file format, the **Sections** contain the actual data used by the executable at runtime. Each section has a specific purpose, such as storing code, data, or resources. Below are the most important **standard sections** found in PE files:

---

### **1. `.text` (Code Section)**
- Contains **executable code** (machine instructions).
- Marked as **readable and executable** (RX).
- Typically the largest section in most executables.
- Sometimes called `CODE` (in older compilers).

---

### **2. `.data` (Initialized Data)**
- Stores **initialized global and static variables**.
- Marked as **readable and writable** (RW).
- Contains values explicitly defined in the program (e.g., `int x = 5;`).

---

### **3. `.rdata` (Read-Only Data)**
- Contains **read-only data**, such as:
  - String literals (`"Hello, World!"`).
  - Constants (`const int y = 10;`).
  - Import/export directory tables (in some cases).
- Marked as **read-only** (R).

---

### **4. `.idata` (Import Directory)**
- Stores **imported functions** (DLL dependencies).
- Contains **Import Address Table (IAT)** and **Import Name Table (INT)**.
- Used by the loader to resolve external function calls.
- Sometimes merged with `.rdata`.

---

### **5. `.edata` (Export Directory)**
- Contains **exported functions** (for DLLs).
- Lists functions that other executables can call.
- Not always present (only in DLLs/exports-aware executables).

---

### **6. `.reloc` (Relocation Table)**
- Stores **address fix-up information** for loaded DLLs/EXEs.
- Used if the executable cannot load at its preferred base address (**ASLR**).
- Critical for **DLLs** (since multiple DLLs may conflict in memory).

---

### **7. `.rsrc` (Resources)**
- Contains **embedded resources** such as:
  - Icons, bitmaps, dialogs.
  - Version information, menus.
  - Embedded files (e.g., executables inside executables).
- Accessed via Windows API (`FindResource`, `LoadResource`).

---

### **8. `.bss` (Uninitialized Data)**
- Stores **uninitialized global/static variables** (e.g., `static int x;`).
- Occupies no space on disk (just a placeholder in memory).
- Marked as **readable and writable** (RW).

---

### **9. `.tls` (Thread Local Storage)**
- Used for **thread-local variables** (data unique to each thread).
- Relevant in multithreaded applications.

---

### **10. `.pdata` (Exception Handling)**
- Contains **structured exception handling (SEH)** data (x64).
- Used for stack unwinding during exceptions.

---

### **11. `.debug` (Debug Information)**
- Contains debugging symbols (if not stripped).
- Used by debuggers (e.g., PDB files in Windows).



### **Key Notes:**
- Not all sections are present in every PE file (depends on compiler/linker settings).
- Some sections can be merged (e.g., `.idata` into `.rdata`).
- Malware often uses **custom section names** (e.g., `.malz`, `.crackme`) to evade detection.


---
[ "Yara roles" Learn and practice it ]

source 1 : [Yara document](https://yara.readthedocs.io/en/latest/)
source 2 : [Try hack me](https://tryhackme.com/hacktivities/search?page=1&kind=rooms&searchText=yara)

- **Awesome YARA Rules** ([https://github.com/InQuest/awesome-yara](https://github.com/InQuest/awesome-yara))
    - Collection of high-quality YARA rules to study and modify.
- **YaraRules Project** ([https://github.com/Yara-Rules/rules](https://github.com/Yara-Rules/rules))
    - Open-source YARA rules for malware families (good for learning patterns).
---

# EFLAGS Register
1- status flags : OF,SF,ZF,AF,PF,CF

SCAS,CMPS,LOOP use ZF flag
"repe cmpsb" compare two strings

2- control flag DF
 \= 1 the string instructions auto decrement  (0 by std )
 \= 0 the string instructions auto increment (0 by cld )
 