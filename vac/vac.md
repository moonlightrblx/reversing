I deliberately omitted **two critical modules** (you'll need to figure out which ones), as I want others to put in the effort to reverse-engineer them independently. Be warned: attempting to bypass VAC is far more complex than it seems. You’ll likely encounter multiple undocumented security measures that I won’t cover here.

It took **48 hours** to reverse-engineer and compile the details in this post (focusing solely on the modules). The information may not be entirely precise but is close to accurate. I only reversed what was necessary for my purposes, making educated guesses about less relevant sections.

The data was verified by analyzing module outputs, giving a solid overview of VAC module capabilities. This post only includes modules streamed to me—there may be others. Feel free to share additional findings in the comments.

---

## 🧩 Module Breakdown

---

### **0x3E40 – Process Handle Scanner**
- Lists processes using `EnumProcesses`.  
- Employs `CreateToolhelp32Snapshot` and `Process32FirstW` to map process IDs to their parent processes.  
- Uses `NtQuerySystemInformation(SystemHandleInformation)` to check for open handles across processes.  
- Collects:  
  - Process start time.  
  - Process file path.  
- Focuses on gathering data about active processes and their handles.

---

### **0x10E0 – Integrity Checker**
Contains two subroutines.

#### Subroutine 1
1. Scans disks using:  
   - `FindFirstVolumeW`, `GetVolumeInformationW`, `CreateFileW`.  
   - Searches for a specific **SerialNumber**.  
2. Opens files by ID via `OpenFileById` and validates them with `WinVerifyTrust`.

#### Subroutine 2
- Collects process module and thread data:  
  - Uses `Module32FirstW` and `Thread32First`.  
  - For modules: Extracts NT headers, file path, and name.  
  - For threads: Retrieves start address via `NtQueryInformationThread(ThreadQuerySetWin32StartAddress)`.  
- Dynamically inspects DLL memory pages (e.g., `client.dll`, `engine2.dll`, `gameoverlay64.dll`).

---

### **0x12B0 – CPU Profiler**
- Queries CPUID using:  
  - `0x40000000` (hypervisor details).  
  - `0x80000000` (CPU specifics).

---

### **0x16E0 – Debug Detector**
- Accesses `KSHARED_USER_DATA` for anti-debugging checks.  
- Inspects `NtCurrentTeb()->ProcessEnvironmentBlock->BeingDebugged`.  
- Applies XOR to the result.

---

### **0x1050 – System Profiler**
A comprehensive module gathering extensive system and process information.

#### Functions Used:
- `GetVersion`, `GetNativeSystemInfo`, `NtQuerySystemInformation` with:  
  - `SystemTimeOfDayInformation`  
  - `SystemCodeIntegrityInformation`  
  - `SystemDeviceInformation`  
  - `SystemKernelDebuggerInformation`  
  - `SystemBootEnvironmentInformation`  
  - `SystemRangeStartInformation`  
- Retrieves process path (`GetProcessImageFileName`) and system directory (`GetSystemDirectoryW`).  
- Collects disk data via:  
  - `GetFileInformationByHandleEx(FileIdBothDirectoryInfo)`  
  - `GetVolumeInformationByHandleW` (serial number).

#### Additional Actions:
- Accesses `ntdll` to locate syscall IDs for:  
  - `NtReadVirtualMemory`  
  - `NtQueryVirtualMemory`  
  - `NtOpenProcess`  
  - `NtQuerySystemInformation`  
- Lists volumes using `FindFirstVolumeW` / `FindNextVolumeW`.  
- Hashes volume details: name, serial number, filesystem type, and flags.  
- Opens the game’s process handle and stores its ID.  
- Captures command-line arguments.  
- Logs runtime using `KSHARED_USER_DATA`.

---

### **0x1150 – Module Mapper**
- Reads the PEB of a remote process to list loaded DLLs.  
- Captures section details:  
  - Name  
  - Raw size  
  - Characteristics  
  - Virtual address  
- Likely hashes sections (in-memory or on-disk) and sends them to the server.

---

### **0x1340 – System Identity**
Includes three subroutines.

#### Subroutine 1
Gathers:  
  - MD5 hashes (possibly of executable sections).  
  - SID via `GetTokenInformation`.  
  - Executable directory path.  
  - Command-line arguments.

#### Subroutine 2
- Traverses a path backward, collecting for each parent folder:  
  - File ID.  
  - Volume serial number.

#### Subroutine 3
- Scans all files in a folder, collecting:  
  - Name  
  - Attributes  
  - ID  
  - Creation time  
- Locates `steam.exe`, retrieves its PID.  
- Uses `OpenProcessToken` → `GetUserProfileDirectoryW`.  
- Hashes the parsed username.

---

### **0x3330 – Boot Config Reader**
- Queries registry:  
  - `BCD00000000\Objects{00000000-0000-0000-0000-000000000000}\Elements\00000000`  
- Identifies entries containing **“Windows 10”** (typically `1200004`).  
- Extracts bootloader details (e.g., `winload.efi` path, GUIDs).

---

### **0xB290 – Embedded Code Loader**
- Decrypts a byte array.  
- Verifies it with CRC32.  
- Executes the resulting code.

---

### **0xE50 – Process Data Sender**
Reference: [VAC – Process Information (and more)](https://www.unknowncheats.me/wiki/Va...ion_(and_more))

- Maps a memory section and transmits it to the server.  
- Currently fails with error `0x1D2` (possibly disabled or outdated).

#### Decompiled Code:
```c
section = (void *)OpenFileMappingW_(4, 0, section_guid);
if (!section) {
  v4 = ((int (*)(void))import_table->GetLastError)();
  if (v4 != 2) {
    *(DWORD *)(output + 0x30) = 0x1B8;
    goto LABEL_39;
  }
  v34[1] = 4;
  v34[0] = 2;
  section = (void *)recursive_NtQueryDirectoryObject(section_guid, Directory, 0, (int)v34);
  if (!section) {
    *(DWORD *)(output + 0x30) = 0x1D2;
    goto LABEL_39;
  }
  v3 = input;
}
v22 = (int (__stdcall *)(void *, int, _DWORD, _DWORD, _DWORD))MapViewOfFile_(section, 4, 0, 0, 0);
MapViewOfFile_ = v22;
if (v22) {
  memcpy((_BYTE *)(output + 0x18), (int)v22 + 0x18, 0xFE8);
  *(DWORD *)(output + 0x24) = *(DWORD *)(v3 + 0x60);
  v23 = *(DWORD *)(v3 + 0x60);
  v4 = 0;
  *(DWORD *)(output + 0x28) = v23;
  UnmapViewOfFile_(MapViewOfFile_);
}
```

---

### **0xF7F0 – Driver & Service Enumerator**

#### Services
- Uses:  
  - `OpenSCManagerA`  
  - `EnumServicesStatusW` (type: 0xB, state: 0x1)  
- Collects:  
  - Path name  
  - Display name  
  - Load order group  
- Compares against hash `0xDC8AF399`.  
- On failure, aborts and discards output.

#### Drivers
- Uses:  
  - `NtOpenDirectoryObject`  
  - `NtQueryDirectoryObject`  
- Gathers driver object names.  
- Tracks the number of drivers and services processed.

---

### **0xF80 – Plug-and-Play Device Scanner**

Collects data on connected devices and their identifiers.

#### Steps:
1. **Retrieve Device List**  
   ```cpp:disable-run
   HDEVINFO hDevInfo = SetupDiGetClassDevsA(
       NULL, NULL, NULL,
       DIGCF_PRESENT | DIGCF_ALLCLASSES
   );
   ```

2. **List Devices**  
   ```cpp
   while (SetupDiEnumDeviceInfo(hDevInfo, index, &devInfo)) {
       // …
   }
   ```

3. **Extract Properties**  
   - Description:  
     `SetupDiGetDeviceRegistryPropertyA(..., SPDRP_DEVICEDESC, ...)`  
   - Hardware IDs:  
     `SetupDiGetDeviceRegistryPropertyA(..., SPDRP_HARDWAREID, ...)`

4. **Parse Identifiers**  
   - Extracts:  
     - Vendor ID (VID_xxxx)  
     - Product ID (PID_xxxx)  
     - Class code (CC_xx)

5. **Remove Duplicates**  
   - Skips devices with matching `(VID, PID, CC)` tuples.

6. **Store Data**  
   - Each entry is 8 bytes:  
     - `[ type_flag | class_code ]`  
     - `[ vendor_id (WORD) ]`  
     - `[ product_id (WORD) ]`
