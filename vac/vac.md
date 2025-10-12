I deliberately excluded **two key modules** (you'll have to deduce which ones), as I want others to invest effort in reverse-engineering them. Be cautioned: bypassing VAC is much trickier than it appears. You'll likely run into several hidden security mechanisms that I won’t discuss here.

It took **48 hours** to reverse-engineer and document the details in this post (focused only on the modules). The information may not be fully accurate but is close. I only analyzed what was necessary for my goals, making informed assumptions about less relevant sections.

The data was validated by examining module outputs, providing a clear picture of VAC module functions. This post covers only the modules I received—there could be others. Feel free to share additional discoveries in the comments.

---

## 🧩 Module Overview

---

### **0x3E40 – Process Handle Monitor**
- Scans processes using `EnumProcesses`.  
- Utilizes `CreateToolhelp32Snapshot` and `Process32FirstW` to link process IDs to parent processes.  
- Employs `NtQuerySystemInformation(SystemHandleInformation)` to detect open handles across processes.  
- Collects:  
  - Process creation timestamp.  
  - Process file path.  
- Focuses on gathering details about running processes and their handles.

---

### **0x10E0 – Validation Module**
Includes two routines.

#### Routine 1
1. Examines disks using:  
   - `FindFirstVolumeW`, `GetVolumeInformationW`, `CreateFileW`.  
   - Searches for a specific **SerialNumber**.  
2. Opens files by ID with `OpenFileById` and verifies them using `WinVerifyTrust`.

#### Routine 2
- Gathers process module and thread information:  
  - Uses `Module32FirstW` and `Thread32First`.  
  - For modules: Extracts NT headers, path, and name.  
  - For threads: Retrieves start address via `NtQueryInformationThread(ThreadQuerySetWin32StartAddress)`.  
- Dynamically reads DLL memory pages (e.g., `client.dll`, `engine2.dll`, `gameoverlay64.dll`).

---

### **0x12B0 – CPU Identifier**
- Queries CPUID with:  
  - `0x40000000` (hypervisor data).  
  - `0x80000000` (CPU details).

---

### **0x16E0 – Anti-Debug Mechanism**
- Accesses `KSHARED_USER_DATA` for anti-debug checks.  
- Examines `NtCurrentTeb()->ProcessEnvironmentBlock->BeingDebugged`.  
- Applies XOR to the output.

---

### **0x1050 – System Data Collector**
A robust module capturing extensive system and process information.

#### Functions Used:
- `GetVersion`, `GetNativeSystemInfo`, `NtQuerySystemInformation` with:  
  - `SystemTimeOfDayInformation`  
  - `SystemCodeIntegrityInformation`  
  - `SystemDeviceInformation`  
  - `SystemKernelDebuggerInformation`  
  - `SystemBootEnvironmentInformation`  
  - `SystemRangeStartInformation`  
- Retrieves process path (`GetProcessImageFileName`) and system directory (`GetSystemDirectoryW`).  
- Collects disk info via:  
  - `GetFileInformationByHandleEx(FileIdBothDirectoryInfo)`  
  - `GetVolumeInformationByHandleW` (serial number).

#### Additional Actions:
- Queries `ntdll` to identify syscall IDs for:  
  - `NtReadVirtualMemory`  
  - `NtQueryVirtualMemory`  
  - `NtOpenProcess`  
  - `NtQuerySystemInformation`  
- Enumerates volumes using `FindFirstVolumeW` / `FindNextVolumeW`.  
- Hashes volume data: name, serial number, filesystem type, and flags.  
- Opens the game process handle and stores its ID.  
- Captures command-line arguments.  
- Tracks execution time via `KSHARED_USER_DATA`.

---

### **0x1150 – Section Inspector**
- Reads a remote process’s PEB to list loaded DLLs.  
- Captures section details:  
  - Name  
  - Raw size  
  - Characteristics  
  - Virtual address  
- Likely hashes sections (in-memory or on-disk) and reports to the server.

---

### **0x1340 – Identity Tracker**
Contains three routines.

#### Routine 1
Collects:  
  - MD5 hashes (possibly of executable sections).  
  - SID via `GetTokenInformation`.  
  - Executable folder path.  
  - Command-line arguments.

#### Routine 2
- Traverses a path backward, gathering for each parent folder:  
  - File ID.  
  - Volume serial number.

#### Routine 3
- Scans all files in a folder, collecting:  
  - Name  
  - Attributes  
  - ID  
  - Creation time  
- Identifies `steam.exe` and retrieves its PID.  
- Uses `OpenProcessToken` → `GetUserProfileDirectoryW`.  
- Hashes the parsed username.

---

### **0x3330 – Boot Config Extractor**
- Queries registry:  
  - `BCD00000000\Objects{00000000-0000-0000-0000-000000000000}\Elements\00000000`  
- Locates entries with **“Windows 10”** (typically `1200004`).  
- Extracts bootloader details (e.g., `winload.efi` path, GUIDs).

---

### **0xB290 – Embedded Code Executer**
- Decrypts a byte array.  
- Validates it with CRC32.  
- Runs the resulting code.

---

### **0xE50 – Process Data Transmitter**
Reference: [VAC – Process Information (and more)](https://www.unknowncheats.me/wiki/Va...ion_(and_more))

- Maps a memory section and sends it to the server.  
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

### **0xF7F0 – Driver & Service Scanner**

#### Services
- Uses:  
  - `OpenSCManagerA`  
  - `EnumServicesStatusW` (type: 0xB, state: 0x1)  
- Collects:  
  - Path name  
  - Display name  
  - Load order group  
- Checks against hash `0xDC8AF399`.  
- On error, terminates and discards output.

#### Drivers
- Uses:  
  - `NtOpenDirectoryObject`  
  - `NtQueryDirectoryObject`  
- Gathers driver object names.  
- Counts drivers and services processed.

---

### **0xF80 – Plug-and-Play Device Enumerator**

Collects details on connected devices and their identifiers.

#### Process:
1. **Fetch Device List**  
   ```cpp:disable-run
   HDEVINFO hDevInfo = SetupDiGetClassDevsA(
       NULL, NULL, NULL,
       DIGCF_PRESENT | DIGCF_ALLCLASSES
   );
   ```

2. **Enumerate Devices**  
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

5. **Deduplicate**  
   - Ignores devices with identical `(VID, PID, CC)` tuples.

6. **Store Data**  
   - Each entry is 8 bytes:  
     - `[ type_flag | class_code ]`  
     - `[ vendor_id (WORD) ]`  
     - `[ product_id (WORD) ]`
```
