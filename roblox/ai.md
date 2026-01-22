this version is the same (i didnt read it but it looks right) just reworded by deepseek.
# Introduction

If you have ever opened the Roblox client in IDA or Binary Ninja, you may have noticed random INT3 instructions scattered throughout the binary.

<img width="648" height="423" alt="INT3 instructions in disassembler" src="https://github.com/user-attachments/assets/c6fa9ee6-245c-4035-b113-119fb0857075" />

Those INT3 instructions are always located where the first branching instruction of every function would normally be. Essentially, the initial branch of each function gets replaced by these breakpoints.

Hyperion emulates the real branch instruction whenever these INT3s are hit. If you want to restore them with the original instructions, you can iterate through an internal array. This array contains both the RVA of each entry and the original instruction data. You can then write the real instructions back.

# Initial Analysis

When you first open the Hyperion protected binary in IDA, you will find that nearly all executable code resides in a .byfron section. Hyperion is not packed and does not use virtualization. So what is actually happening?

Click on almost any function containing control flow, and IDA will likely fail to disassemble it properly. This is Hyperion's most common obfuscation technique. It is easily recognizable by seemingly "fake" instruction sequences that follow specific, repeating patterns throughout the binary. Mixed in is actual dead code that does not contribute to functionality but complicates analysis.

<img width="767" height="362" alt="IDA failing to disassemble obfuscated function" src="https://github.com/user-attachments/assets/29b3690b-0f39-4a4b-8888-199ebece42fa" />

# Module Protection

If you inspect the memory regions of imported modules, you will notice some are not mapped normally.

<img width="362" height="190" alt="Abnormal module mappings in memory" src="https://github.com/user-attachments/assets/bb69b971-434e-4028-8188-0c95ff76ebd8" />

Normally, loaded modules are shared across processes until a write triggers Copy on Write (CoW). Hyperion "protects" certain modules, like NTDLL, by remapping them with the SEC_NOCHANGE flag. This prevents writes and makes CoW impossible. Trying to change page protection on these modules will fail.

Hyperion hooks numerous NTDLL functions (and others) to intercept critical API calls:

<img width="207" height="559" alt="List of hooked NTDLL functions" src="https://github.com/user-attachments/assets/afb39a89-e16f-4de1-be9f-8717de01cdf8" />

# Launch and Initialization

Hyperion gains control before Roblox's main code executes through several mechanisms:

1.  **Pre execution via Windows loader:** Hyperion loads as an entry point DLL. It runs before Roblox's main code to set up protections, encrypt .text, install hooks, and more.
2.  **Manual loading of critical imports:** Important libraries are loaded into custom memory sections with non standard mappings that prevent tampering.
3.  **Instrumentation Callback (IC):** Hyperion registers an undocumented Windows feature that intercepts user mode to kernel mode transitions. This IC monitors threads, manages exceptions, and prevents unauthorized actions.

## What is an IC?

An Instrumentation Callback acts as a middleman between user mode and kernel mode transitions. Hyperion uses it to control thread creation and monitor execution.

One critical event the IC redirects is LdrInitializeThunk. This is the function Windows jumps to when creating a new thread. This gives Hyperion control before the thread's actual start address runs, allowing it to whitelist or terminate threads.

Hyperion's hook on NtCreateThread(Ex) ensures internally created threads pass validation checks. External thread creation attempts are blocked.

## TLS Callback

Hyperion implements TlsCallback_0, which runs even before the DLL entry point. It contains substantial junk code and several anti debug/anti VM checks:

They check for the CPUID leaf 0x40000002, commonly used by hypervisors and VMs:
<img width="509" height="69" alt="CPUID check for hypervisor detection" src="https://github.com/user-attachments/assets/d3803e09-4369-43e1-8f62-00244505298c" />

They also perform user mode hook checks using the GDI buffer (rarely accessed, stable memory):
<img width="778" height="98" alt="GDI buffer hook check" src="https://github.com/user-attachments/assets/6b6a8471-8cc9-406c-bace-b451171c9446" />

If any check fails, NtTerminateProcess is called (interestingly, this function is statically imported):
<img width="684" height="215" alt="NtTerminateProcess call on failure" src="https://github.com/user-attachments/assets/27c3efcb-5594-4da8-b4c8-ee6a33c1fe9b" />

# Hypervisor Detection

Hyperion employs several techniques to detect virtualization:

*   Forces the CPU into 32 bit compatibility mode to execute instructions like CPUID that behave differently under virtualization
*   Uses trap flags in specific registers to cause unconditional VMExits (many hypervisors mishandle this)
*   Leverages #UD (Undefined Instruction) exceptions. Some hypervisors improperly emulate syscall/ret instructions that should normally raise these exceptions

# Protection Mechanisms

## Obfuscation Techniques

Hyperion uses multiple methods to break static analysis:

1.  **Fake instruction sequences:** Repetitive patterns that confuse disassemblers
2.  **Dead code insertion:** Inflates stack frames and obscures real control flow
3.  **Unconditional jumps to decrypted addresses:** Breaks linear code flow, forcing real time emulation to follow execution

## Memory and Import Protection

1.  **Dynamic import encryption:** Import addresses are encrypted and only decrypted when needed
2.  **Memory monitoring:** Hooks on NtProtectVirtualMemory and NtAllocateVirtualMemory restrict executable memory to whitelisted regions
3.  **Dual view memory for syscalls:** Uses separate RW and RX sections to hide code structure
4.  **Hashed import resolution:** Uses Fnv1a 32 hashing for API lookups. Only validated keys are decrypted

## Anti External Access (0AVX)

External cheats often access the same Roblox instances (Players, Humanoid, etc.). Hyperion invalidates these instances and checks if they have been accessed between scheduler iterations.

It uses NtQueryVirtualMemory to see if pages supporting these instances remain in the process's working set. By calling VirtualUnlock, Hyperion removes pages from the working set. If they reappear before the next iteration, it indicates unauthorized access.

According to Microsoft: "The working set of a process is the set of pages in the virtual address space that are currently resident in physical memory." Hyperion exploits this by extracting memory from the working set and checking for unauthorized restoration.

# Dumping and Opaque Predicates

I created a dumper specifically targeting the Hyperion module in memory. It resolves opaque predicates. These are branches that always take the same path but are disguised as conditional.

> ## Example of an opaque predicate
> <img width="698" height="455" alt="Example of opaque predicate in code" src="https://github.com/user-attachments/assets/0625f1b3-32eb-4c7a-baae-bcbe78e89c59" />

# Bypassing Hyperion

Since Hyperion operates entirely in user mode, many checks can be circumvented:

1.  **Abusing the Instrumentation Callback:** The IC is central to many checks. Unmapping Hyperion, placing hooks, and remapping can bypass it.
2.  **Page decryption:** Encrypted pages raise exceptions handled by the IC. Patching internal timers can leave pages unprotected indefinitely.
3.  **Syscall spoofing:** Hook Hyperion's syscalls and return faked data.

Fun fact: There are internal timers controlling how long pages stay unprotected and how often memory scans occur. Patching these alone can give you indefinitely unprotected pages and disable scans.

# Conclusion

Hyperion represents a sophisticated anti tamper solution, especially considering it operates entirely in user mode. While it contains some oversights, reversing and bypassing it requires deep knowledge of Windows internals and significant reverse engineering experience.

The system has successfully disabled previous major executors like Krnl, Synapse X, and Script Ware, demonstrating its effectiveness despite being user mode.
