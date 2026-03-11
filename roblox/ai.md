> *Reworded by Claude*

# Introduction

If you have ever loaded the Roblox client into a disassembler such as IDA or Binary Ninja, you may have noticed what appear to be random INT3 instructions scattered throughout the binary.

These INT3 breakpoints are consistently placed at the location where the first branching instruction of each function would ordinarily appear — in other words, the initial branch of every function has been swapped out for a breakpoint.

Hyperion intercepts each of these INT3 hits and emulates the original branch instruction on the fly. If you want to restore the binary to its original state, you can walk through an internal array that stores both the RVA of each patched location and the original instruction bytes, then write them back.

---

# Initial Analysis

Opening the Hyperion-protected binary in IDA reveals that virtually all executable code lives inside a `.byfron` section. Hyperion is neither packed nor virtualized — so what exactly is going on?

Clicking into almost any function that contains control flow will cause IDA's disassembler to choke. This is Hyperion's most prevalent obfuscation strategy. It manifests as recognizable sequences of seemingly invalid instructions that repeat across the binary in predictable patterns, interspersed with genuine dead code that serves no functional purpose but significantly clutters analysis.

---

# Module Protection

Inspecting the memory regions of imported modules reveals that some of them are not mapped in the standard way.

Under normal circumstances, loaded modules are shared across processes until a write triggers Copy-on-Write (CoW). Hyperion "hardens" select modules — most notably NTDLL — by remapping them using the `SEC_NOCHANGE` flag. This flag prevents any writes and makes CoW impossible. Any attempt to modify page protections on these modules will fail.

Beyond remapping, Hyperion also installs hooks on a wide range of NTDLL functions (and others) to intercept sensitive API calls.

---

# Launch and Initialization

Hyperion establishes control before any of Roblox's own code has a chance to run, using several mechanisms:

1. **Pre-execution via the Windows loader:** Hyperion loads as an entry-point DLL, running ahead of Roblox's main code to configure protections, encrypt the `.text` section, install hooks, and perform other setup tasks.
2. **Manual loading of critical imports:** Key libraries are loaded into custom memory regions using non-standard mappings specifically chosen to resist tampering.
3. **Instrumentation Callback (IC):** Hyperion registers an undocumented Windows mechanism that intercepts every user-mode-to-kernel-mode transition. This callback is used to monitor threads, handle exceptions, and block unauthorized operations.

## What Is an Instrumentation Callback?

An Instrumentation Callback sits between user mode and kernel mode, intercepting transitions in both directions. Hyperion uses it to exert control over thread creation and to monitor execution.

One particularly important event it intercepts is `LdrInitializeThunk` — the function Windows jumps to when spinning up a new thread. By hijacking this, Hyperion gains execution before the thread's real start address runs, giving it the ability to whitelist or terminate threads on a case-by-case basis.

Hyperion's hook on `NtCreateThread(Ex)` ensures that any threads it creates internally pass its own validation. Any attempt to create threads from outside the process is blocked outright.

## TLS Callback

Hyperion implements `TlsCallback_0`, which executes even before the DLL entry point. It contains a heavy volume of junk code alongside several anti-debug and anti-VM checks:

- It queries CPUID leaf `0x40000002`, a value commonly reported by hypervisors and virtual machine monitors.
- It performs user-mode hook detection using the GDI buffer — an area of memory that is rarely accessed but tends to remain stable, making it a reliable baseline.

If any of these checks fail, `NtTerminateProcess` is called. Notably, this function is statically imported rather than resolved dynamically.

---

# Hypervisor Detection

Hyperion employs several techniques to detect whether it is running inside a virtual machine:

- It forces the CPU into 32-bit compatibility mode to execute instructions like `CPUID` that behave differently when virtualized.
- It sets trap flags in specific registers to force unconditional VM exits, then checks whether the hypervisor handles them correctly (many do not).
- It triggers `#UD` (Undefined Instruction) exceptions using `syscall`/`ret` sequences that should raise these exceptions in certain contexts — some hypervisors emulate these incorrectly, exposing their presence.

---

# Protection Mechanisms

## Obfuscation

Hyperion uses several methods to defeat static analysis:

1. **Fake instruction sequences:** Repetitive, patterned byte sequences that mislead disassemblers into producing incorrect output.
2. **Dead code insertion:** Inflates stack frames and buries real control flow under layers of non-functional instructions.
3. **Unconditional jumps to runtime-decrypted addresses:** Shatters linear code flow and forces any analysis tool to emulate execution in real time to follow branches.

## Memory and Import Protection

1. **Dynamic import encryption:** Import addresses remain encrypted at rest and are only decrypted immediately before use.
2. **Memory monitoring:** Hooks on `NtProtectVirtualMemory` and `NtAllocateVirtualMemory` restrict executable memory to a set of pre-approved regions.
3. **Dual-view memory for syscalls:** Separates readable/writable and executable views of the same memory to obscure code structure.
4. **Hashed import resolution:** API lookups use FNV-1a 32-bit hashing. Only entries with validated hashes are decrypted.

## Anti-External Access (0AVX)

External cheats commonly work by reading from the same Roblox object instances (such as `Players` or `Humanoid`). Hyperion counters this by invalidating those instances and checking whether they have been accessed between scheduler iterations.

It uses `NtQueryVirtualMemory` to determine whether the pages backing these instances are still present in the process's working set. By calling `VirtualUnlock`, Hyperion explicitly evicts those pages. If they show up again before the next iteration, that is treated as evidence of unauthorized access.

As Microsoft defines it, a process's working set is the collection of virtual memory pages currently resident in physical memory. Hyperion exploits this by evicting pages and watching for unauthorized restoration.

---

# Dumping and Opaque Predicates

A custom dumper targeting the in-memory Hyperion module was developed specifically to address opaque predicates — conditional branches that are disguised to look like real conditions but always resolve the same way.

---

# Bypassing Hyperion

Because Hyperion runs entirely in user mode, many of its checks are theoretically circumventable:

1. **Abusing the Instrumentation Callback:** Since the IC sits at the center of Hyperion's detection logic, unmapping Hyperion, inserting hooks, and remapping can neutralize it.
2. **Page decryption abuse:** Encrypted pages raise exceptions that the IC normally handles. Patching the internal timers that govern re-encryption can leave pages permanently exposed.
3. **Syscall spoofing:** Hook Hyperion's own syscall invocations and return falsified results.

Of note: internal timers control both how long pages remain unprotected and how frequently memory scans are scheduled. Patching these values alone is enough to obtain indefinitely decrypted pages and fully disabled scanning.

---

# Conclusion

Hyperion is a sophisticated anti-tamper system — particularly impressive given that it operates entirely within user mode. While it has exploitable weaknesses, reversing and bypassing it demands deep familiarity with Windows internals and a substantial investment of reverse engineering effort.

Its effectiveness is demonstrated by the fact that it has successfully neutralized several previously prominent executors, including Krnl, Synapse X, and Script-Ware.
