Credits to Archie-osu for this paper :D (i just reformatted)
# Inside Riot Vanguard's Dispatch Table Hooks

*Oct 10, 2025*

[Riot Vanguard](https://support-valorant.riotgames.com/hc/en-us/articles/360046160933-What-is-Vanguard) is an anti-cheat system developed by Riot Games for their first-person shooter [VALORANT](https://playvalorant.com). Unlike other popular anti-cheat solutions ([EasyAntiCheat](https://www.easy.ac), [Battleye](https://www.battleye.com/)), the anti-cheat driver is loaded at boot time. By loading this early in the boot process, Vanguard can inspect every driver loaded after Windows boots. This is a luxury that other anti-cheats lack, as they typically launch alongside the protected game.

On top of that, Vanguard places several hooks all throughout the kernel to get notified of certain events happening. This article, while not an exhaustive list of Vanguard’s protections, aims to document some of the techniques I observed during analysis.

---

## The SwapContext hook

While doing research for my recent projects I came across an article about Vanguard’s ["Guarded Regions"](https://reversing.info/posts/guardedregions/), a mechanism made to hide memory from untrusted threads.

Naturally, this caught my interest. By that point, I had already reversed most of the ETW functions, so I figured I’d install Vanguard and check all of them for patches.

Not seeing anything out of the ordinary at first, I dug deeper into how `nt!SwapContext` works. It didn’t take long to find another possible hook point, directly below the ETW call I had targeted previously.

![KiClearLastBranchRecordStack being executed](https://raw.githubusercontent.com/Archie-osu/Archie-osu.github.io/refs/heads/master/_images/vanguard/context_swap_hook.png)

`nt!KiClearLastBranchRecordStack` is a wrapper for a function pointer inside the `HalPrivateDispatchTable`. This table is simply a structure full of function pointers, which a hardware abstraction layer (HAL) can override to implement optional functionality. Despite the name, its address is exported by `ntoskrnl`, which means that accessing it is as simple as declaring its existence in your driver:

```cpp
extern "C" __declspec(dllimport) HAL_PRIVATE_DISPATCH HalPrivateDispatchTable;
````

Moreover, the table is stored in the `.data` section, which means that it’s not only writable by default, but also not protected by Kernel Patch Protection. The function is also exclusively called from the `nt!SwapContext` method, which simplifies the work on Vanguard’s end. Furthermore, the function is called after the context switch is largely complete, with only one stack frame between the potential hook and `nt!SwapContext`. The hook can also be easily managed by toggling the second least-significant bit of `nt!KiCpuTracingFlags` — the kernel will invoke our hook only if the bit is set.

After setting up the `KiCpuTracingFlags`, breakpointing inside `nt!KiClearLastBranchRecordStack` reveals everything we need to know. The old thread is stored in the `rdi` register, and the new, current thread, is stored inside `rsi`:

```text
Breakpoint 0 hit
nt!KiClearLastBranchRecordStack:
fffff801`cdde59d0 4883ec28        sub     rsp,28h

; Listing the current thread
kd> .thread
Implicit thread is now ffffc289`5df22080

; Listing the registers - notice the current thread is stored in rsi.
kd> r rsi, rdi
rsi=ffffc2895df22080 rdi=ffffc2895a49f040

; Dumping the old thread's stacktrace
kd> !thread rdi
THREAD ffffc2895a49f040
Child-SP          RetAddr               : Call Site
ffff8506`8f96a830 fffff801`cdc0ca92     : nt!KiSwapContext+0x76
ffff8506`8f96a970 fffff801`ce0800af     : nt!KiDispatchInterrupt+0x152
ffff8506`8f96a9a0 fffff801`cddcec62     : nt!KiDpcInterrupt+0x39f
ffff8506`8f96ab30 fffff801`61a2e880     : nt!KzLowerIrql+0x22
ffff8506`8f96ab60 00000000`00000000     : 0xfffff801`61a2e880
```

Verifying the above is rather straightforward. Launch the game, and take a look at `KiCpuTracingFlags`. You’ll see it being set to `2` upon game launch, with the corresponding `HalPrivateDispatchTable` entry now pointing to a location within `vgk.sys` instead of inside `ntoskrnl.exe`.

Upon closing the game, the changes are reverted, and context swaps are unhooked. Out of curiosity, I tried reverting the changes made by Vanguard. Interestingly, Vanguard didn’t attempt to restore its hook, and let me play a game of Deathmatch without any issues.

![VALORANT running without a context switch hook](https://raw.githubusercontent.com/Archie-osu/Archie-osu.github.io/refs/heads/master/_images/vanguard/running_unhooked.png)

---

## System call hook

While scouring several cheating forums, I came across [a particular post](https://www.unknowncheats.me/forum/3703499-post7606.html) hinting at the existence of a system call hook.

Looking at `nt!KiSystemCall64`, I found two possible execution paths, both of which depended on a variable:

* `nt!KiDynamicTraceMask` leading to a call to `nt!KiTrackSystemCallEntry`
* `nt!PerfGlobalGroupMask` leading to a call to `nt!PerfInfoLogSysCallEntry`

I read the values of both variables when the game wasn’t running, launched the game, and read their values again. `KiDynamicTraceMask` was left unchanged with a value of `0`, but the latter one had changed to a value of `64` — the exact value needed to make the kernel log system calls via `nt!PerfInfoLogSysCallEntry`. This is the same function responsible for allowing ETW hooks to take place.

Suspecting I might’ve missed something, I decided to take another look at the `HalPrivateDispatchTable`. I did so by scanning the entire structure for addresses that pointed into `vgk` memory:

```cpp
const auto target_address = Sym::GetSymbol("nt!HalPrivateDispatchTable");

// Read the entire HalPrivateDispatchTable from kernel memory
HAL_PRIVATE_DISPATCH hal_private_dispatch = {0};
if (NT_SUCCESS(Hv::HvReadMemory(target_address, hal_private_dispatch)))
{
    // Scan the entire struct for pointers into VGK
    for (auto ptr = reinterpret_cast<UINT64*>(&hal_private_dispatch);
         ptr < reinterpret_cast<UINT64*>(&hal_private_dispatch + 1);
         ptr++)
    {
        if (IsAddressWithinModule("vgk.sys", *ptr))
        {
            size_t current_offset = GetOffsetFromVA(&hal_private_dispatch, ptr);
            printf(
                "[!] HalPrivateDispatchTable+0x%llX = 0x%llX (vgk.sys+0x%llX)",
                current_offset,
                *ptr,
                *ptr - vgk
            ); 
        }
    }
}
```

The checks ended up tripping twice, and the program produced the following output:

```text
[!] HalPrivateDispatchTable+0x248 = 0xFFFFF80A3D3F4A10 (vgk.sys+0x14A10)
[!] HalPrivateDispatchTable+0x400 = 0xFFFFF80A3D44C090 (vgk.sys+0x6C090)
```

The second result was expected — that’s the `HalClearLastBranchRecordStack` hook covered earlier. It was the first line that caught my attention. At offset `0x248`, there is a function pointer called `HalCollectPmcCounters`. Looking up the variable’s name led me to a [well-known article](https://revers.engineering/fun-with-pg-compliant-hook/) by [Aidan Khoury](https://x.com/aidankhoury) and [Daax](https://x.com/daaximus).

The article details a PatchGuard-compliant system call hook — *using this exact function*.

![Coincidence?](https://raw.githubusercontent.com/Archie-osu/Archie-osu.github.io/refs/heads/master/_images/vanguard/coincidence.jpg)

---

## An unforeseen extension?

Originally, this article would’ve wrapped up right about now. But as I was preparing to publish this article, I saw a [new comment](https://x.com/panchoszczcur/status/1910476868173602958) pop up on my last Twitter post.

Motivated to bring something new to the table, I decided to reexamine some of Vanguard’s hooks. To my knowledge, the information below has **never been shared in public**. I know this is a very bold claim, but over the entire course of my research, I have not seen anyone give a full list of hooked system calls.

As discussed in the previous section, Vanguard hooks system calls using a very similar method to the one described in [Aidan Khoury’s and Daax’s article](https://revers.engineering/fun-with-pg-compliant-hook/). This can be confirmed by looking at Vanguard’s replacement for `HalCollectPmcCounters`:

```cpp
// Argument names taken from https://revers.engineering/fun-with-pg-compliant-hook/
void vgk::HalCollectPmcCounters_Hook(
    IN INT64 PerformanceCounterData,
    IN PWORD TraceBufferEnd
)
{
    InterlockedIncrement64(
        &g_ThreadsInsideHalCollectPmcCountersHook
    );

    if (g_OriginalHalCollectPerformanceCounters)
    {
        g_OriginalHalCollectPmcCounters(PerformanceCounterData, TraceBufferEnd);

        // Check that we have a trace buffer, and that it contains the special "hook ID".
        // If it does, we can swap the syscalls.
        if (TraceBufferEnd && *(TraceBufferEnd - 5) == 0xF33)
            vgk::HandleSyscall(_AddressOfReturnAddress(), 0xF3300501802ui64);
    }

    InterlockedDecrement64(
        &g_ThreadsInsideHalCollectPmcCountersHook
    );
}
```

Once the function verifies that the call to `HalCollectPmcCounters` originates from a system call, the function calls `HandleSyscall` to actually do the hooking.

I’ll be omitting some of the code from here on out, as it is not important to the article. Looking at the `HandleSyscall` routine, we see something similar to this:

```cpp
BOOLEAN vgk::HandleSyscall(
    IN PCHAR Caller,
    IN UINT64 Token
)
{
    // Omitted some stack management code for clarity.
    // 'Token' is used there.
    UNREFERENCED_PARAMETER(Token);

    const auto RspBase = KeGetCurrentPrcb()->RspBase;
    if (Caller > RspBase)
        return FALSE;

    // This is a method that I made up.
    // VGK pulls the address from the stack using the omitted code.
    // CalledMethod would be a pointer / reference to the target function address on the stack.
    auto &CalledMethod = GetCalledMethodFromStack(Caller);

    switch (CalledMethod)
    {
    // Ntoskrnl functions
    case g_NtFunctions.NtAllocateVirtualMemory:
        CalledMethod = Hook_NtAllocateVirtualMemory;
        break;
    case g_NtFunctions.NtFreeVirtualMemory:
        CalledMethod = Hook_NtFreeVirtualMemory;
        break;
    case g_NtFunctions.NtMapViewOfSection:
        CalledMethod = Hook_NtMapViewOfSection;
        break;
    case g_NtFunctions.NtSuspendThread:
        CalledMethod = Hook_NtSuspendThread;
        break;
    case g_NtFunctions.NtSuspendProcess:
        CalledMethod = Hook_NtSuspendProcess;
        break;
    // Win32k functions
    case g_W32kFunctions.NtUserSendInput:
        CalledMethod = Hook_NtUserSendInput;
        break;
    case g_W32kFunctions.NtGdiBitBlt:
        CalledMethod = Hook_NtGdiBitBlt;
        break;
    case g_W32kFunctions.NtGdiGetPixel:
        CalledMethod = Hook_NtGdiGetPixel;
        break;
    case g_W32kFunctions.NtGdiDdDDIPresent:
        CalledMethod = Hook_NtGdiDdDDIPresent;
        break;
    case g_W32kFunctions.NtGdiDdDDIOutputDuplGetFrameInfo:
        CalledMethod = Hook_NtGdiDdDDIOutputDuplGetFrameInfo;
        break;
    case g_W32kFunctions.NtUserGetWindowDisplayAffinity:
        CalledMethod = Hook_NtUserGetWindowDisplayAffinity;
        break;
    default:
        // Don't replace CalledMethod.
        return FALSE;
    }
    return TRUE;
}
```

Given how long this article already is, I will only cover one function for now — the rest may come in a future post. For no particular reason, I went to reverse the `NtSuspendProcess` handler, as I was curious what processes are prevented from being suspended.

Below is an excerpt from the hook:

```cpp
NTSTATUS vgk::NtSuspendProcessHook(
    IN HANDLE ProcessHandle
)
{
    // Same variable is used for all hooked methods.
    InterlockedIncrement64(
        &g_ThreadsInsideSyscallHooks
    );

    // Encryption using XOR was omitted for all function calls including this one.
    // An example of the encryption: Value = *(g_XorStuff_7F530[0] ^ g_XorStuff_7F538[byte_7F529]);
    PEPROCESS current_process = PsGetCurrentProcess();
    PEPROCESS referenced_process = nullptr;
    NTSTATUS result = STATUS_SUCCESS;

    // Yes, I double-checked, this is really what they seem to do.
    //
    // If anyone knows under what condition this actually trips,
    // I'd be interested to know. 
    if (*PsProcessType == *PsThreadType)
    {
        PETHREAD referenced_thread = nullptr;

        if (!NT_SUCCESS(ObReferenceObjectByHandle(
            ProcessHandle,
            PROCESS_ALL_ACCESS,
            *PsThreadType,
            KernelMode,
            &referenced_thread,
            nullptr
        )))
        {
            result = STATUS_ACCESS_DENIED;
            goto exit;
        }

        referenced_process = IoThreadToProcess(referenced_thread);
    }
    else
    {
        result = ObReferenceObjectByHandle(
            ProcessHandle,
            PROCESS_ALL_ACCESS,
            *PsProcessType,
            KernelMode,
            &referenced_process,
            nullptr
        );

        // First check seems unnecessary.
        // Maybe a by-product of their obfuscation?
        if (*PsProcessType != *PsProcessType || !NT_SUCCESS(result))
        {
            result = STATUS_ACCESS_DENIED;
            goto exit;
        }
    }

    ObDereferenceObject(referenced_process);

    // Redacted.
    if (!RunSomeChecks(current_process, 0) && RunSomeChecks(referenced_process, 0))
    {
        result = STATUS_ACCESS_DENIED;
        goto exit;
    }

    // Forward the call to the original function.
    result = g_NtFunctions.NtSuspendProcess(ProcessHandle);

exit:
    InterlockedDecrement64(
        &g_ThreadsInsideSyscallHooks
    );
}
```

---

## Conclusion

Originally, I set out to explore how Vanguard protects the game’s memory from being copied via `nt!MmCopyVirtualMemory`, as I had come across [numerous posts](https://www.unknowncheats.me/forum/4305290-post1.html) discussing this behavior.

However, I was unable to reproduce it — my test driver could read VALORANT’s memory just fine using that function. That said, I only tried reading the process’s [PEB](https://en.wikipedia.org/wiki/Process_Environment_Block) and the MZ header of the main executable. For all I know, the protection may only be applied to actual game structures, such as the `UWorld` instance.

To wrap this up, I think it’s important to note that Vanguard’s protections go beyond what I’ve detailed above. I may revisit this topic in the future, but given the current time constraints, this is all I’ve got for now.

As always, I applaud you, the reader, for making it this far. **Stay tuned for next time.**

