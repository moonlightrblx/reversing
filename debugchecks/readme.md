# Bypassing Debugger Checks

So if you're here you're probably stuck crashing or getting a warning because your debugger is getting flagged right? This guide will explain exactly what functions inside of windows handle debug checks and the easiest ways to get around the checks.

---

## The PEB

The PEB is one of the most important Windows structures to know in order to bypass debugging. A majority of anti-debugger functions rely on data from the PEB, more specifically the `BeingDebugged` flag.

So what can we do with this information?

If we look into ReactOS which is a Windows compatible OS and we find the function `IsDebuggerPresent` we will see the function is defined as this:

```cpp
BOOL WINAPI IsDebuggerPresent(VOID)
{
    return (BOOL)NtCurrentPeb()->BeingDebugged;
}
```

> https://github.com/reactos/reactos/blob/08eddb273637e3defe34b7b598e3ff943bead45d/dll/win32/kernel32/client/debugger.c#L580

So how can we abuse this? The first thing you might think is by hooking the function. Though this is a good response to most other checks there are way simpler methods, we can create a simple dll that patches the PEB instead.

```cpp
BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved )
{
    if (fdwReason == DLL_PROCESS_ATTACH) {
        PPEB pPEB = (PPEB)__readgsqword(0x60);
        pPEB->BeingDebugged = 0;
    }
}
```

---

## NtGlobalFlag

Another field inside the PEB worth knowing is `NtGlobalFlag`. When a process is launched under a debugger Windows sets this to `0x70` (a combination of `FLG_HEAP_ENABLE_TAIL_CHECK`, `FLG_HEAP_ENABLE_FREE_CHECK`, and `FLG_HEAP_VALIDATE_PARAMETERS`). Applications can read this directly to detect a debugger without ever calling `IsDebuggerPresent`.

```cpp
PPEB pPEB = (PPEB)__readgsqword(0x60);
if (pPEB->NtGlobalFlag == 0x70) {
    // debugger detected
}
```

The fix here is just as simple as patching `BeingDebugged`:

```cpp
PPEB pPEB = (PPEB)__readgsqword(0x60);
pPEB->NtGlobalFlag &= ~0x70;
```

---

## CheckRemoteDebuggerPresent / NtQueryInformationProcess

`CheckRemoteDebuggerPresent` is a slightly higher level check that works on both the current process and remote processes. Under the hood it calls `NtQueryInformationProcess` with the `ProcessDebugPort` class. If a debugger is attached the kernel returns a non-zero debug port.

```cpp
BOOL bDebugged = FALSE;
CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebugged);
if (bDebugged) {
    // debugger detected
}
```

Because this goes through `ntdll` the cleanest fix is to hook `NtQueryInformationProcess` directly so you control what it returns:

```cpp
typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
    HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

pNtQueryInformationProcess OrigNtQIP = nullptr;

NTSTATUS NTAPI HookedNtQueryInformationProcess(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength)
{
    NTSTATUS status = OrigNtQIP(
        ProcessHandle, ProcessInformationClass,
        ProcessInformation, ProcessInformationLength, ReturnLength);

    if (NT_SUCCESS(status)) {
        if (ProcessInformationClass == ProcessDebugPort) {
            *(PHANDLE)ProcessInformation = 0;
        } else if (ProcessInformationClass == 30) {
            return 0xC0000353;
        } else if (ProcessInformationClass == 31) {
            *(PULONG)ProcessInformation = 1;
        }
    }
    return status;
}
```

To install the hook you can use any inline hooking library (MinHook, Detours, etc.) or write your own trampoline.

---

## Heap Flags

When a debugger is present the heap header also gets modified. Windows sets `Flags` and `ForceFlags` inside the heap structure to non-standard values. Some protections check these directly rather than using any API.

The heap starts at `PEB->ProcessHeap`. On 64-bit the `Flags` field is at offset `0x70` and `ForceFlags` at `0x74`:

```cpp
PPEB pPEB   = (PPEB)__readgsqword(0x60);
PVOID pHeap = pPEB->ProcessHeap;

*(PULONG)((PBYTE)pHeap + 0x70) = 2;
*(PULONG)((PBYTE)pHeap + 0x74) = 0;
```

---

## Putting It All Together

Here is a full self-contained DLL that patches all of the above on attach. Just inject it into the target before or as early as possible during startup.

```cpp
#include <Windows.h>
#include <winternl.h>
#include <MinHook.h>

#pragma comment(lib, "libMinHook.x64.lib")

typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
    HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

pNtQueryInformationProcess OrigNtQIP = nullptr;

static void PatchPEB()
{
    PPEB pPEB = (PPEB)__readgsqword(0x60);

    pPEB->BeingDebugged = 0;
    pPEB->NtGlobalFlag &= ~0x70;

    PVOID pHeap = pPEB->ProcessHeap;
    if (pHeap) {
        *(PULONG)((PBYTE)pHeap + 0x70) = 2;
        *(PULONG)((PBYTE)pHeap + 0x74) = 0;
    }
}

static NTSTATUS NTAPI HookedNtQIP(
    HANDLE              ProcessHandle,
    PROCESSINFOCLASS    ProcessInformationClass,
    PVOID               ProcessInformation,
    ULONG               ProcessInformationLength,
    PULONG              ReturnLength)
{
    NTSTATUS status = OrigNtQIP(
        ProcessHandle, ProcessInformationClass,
        ProcessInformation, ProcessInformationLength, ReturnLength);

    if (NT_SUCCESS(status)) {
        switch ((ULONG)ProcessInformationClass) {
        case 7:
            *(PHANDLE)ProcessInformation = 0;
            break;
        case 30:
            return 0xC0000353L;
        case 31:
            *(PULONG)ProcessInformation = 1;
            break;
        default:
            break;
        }
    }
    return status;
}

static void InstallHooks()
{
    MH_Initialize();

    MH_CreateHookApi(L"ntdll", "NtQueryInformationProcess",
        HookedNtQIP, reinterpret_cast<PVOID*>(&OrigNtQIP));

    MH_EnableHook(MH_ALL_HOOKS);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        PatchPEB();
        InstallHooks();
    } else if (fdwReason == DLL_PROCESS_DETACH) {
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
    }
    return TRUE;
}
```
---

## What's Next

There are more exotic checks worth knowing about — `CloseHandle` with an invalid handle (which throws an exception only under a debugger), `DbgBreakPoint` / `DbgUiRemoteBreakin` thread detection, and timing-based checks using `RDTSC` — but the techniques above cover the vast majority of what you'll run into in the wild. The PEB patches alone will defeat most off-the-shelf protections.
