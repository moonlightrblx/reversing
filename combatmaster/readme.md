# Bypassing Combat Master’s Anti-Debug

*December 11, 2025*

Everything below is from the current live build (12/11/25).

### Direct Call to IsDebuggerPresent

Search the main executable (`CombatMaster.exe`) for the string “kernel32.dll” (or just scan imports).  
You will find this exact sequence in `.text`:

```asm
.text:0000000140C14B28                 call    cs:__imp_IsDebuggerPresent
.text:0000000140C14B2E                 test    eax,eax
.text:0000000140C14B30                 jz      short loc_140C14B40     ; if no debugger → continue
.text:0000000140C14B32                 mov     ecx, 7F7Fh               ; else crash with error code
.text:0000000140C14B37                 call    TriggerAntiDebugCrash     ; immediate exit
```

Offset of the call: `0xC14B28` (RVA)  

### DbgUiRemoteBreakin Is Also Checked

Combat Master does not call `DbgUiRemoteBreakin` directly, but it deliberately triggers the condition that forces Windows to invoke it.
(this is to prevent people from just adding a breakpoint.)

Look at this function around RVA `0xC15980`:

```asm
.text:0000000140C15980                 mov     rax, cs:__imp_DebugActiveProcess
.text:0000000140C15987                 mov     ecx, [rbx+ProcessId]      ; the current process id
.text:0000000140C1598A                 call    rax                        ; calls DebugActiveProcess(self)
.text:0000000140C1598C                 test    eax,eax
.text:0000000140C1598E                 jns     short continue
.text:0000000140C15990                 call    TriggerAntiDebugCrash ; crashes your game.
```

When `DebugActiveProcess` is called on an already-running process that is not being debugged, Windows internally creates a remote thread that executes `DbgUiRemoteBreakin` inside the target process.  
If that function is patched to `ret`, this whole trick becomes harmless.

### Crash String Reference

Search the binary for one of these strings:

```
L"Anti-debug detected"
L"Debugger detected."
L"Security violation #0x4201"
```

You will find at least two of them.  
Now place an access breakpoint (hardware) on one of those strings in x64dbg.  
Run the game → inject any DLL → the breakpoint instantly hits right after the `IsDebuggerPresent` check at `0xC14B28`.

### My Patch In Action (Live Screenshots From Today)

Here is the before/after from the current version (Dec 2025):

**Before patching** – first bytes of `IsDebuggerPresent` in kernel32.dll  
`4C 8B D1              mov r10, rcx`  
`B8 3A 00 00 00        mov eax, 3Ah`

**After debubg → instant crash**

**After single-byte patch to 0xC3**  
`C3                    ret`

Same story with `DbgUiRemoteBreakin` inside ntdll.dll:

**Original prologue**  
`4C 8B D1              mov r10, rcx`  
`B8 5F 00 00 00        mov eax, 5Fh`

**Patched to**  
`C3                    ret`
#### Proof
<img width="1919" height="1039" alt="image" src="https://github.com/user-attachments/assets/1bb9683d-a3ed-45a1-9b62-727b5f332b54" />
```txt
[*] DbgUiRemoteBreakin @ 0x00007FF843A1C9C0
[BEFORE] ret patch: C3 4A 36 15 00
[AFTER] ret patch: C3 4A 36 15 00
[+] Patched DbgUiRemoteBreakin with RET
```
```cpp
bool patch_dbgbreak() {
// patching lib is closed src
    void* dbgbreak = patcher::get_proc("ntdll.dll", "DbgUiRemoteBreakin");
    if (!dbgbreak) {
        return false;
    }

    printf("[*] DbgUiRemoteBreakin @ 0x%p\n", dbgbreak);

    g_patch.set(dbgbreak);
    if (g_patch.apply_ret()) {
        printf("[+] Patched DbgUiRemoteBreakin with RET\n");
        return true;
    }

    printf("[!] Failed to patch DbgUiRemoteBreakin\n");
    return false;
}
```
Meaning a single `0xC3` byte is literally enough to play the entire season undetected (as long as you don’t glow like a Christmas tree).
