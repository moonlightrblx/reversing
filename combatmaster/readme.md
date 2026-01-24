# Bypassing Combat Master’s Anti-Debug

*December 26, 2025*


Everything below is from the current live build (12/26/25).

### Find 0xDEADC0DE (the crash ref)

Search the main dll (`engine.dll`) for the string “0xDEADC0DE” 


You will find exactly ONE 

<img width="806" height="150" alt="image" src="https://github.com/user-attachments/assets/115b4275-31ce-4d8e-8d7c-b29f7213ca7c" />

This is the only function that handles crashing that you can xref to but you can simply goto the signature `48 83 EC ? FF 15 ? ? ? ? BA` and return every early :D

if you dont want to do that patch DbgUiRemoteBreakin :D


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

```cpp
[*] DbgUiRemoteBreakin @ 0x00007FF843A1C9C0
[BEFORE] ret patch: B8 5F 00 00 00
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

Meaning a single `0xC3` byte is literally enough to play the game with the debugger attached.


### merry christmas 🎄 
hope this post helps you in some way shape or form.
