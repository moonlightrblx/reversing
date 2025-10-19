So I've been coding cheats for combat master for a while and the biggest question I get in my community is "How do I debug the game it just crashes", and I've been tired of this question for a while so I'm gonna release the method that I've been using to debug CombatMaster and other titles similar to it. It works by patching DbgUiRemoteBreakin (ntdll) and IsDebuggerPresent (KERNEL32) with a ret opcode (0xC3). I've tried to comment this out so even the most beginners can understand what its doing and how you can improve the detections.


#### Patcher.h
```cpp
#pragma once
#include <windows.h>
#include <cstdint>
enum class opcodes_t : BYTE {    
    // asm opcodes
    JMP = 0xE9,
    JMP_SHORT = 0xEB,
    JE = 0x84,       
    JNE = 0x85,      
    JG = 0x8F,       
    JL = 0x8C,       
    JGE = 0x8D,      
    JLE = 0x8E,      
    CALL = 0xE8,     
    RET = 0xC3,      
    NOP = 0x90,       
    INT = 0xCD,       
    HLT = 0xF4        
};
class c_patch { 
    // asm helper library that helps you patch functions 
    // if you're woried about detections do NOT use this 
    // this is only meant to be a simple showcase of how we can patch bytes in functions
    // todo: use safer functions
private:
    void* func_addr; // the address of the function that we're patchingg
    BYTE original_bytes[5]; // save first 5 bytes for jmp patching
    bool patched; // if the patch was successfull
    size_t patch_size; // size of the patch we're creating.

public:
    c_patch() : func_addr(nullptr), patched(false), patch_size(0) {
        memset(original_bytes, 0, sizeof(original_bytes));
    }

    void set_func(void* addr) {
        func_addr = addr;
        patched = false;
        patch_size = 0;
        memset(original_bytes, 0, sizeof(original_bytes));
    }

    bool patch_byte(BYTE new_byte) { 
        if (!func_addr) return false;

        DWORD oldProtect;
        if (!VirtualProtect(func_addr, 1, PAGE_EXECUTE_READWRITE, &oldProtect))
            return false;

        if (!patched) {
            original_bytes[0] = *(BYTE*)func_addr;
            patched = true;
            patch_size = 1;
        }

        *(BYTE*)func_addr = new_byte;

        VirtualProtect(func_addr, 1, oldProtect, &oldProtect);
        return true;
    }

    // patch with ret (0xC3)
    __forceinline bool patch_ret() {
        return patch_byte((BYTE)opcodes_t::RET);
    }

    // patch with jmp to target addr (relative jump, 5 bytes)
    __forceinline bool patch_jmp(void* target) {
        if (!func_addr || !target) return false;

        DWORD oldProtect;
        if (!VirtualProtect(func_addr, 5, PAGE_EXECUTE_READWRITE, &oldProtect))
            return false;

        if (!patched) {
            memcpy(original_bytes, func_addr, 5);
            patched = true;
            patch_size = 5;
        }

        uintptr_t src = (uintptr_t)func_addr;
        uintptr_t dst = (uintptr_t)target;
        intptr_t rel_addr = dst - (src + 5); // relative offset from next instruction

        BYTE patch[5];
        patch[0] = (BYTE)opcodes_t::JMP; 
        *(int32_t*)(patch + 1) = (int32_t)rel_addr;

        memcpy(func_addr, patch, 5);

        VirtualProtect(func_addr, 5, oldProtect, &oldProtect);
        return true;
    }

    // restore original bytes (1 or 5 bytes depending on patch)
    bool restore() {
        if (!func_addr || !patched) return false;

        DWORD oldProtect;
        if (!VirtualProtect(func_addr, patch_size, PAGE_EXECUTE_READWRITE, &oldProtect))
            return false;

        memcpy(func_addr, original_bytes, patch_size);

        VirtualProtect(func_addr, patch_size, oldProtect, &oldProtect);
        patched = false;
        patch_size = 0;
        memset(original_bytes, 0, sizeof(original_bytes));
        return true;
    }

    // fetch function address from dll + func name
    static void* fetch_func(const char* dll_name, const char* func_name) {
        HMODULE mod = (HMODULE)fetch_module(dll_name, false);
        return (void*)GetProcAddress(mod, func_name);
    }

    static uintptr_t fetch_module(const char* module_name, bool should_load = true) {
        HMODULE mod = GetModuleHandleA(module_name);
        if (!mod && should_load) {
            mod = LoadLibraryA(module_name); 
            // if module isnt loaded and should_load = true then load it
            if (!mod) // if we couldnt load it just return null
                return NULL;
        }
        return reinterpret_cast<uintptr_t>(mod);
    }
};
```
#### dllmain.cpp
```cpp
#include <Windows.h>
#include <thread>
#include <windows.h>
#include <iostream>
#include <winternl.h>
#include "sdk/game/includes.h"

c_patch editor;
c_patch editor2;

__forceinline bool patch_antidebug() {
    bool dbgBreakfailed = false;
    bool dbgPresentfailed = false;
    if (!GetModuleHandleA("ntdll.dll")) {
        // ntdll isn't included in this process meaning we cant patch it.
        return 0; // the function *might* still be used so you can call LoadLibraryA
    }
    
    void* dbgBreak = editor.fetch_func("ntdll", "DbgUiRemoteBreakin"); 
    // DbgUiRemoteBreakin, 56, 0xcbe30

    // void* dbgBreak = GetProcAddress(GetModuleHandleA("ntdll.dll"), "DbgUiRemoteBreakin");
    // dbgbreak is used by some anti debug methods 
    // so we patch it to return false always (in this case we just patch a ret but it defaults to false)
    // this is better than patching IsDebuggerPresent cause some anti-debuggers store that function and verify the bytes
    // yes i found this myself, and yes this is used on some games to this day :skull:

    // this method is used in CombatMaster and works great. 
    // other games i've tested (polygon, rocket league) have also had great compatability.

    if (!dbgBreak) { // function not found 
        dbgBreakfailed = true;
    }
    if (!dbgBreakfailed) {
        editor.set_func(dbgBreak);
   
        if (editor.patch_ret())
            return true;
        else
            return false;
    }

    void* IsDebuggerPresent_ = editor2.fetch_func("KERNEL32", "IsDebuggerPresent");

    if (!IsDebuggerPresent_) {
         dbgPresentfailed = true;
    }
    if (!dbgPresentfailed) {
        editor2.set_func(IsDebuggerPresent_);
        // if they try to check for debugger just return false
        if (editor2.patch_ret())
            return true;
        else
            return false;
    }

}



__forceinline void message_box() {
    // MessageBox(NULL, L"injected twin <3", L"ERROR", MB_OK | MB_ICONERROR);
    if (!patch_antidebug()) {
        MessageBox(NULL, L"couldnt patch 1 or more anti debug function", L"ERROR", MB_OK | MB_ICONERROR);
        // blegh :( 
    }
}

BOOL APIENTRY DllMain( HMODULE handle, DWORD  injectreason, LPVOID unused)
{
    if (injectreason == DLL_PROCESS_ATTACH) {
		std::thread(message_box).detach();
    }

    return TRUE;
}


```
#### Why Patch These Functions?

`IsDebuggerPresent (KERNEL32.dll)`: Checks if a debugger is attached to the process. Returns TRUE if a debugger is present, causing the game to crash or exit.

`DbgUiRemoteBreakin (ntdll.dll)`: Handles remote debugging breakpoints. Patching it prevents the game from triggering anti-debugging measures.

- By overwriting the first byte of these functions with 0xC3 (the ret instruction), we force them to return immediately, effectively disabling their checks.

I really hope this guys helps you as it did me when I started coding cheats for CM and other games :439:
