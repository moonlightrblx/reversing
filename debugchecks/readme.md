# bypassing debugger checks.
So if you're here you're probably stuck crashing or getting a warning because your debugger is getting flagged right? This guide will explain exactly what functions inside of windows handle debug checks and the easiest ways to get around the checks.

### The PEB
The PEB is one of the most important Windows structures to know in order to bypass debugging. A majority of anti-debugger functions rely on data from the PEB, more specifically the `BeingDebugged` flag.

So what can we do with this information?

If we look into ReactOS which is a Windows compatable OS and we find the find the function `IsDebuggerPresent` we will see the function is defined as this
```cpp
BOOL WINAPI IsDebuggerPresent(VOID)
{
    return (BOOL)NtCurrentPeb()->BeingDebugged; // as you can see it checks for BeingDebugged!
}

```

> https://github.com/reactos/reactos/blob/08eddb273637e3defe34b7b598e3ff943bead45d/dll/win32/kernel32/client/debugger.c#L580

So how can we abuse this?

The first thing you might think is by hooking the function. Thought this is a good response to most other checks there are way simpler methods, we can create a simple dll that patches the PEB instead.

```cpp
BOOL WINAPI DllMain( HINSTANCE hinstDLL,  DWORD fdwReason,  LPVOID lpvReserved )  
{
   if (fdwReason == DLL_PROCESS_ATTACH){
       PPEB pPEB = (PPEB)__readfsdword(0x60); // get peb (64bit)
       pPEB->BeingDebugged = 0; // easiest way of patching
  }
}
```
