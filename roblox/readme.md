# Intro
If you've ever opened roblox in IDA or Binary Ninja or whatever you may use to disassemble roblox you may have noticed the random INT3 instructions spread around the binary.
<img width="648" height="423" alt="image" src="https://github.com/user-attachments/assets/c6fa9ee6-245c-4035-b113-119fb0857075" />

Those are always located where the first branching instruction was. This essentially means the first branch of every function is replaced by the INT3s.

Hyperion emulates the real branch instruction every time the INT3's are hit, if you want to restore them with the real instructions, you can iterate the array and get the RVA of each entry, and write the original instruction on that place, which as I said is also stored in the array.

# Start
In this section, we'll start our initial analysis of Hyperion's binary. 

First, we'll open the binary in IDA, initially you'll see that all of the executable code is in a .byfron section. As you may have already noticed, Hyperion is not packed, it also doesn't employ any sort of virtualization. So what do they do?

Let's start out by just clicking on a couple of functions. No matter which function you've chosen, as long as it has control flow, you'll see that IDA will likely fail to disassemble it: Hyperion implements a few variations of this across all of their functions. This is the most common form of obfuscation that you will see throughout your analysis, and it's easily recognizable. 
The seemingly "fake" instruction sequences are also not arbitrary, but follow specific sequences that repeat throughout the binary. Along with this are actual fake instructions, as in dead code, which is present throughout the binary.

<img width="767" height="362" alt="image" src="https://github.com/user-attachments/assets/29b3690b-0f39-4a4b-8888-199ebece42fa" />

# Modules
If you look at the memory regions of the imported modules, you might notice that some of them aren't mapped normally.
<img width="362" height="190" alt="image" src="https://github.com/user-attachments/assets/bb69b971-434e-4028-8188-0c95ff76ebd8" />

Normally, loaded modules aren't copied into the private working set of the process, instead they're shared until a process writes into them, which invokes CoW (Copy on Write), but that isn't the topic of this thread. Basically, this is one of the modules that Hyperion "protects," the idea is that you can't patch its code, and if you try to, you will get an error while trying to change its protection to writable.
### NTDLL
Hyperion hooks ALL of the functions below (and more).

<img width="207" height="559" alt="image" src="https://github.com/user-attachments/assets/afb39a89-e16f-4de1-be9f-8717de01cdf8" />

# Launching
Initialization Routine: In order to gain control over critical execution from the start, they do initialize hyperion before roblox's primary executable code via multiple techniques that i'll explain right now.

The first one is that they're doing pre-execution control via windows loader, they do take advatange of windows loader by loading their module as an entry dll, making sure hyperion's code is executed before roblox's main code, enabling them to setup protections, encrypting the .text, setting up hooks etc.... 

They also manually load and protect important imports that Roblox relies on. Their initialization routine includes creating custom memory sections for these libraries using non-standart mappings that prevent tampering and make CoW (Copy-On-Write) not possible. (They do remap them with SEC_NOCHANGE FLAG).

## What is an IC?

The last thing and probably the most important out of here is that during initialization, they register an Instrumentation Callback, which is an undocumented windows feature (officially undocumented, although you can find a lot of examples about them anywhere).

In short ICs allows anyone to intercept usermode to kernelmode transitions (it is like a middleman between UM & KM). They do use their registered IC to monitor and control threads, manage exceptions and prevent unauthorized actions in the code.

---

One of the events Hyperion's IC redirects is `LdrInitializeThunk`. So, what's so special about this function? Well, when the Windows kernel creates a new thread, it jumps to `LdrInitializeThunk`, it performs various datum initialization before jumping to the actual thread start address.

This means that Hyperion has full control over any new thread as it's created before its start address is ran, and can decide whether or not to let the thread continue, or to terminate it.

If you try to create a thread externally, you will realize that it never actually jumps to your thread's start address, this is because Hyperion does not let non-whitelisted threads be created.

You might be wondering "what determines if a thread is whitelisted" and that's a good question. Earlier we saw that they hook some NtDLL imports, well among those is `NtCreateThread(Ex)`. This hook exists so that internally created threads by Roblox code or loaded modules will be whitelisted after a few checks, the hook creates a stub that decrypts the start address, then jumps to it. 

Then, they spoof the start address of the thread to the stub. By the time the new thread spawns and hits the `LdrInitializeThunk` hook, Hyperion knows if it's legit or not.

## TlsCallback_0
As you may know TLS callbacks are one of the first steps in the order of windows dll execution, they occur even before the entrypoint. 

Hyperion has implemented a TlsCallback (`TlsCallback_0`) that runs some initilization logic. It has a LOAD of junk arugments 64)
### Checks
They check for a value known as a "leaf" / 0x40000002  is commonly used by:
* Hypervisors
* Emulators
* VM vendors
<img width="509" height="69" alt="image" src="https://github.com/user-attachments/assets/d3803e09-4369-43e1-8f62-00244505298c" />

They also have some usermode hook checks using the GDI buffer. Why GDI buffer you ask? It's rarely accessed, stable memory and not expected to be touched.
<img width="778" height="98" alt="image" src="https://github.com/user-attachments/assets/6b6a8471-8cc9-406c-bace-b451171c9446" />

If any one of them fail NtTerminateProcess is called. For some odd reason this function is not dynamically imported like the other imported functions which I find very interesting.
<img width="684" height="215" alt="image" src="https://github.com/user-attachments/assets/27c3efcb-5594-4da8-b4c8-ee6a33c1fe9b" />

# Hypervisor protections
They check for hypervisor presence by forcing the CPU into compatibility mode (32 bit) and executing specific instructions like CPUID. The thing is that in this mode, executing certain instructions cause EIP overflow which is a bit annoying...

They also have trap flags and #UD exception (lol). Their trap flags are set in specific registers that will cause unconditional VMExits. The problem is that many hypervisors mishandle this state so Hyperion will detect virtualization because of this.

But in plus they use #UD (undefined instruction) exceptions as some hypervisors imporperly emulate syscall/ret instructions which should normally raise those undefined instructions

# Protections

We'll start with the first one which is Obfuscation Techniques, they do have complex obfuscation tricks that are made to break reverse engineering efforts, like fake instruction sequences, they fill their executable code with arbitrary sequences that confuse static disassemblers.
Their fake instructions often follow specific and repetitive patterns which makes it harder for reversers to know which which one is functional code or filled junk (which will also cause reversing tools like IDA to misinterpret code and leading to incomplete or inaccurate disassembly results).
 
They also have dead code sequences, which does not contribute to actual functionality but complicate reverse by inflating its stack frames and obscure control flow which leads to creating functions that appear more complex than they really are. 

Finally we got unconditional jumps to decrypted addresses, they complicate control flow by occasionally jumping to dynamically decrypted addresses, which break the linear flow of code forcing reversers to resolve or emulate each jmps destination in real time.

Now, we'll talk about their memory and import protection. 
They deploy various techniques to protect them from reverse engineering and we'll start with the first one which is their dynamic import encryption, instead of relying on basic static import tables, they dynamically encrypts import addresses and decrypt them only when necessary (just like they do with PTEs), this protection is actually powerful because the imports are protected by both encryption and trap mechanisms that trigger crashes if accessed improperly.

Then it comes the memory monitoring and page protection, they actively monitors executable memory pages in Roblox Memory, they do use hooks to manage memory allocations and they hook on syscalls like `NtProtectVirtualMemory` and `NtAllocateVirtualMemory` to restrict by whitelisting specific executable memory regions.

The last one for this part are mapped views for syscall invocations, they use dual views of memory for syscalls invocations which are divided into RW and RX sections, allowing it to manage memory without revealing its code structure. 
Also, they resolve their imports through a hash lookup system where each key is hashed using the Fnv1a-32 algorithm, with using handler tables based on modules like ntdll and kernelbase which only permit validated keys to be decrypted and called.

## 0AVX
External cheats, such as ESP/Aimbot, often access the same Roblox instances, such as Players, Humanoid, etc. Therefore, Roblox has taken action against them.

To accomplish this, they identify unauthorized memory access instances. How? It's quite straightforward. 

Since they execute within the task scheduler worker loop, they control when Roblox's code is executed. 

So, they invalidate particular instances, and before Roblox's code is executed, they verify whether these instances have been accessed.

There is a function which its job is to see if memory has been accessed. It does this by checking if the pages supporting the Instances in Roblox are part of the process's working set using `NtQueryVirtualMemory`.

Before we proceed, let's delve into how Windows handles memory, according to Microsoft's documentation: "The working set of a process is the set of pages in the virtual address space of the process that are currently resident in physical memory. 
The working set contains only pageable memory allocations; non-pageable memory allocations such as Address Windowing Extensions (AWE) or large page allocations are not included in the working set."

This might sound a bit complex, so let's break it down. In any modern operating system, like Windows, memory management involves two main states: physical memory and paged out memory. If a chunk of memory isn't frequently used, it's not efficient to keep it constantly loaded into physical memory. So, the OS moves it to the page file. When this memory is accessed again, it triggers a page fault, and Windows then fetches it from the page file back into physical memory and adds it to the working set.

Hyperion takes advantage of this by extracting memory from the working set and subsequently checking if it's still there before the next job iteration. Interestingly, in the Microsoft documentation, there's a function that perfectly fits this scenario: `VirtualUnlock`: "Calling `VirtualUnlock` on a range of memory that isn't locked releases the pages from the process's working set."

# Dumping
I made a dumper specifically targetting the Roblox Hyperion module, it dumps it from memory and resolves statically what we call 'opaque predicates' those are basically branches of code that will be always taken.

> ## Example of an opraque predicate
> <img width="698" height="455" alt="image" src="https://github.com/user-attachments/assets/0625f1b3-32eb-4c7a-baae-bcbe78e89c59" />


# BONUS (bypassing checks)

There is a LOT of ways to bypass their checks since they are fully usermode, i'll list a few of them.

The first one is abusing their Instrumentation Callback. It is linked to all their checks one way or another.

Want to hook their syscalls and fake what they return ? Simple, just unmap hyperion, put your hooks and remap it.

Want to make a proper page decryption ? Fine, when you try to execute code from an encrypted page a violation is raised right? well this is where the IC comes into play, their IC will intercept the exceptions before they are handled by WEH, so hyperion can inspect and manage how the memory pages are handled) and of course the IC uses this to check if the exception occured within an encrypted region of code and if it did it will trigger their decryption which is.
(fun fact: there are several timers in their code that determine how long a page stay unprotected for and how often to perform a memory scan etc. patching that alone will let you have a infinitely long live unprotected page and disable scans.)
# Conclusion
Hyperion is a great anti-tamper because it is able to do a lot of interesting methods while being fully usermode. 

Of course they do a lot of dumb mistakes but eh it happens to everyone.

Honestly, not anyone can fully reverse and bypass Hyperion, you need a deep knowledge about windows internals and a lot of experience with reverse engineering. 

They still patched all previous big executors such as Krnl, Synapse X (which now work with roblox), Script-Ware etc... so they got a plus on that.
