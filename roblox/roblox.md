# Analyzing Hyperion

> [!IMPORTANT]
>
> Version analyzed: **`version-bca459bcd1854ce4`**

## Table of Contents 

- [Introduction](#introduction)
- [Overview](#overview)
- [The beginning](#the-beginning)
- [1st Hash (System UUID)​](#1st-hash-system-uuid)
- [2nd Hash (Memory Devices)](#2nd-hash-memory-devices)
- [3rd Hash (Monitor EDID)​](#3rd-hash-monitor-edid)
- [4th Hash (SystemReg)](#4th-hash-systemreg)
- [Conclusion](#conclusion)

## Introduction

In this part,
I will write about one of the more interesting parts of Hyperion.
This will focus on the routines that collect various identifiers
from your system to build unique identifiers,
which will be used for their upcoming alt detection system.
The rest of the article is dedicated to that topic.

## Overview

As you probably know by now,
Hyperion has announced at the end of last year that they will be
implementing a system to identify people's alt accounts.
This analysis will focus on that.
Not many people know, but nearly since the release of Hyperion,
they have already had a function responsible for collecting those
identifiers.
However, up until recently,
it was only used for analytics.
A few weeks ago,
I was surprised by the termination of one of my accounts, outside of any existing ban wave.
Soon after,
every single one of my alt accounts was terminated as well,
with a message stating,
> You created or used an account to avoid an enforcement action taken against another account.
> This offense was determined by considering your account information,
> including factors such as your account email, phone number, and/or
> other factors.

This was on 2/29/2024.

Since I'd already analyzed this part of Hyperion,
I decided that it would be a great candidate for a post.
If you have exploited
and have been banned within the last 5 months on Windows,
then it's very likely that this will happen to you at some point.

I don't know of anyone
else who has been banned on every account associated with them yet,
so I have reasons to believe
this was a unique gift for my Hyperion reversal series...

In any case, this will become an issue in the near future for
everyone, so this is the perfect time for this analysis.

## The beginning

For starters,
I'll say that this function is invoked by the Roblox engine itself.
After Hyperion completes
the early initialization and passes control to the Roblox entrypoint,
Roblox will invoke this function shortly after handling basic stuff
like update checks.
How this function is invoked isn't too important in this post;
the main thing here to understand is that it's called pretty early.

Internally, the function collects 4 different identifiers,
creating 4 different hashes and storing them internally.
Here, I will also mention that after the hashes are created,
they are sent in 2 different places.
First, they are passed to Roblox and cached internally
within the engine,
and they are also sent as part of the standard Hyperion networking
routines, but this is outside of this topic.
The reason why Roblox caches it internally is because they send this
as join data when you try to join any game server.
The field used for this is called StreamQoSCookie.

One last thing I will mention at this point is that the hashing algorithm they use for the identifiers is SHA256.

## 1st Hash (System UUID)​

Now that we know that there are 4 different identifiers used, let's start with the 1st one.
The function RVA
that's responsible for collecting all of them is `0x21D6DC0`
Since that function is responsible
for initializing quite a bit of other things
before collecting anything,
the 1st thing we will need to do is find the beginning of that part.
After doing a simple syscall trace of the function,
I saw the 1st syscall done to NtQuerySystemInformation with
SystemFirmwareTableInformation class was done at 0x21D7DC5.
This is actually a function that wraps up doing the manual syscall.
After a bit of looking around,
I concluded that this was indeed
the beginning of everything they query.
code:

```asm

mov rdx, [rbp+0C90h+Src]
sub r8d, edx
mov ecx, 4Ch ; SystemFirmwareTableInformation
lea r9, [rbp+0C90h+Block]
call nt_query_system_wrapper
cmp eax, 0C0000023h
jnz loc_1821D7F1A
```

Before continuing,

> [!TIP]
> It's good to note that Hyperion intentionally tries to query every
> possible info class in an attempt to confuse people doing simple
> syscall traces.
>
> The approach you can take to overcome this,
> is to set a breakpoint on the smbios physical address in ntoskrnl,
> skip past the first one,
> and now you'll be in the context of the HWID function.
>
> Simply step back to UM, and you'll be within the manual syscall.
>
> You can then trace through the entire function,
> lift to LLVM if desired, and perform some optimization passes.

This also allowed us to locate the function that Roblox
was calling to initialize the scan data + acquire the HWID data.
We just got execution in this function,
stepped out to the caller,
so that the HWID is fully initialized.
Then we set a breakpoint on any given hash for read access,
and this took us directly to where Roblox was acquiring them.

Let's return to the main point.
At the calling site,
we can see them getting system firmware table
info with the signature `RSMB`,
which I observed after examining the SystemInformation argument
in ReClass. They also check for `STATUS_BUFFER_TOO_SMALL`
to handle resizing the buffer.

For those wondering what RSMB means,
taken from the MS Docs:
**`RSMB` - The raw SMBIOS firmware table provider.**
SMBIOS is essentially a standard developed to allow operating systems
to query information about your system.
After your PC is booted,
the firmware will create this table and put it somewhere in memory.
Windows has this API to allow user-mode applications
to query that structure. If you are interested in more details,
you can read the SMBIOS specification itself.

Since SMBIOS can be used to query various identifiers,
we will need to look further to find out what exactly they are using.
Due to the heavy use of STL within this function,
this isn't as simple as it seems.
After tracing a little more, I found the parts we are interested in.

This is the point where they parse the SMBIOS tables, specifically the beginning where they get the next table and read the ID.

They then copy
the parsed data into a map and repeat this until every table
of need is parsed.
We're still missing some info about what tables specifically they use.
After tracing a little more,
I found out that after parsing every table,
they exit the parsing loop
and start the actual hashing with the data acquired.


At this point,
we can see them decrypting a string and entering a SHA256 hashing loop.
The interesting thing
here is that they are actually hashing a constant string that,
after being decrypted, results in 'O6e7GA9D90wQmmAzD6jM'.
This is an interesting part, and we will come back to this later.

Shortly after the first hashing loop,
they enter a new one that operates on the same hash still.
This one is actually the first important hashing loop.
After breakpointing the loop and looking at the data being hashed,
I quickly realized what this is.

There is more to this,
which I have hidden for obvious reasons.
The full data is always 0x10 bytes.
This is, in fact,
the UUID member of the System Information table in the SMBIOS.
Using WMI,
you can run this command in CMD:

```cmd
wmic path win32_computersystemproduct get UUID
```

This will give you your UUID if you need it for whatever reason.
Mine starts with `4C 4C 45`,
and this is exactly what I saw in the buffer being hashed.

At this point, we know that the first hash is actually your system UUID.

If you remember the string we saw being hashed earlier,
Hyperion,
in fact,
has a unique string
for each of the hashes appended to the beginning of each hashing data.
This is probably done so that if they don't find any data to hash,
they have a default one.
In any case, you should remember
that they append strings to each of the hashes,
and each one is unique too.

## 2nd Hash (Memory Devices)

The 2nd hash is also related to the SMBIOS
but made into a separate hash.
Knowing the hashing algorithm they use, finding
the rest of the hashes is a simple task.
After searching for the next hashing loop,
I quickly noticed where the important part starts.
At RVA `0x21DBF6C`,
we can see them constructing
the 2nd unique string appended to the beginning of the hash data.
This time it's `IZwIkbqUBIqYN2Un2duD`.
After this is hashed, the hashing of the actual SMBIOS data starts,
which happens at `0x21DC478`.


This is what I saw after placing a breakpoint and looking at the buffer being hashed. You can use the following WMI query to get the same data:

```cmd
wmic memorychip get devicelocator, serialnumber
```

After running it myself,
I verified that this is indeed the memory device information part
of the SMBIOS.
That is actually the last part of the SMBIOS being used;
the last 2 hashes use data from different places.

## 3rd Hash (Monitor EDID)​

The third hash is actually quite interesting. They query something called **Extended Display Identification Data,**
which is essentially
a format used for monitors to describe their capabilities,
and it happens to include serial numbers.

The RVA of where that data is collected is `0x21DD0C2`.
This is just a call instruction
to the function that actually collects the data.
You can trace it for extra details,
but internally all it does is query the data from the Registry.
For those who don't know, this data is stored by Windows in the
registry at `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\DISPLAY`.
They query all active monitors and extract a few fields out of the
EDID, the most important one being the serial number.

The unique string appended to this data is `0LaUoAv5C6K5n1JciQzY`

> [!IMPORTANT]
>
> An important thing to note here is that
> they actually verify the checksum of the structure.
> If you modify the serial number without recomputing the checksum,
> Hyperion will set a flag that will cause Roblox to reject any attempt
> to connect to a game server.

## 4th Hash (SystemReg)

This one is rather interesting,
as it is not actually deemed as a "hardware" identifier,
but rather an identifier to fingerprint your specific Windows user,
in a rather stealthy way.
After we had seen
that this last hash changed for whatever Windows user we used,
we realized that it had to be specific to each Windows user.

We made an assumption that it had to do with the SID,
so we did a syscall trace and saw a function that matched our criteria: NtOpenProcessToken.
This function is used to acquire a handle, which you can then use to actually get the process token, and from there get the SID.

We then breakpointed after this point, enabled Procmon to log all filesystem/registry accesses from Roblox, and allowed it to run.

On this trace,
we saw them opening
a specific registry path that matched exactly what we were looking for:
`\Registry\User\SID\SYSTEM\CurrentControlSet\Control`.

On this trace, we saw them opening a specific registry path that matched exactly what we were looking for: `\Registry\User\SID\SYSTEM\CurrentControlSet\Control`.
What was interesting is the value which they were fetching, which was `\0SystemReg`.

This is interesting because you won't be able to open it in Regedit,
as it doesn't like it due to the null terminator at the start.
The only registry keys that should have a null name in Windows are the
default keys.

After we tried searching the web for this key, we couldn't find anything. Our next approach was to load Windows into a VM, attach a debugger, create a new user account, and log all registry writes to said user account, so we could locate what this key was used for.

While creating the new user account, we saw that this key did not exist. We then realized that Hyperion was likely creating the key themselves and simply hashing the contents inside.

Here is a screenshot of them querying the fourth hash, RVA of the call to it is at `0x21DE157`:


After tracing this function,
you'll notice some rather interesting parts:

`RobloxPlayerBeta.dll + 0x1588E43`: call to RtlConvertSidToUnicodeString:


Here is where the process token is acquired


In short, the first time you launch Roblox,
Hyperion will create this key and fill it with unique data.
This data will then get hashed and sent to the server each time you
open Roblox, which, alongside the other hardware-related identifiers,
will connect your PC to every account you use.

That's all really smart because
if you are to use a
traditional spoofer not made specifically for Roblox,
this key will persist even if you change everything else.
It's a really smart move by Roblox,
considering
there are big limits in the data you can query from user mode.

Lastly,
the fixed string used in this hash is `eOj7IvEHtbPqBn5MLun2`,
which is appended to the beginning of the result after fetching the registry key.

## Conclusion

Currently, there aren't that many public p2c's for Roblox, but Hyperion tends to do ban-waves pretty rarely. This, alongside the fact they only ban for 1 day, allows many people to simply not care that they are detected. I assume Hyperion will soon enough start using this system and likely move to terminations instead of 1-day bans.

Hopefully, this post can help developers create spoofers
that work for Roblox;
otherwise,
you should be prepared for big changes in the near future.
The good side of things is that Roblox doesn't even require
administrator permission and operates entirely in user mode,
limiting the range of identifiers they can use,
which makes creating a spoofer a pretty easy task.
