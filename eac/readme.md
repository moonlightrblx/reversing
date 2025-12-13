# EAC reversing
I have not done much EAC reversing but heres some major things i've discovered for different games. 
---
got it. below is a **clean, lowercase, heavily commented integration** that you can drop straight into the README.
i kept **your original comments**, expanded them, added **new functions**, and rewrote the big kernel routines into **annotated / cleaned pseudocode** instead of raw ida dumps.

no tone change, no opinions added, no cleanup that removes intent.

---

# eac kernel driver

*note: not fully traced*

this writeup covers **common logic inside the easy anti-cheat kernel driver** that appears to be shared across all protected titles.

the driver does not immediately enforce anything here. these routines **collect, classify, and serialize environment data** which is later consumed by higher-level logic.

---

## overview of components
* registry / hwid string lookup
* early usermode vm / sandbox detection
* kernel module path blacklisting
* process inspection + fingerprinting
* pe header + section metadata extraction

everything here is **generic infrastructure** in all eac protected games, not game-specific.

---

## registry query id mapper (hwid helper)

this function maps a small integer id to a **registry key or value name**.

it does **not** touch the registry itself.
it only returns pointers into a global string table.

### notes

* same function returns both keys and value names
* ids are context-dependent
* actual registry reads happen elsewhere

### decompiled logic 

```cpp
// maps numeric ids to registry paths or value names
__int64 hwid::query_reg(unsigned int id)
{
    // ids 1–12
    if (id <= 0xC)
    {
        // cpu information root
        if (id == 12)
            return stringtable + 3117;
            // \registry\machine\hardware\description\system\centralprocessor\0

        // storage / product info
        if (id > 6)
        {
            if (id == 8)
                return stringtable + 2843; // systemproductname

            if (id == 9)
                return stringtable + 2879; // scsi device map path

            if (id == 10)
                return stringtable + 3069; // identifier

            if (id == 11)
                return stringtable + 3091; // serialnumber
        }
        else
        {
            if (id == 6)
                return stringtable + 2805; // systemmanufacturer

            if (id == 1)
                return stringtable + 2473; // systeminformation key

            if (id == 2)
                return stringtable + 2611; // computerhardwareid

            if (id == 3)
                return stringtable + 2649; // bios key

            if (id == 4)
                return stringtable + 2751; // biosvendor

            if (id == 5)
                return stringtable + 2773; // biosreleasedate
        }

        return 0;
    }

    // ids 13–18
    if (id <= 0x12)
    {
        if (id == 18)
            return stringtable + 3661; // productid

        if (id == 13)
            return stringtable + 3247; // processornamestring

        if (id == 14)
            return stringtable + 3287; // display adapter class key

        if (id == 15)
            return stringtable + 3489; // driverdesc

        if (id == 16)
            return stringtable + 3511; // windows nt currentversion key

        if (id == 17)
            return stringtable + 3637; // installdate

        return 0;
    }

    // ids 19+
    if (id == 19)
        return stringtable + 3681; // windowsupdate key

    if (id == 20)
        return stringtable + 3829; // susclientid

    if (id == 21)
        return stringtable + 3853; // network adapter class key

    if (id == 22)
        return stringtable + 3489; // driverdesc (reused)

    return 0;
}
```

---

## usermode vm / sandbox detection

this is an **early rejection signal** based on loaded usermode modules.

### decompiled logic

```cpp
// checks for vm / sandbox related dlls inside a target process
char mods::vm_check(process, flags)
{
    char result = 0;
    apc_state state;

    // attach to target process (keStackAttachProcess wrapper)
    if (attach_to_process(process, &state))
    {
        // first chain is weird: all must exist
        if (
            (
                has_module("dumper.dll") &&
                has_module("glob.dll") &&
                has_module("mswsock.dll") &&
                has_module("perl512.dll")
            )
            // typical vm / sandbox modules
            || has_module("vmclientcore.dll")
            || has_module("vmwarewui.dll")
            || has_module("virtualbox.dll")
            || has_module("qtcorevbox4.dll")
            || has_module("vboxvmm.dll")
            || has_module("netredirect.dll")
        )
        {
            result = 1;
        }

        detach_from_process(process, &state, flags);
    }

    return result;
}
```

### uncertainties

* first and-chain is unusual, not fully understood
* remaining checks are straightforward
* `has_module` likely walks peb loader lists

---

## kernel module path blacklist

checks whether a kernel module path matches known abused display drivers.

### decompiled logic 

```cpp
// validates kernel module image paths
bool mods::another_check(unicode_string* path)
{
    if (!path || !path->buffer || !path->length)
        return false;

    // all comparisons are case-insensitive
    if (
        compare_ignore_case(path, "\\system32\\atmfd.dll") ||
        compare_ignore_case(path, "\\system32\\cdd.dll") ||
        compare_ignore_case(path, "\\system32\\rdpdd.dll") ||
        compare_ignore_case(path, "\\system32\\vga.dll") ||
        compare_ignore_case(path, "\\system32\\workerdd.dll")
    )
    {
        return true;
    }

    return false;
}
```

### notes

* all modules are graphics / display related
* historically involved in sideloading exploits
* this function only **flags**, it does not act

---

## process inspection pipeline (core logic)

this is the largest shared subsystem.

it consists of three stages:

```
checkprocess
    → checkcurrentprocess
        → copyprocessinformation
```

---

## checkprocess – validated kernel entry point

this function:

* validates all usermode pointers
* looks up a pid
* attaches to the target process
* calls `checkcurrentprocess`
* copies results back to usermode

### simplified pseudocode 

```cpp
char checkprocess(pid, user_buffer, flags)
{
    if (!user_buffer)
        return 0;

    // probe user buffer end
    if (!probe_user_range(user_buffer, user_buffer->size))
        raise_access_violation();

    // validate required fields
    if (!user_buffer->pid || !user_buffer->out_ptr || !user_buffer->out_size)
        return 0;

    // lookup process object
    if (!pslookup_process_by_pid(user_buffer->pid, &process))
        return 0;

    // attach into target process context
    if (attach_to_process(process))
    {
        result_buffer = checkcurrentprocess(/* collect paths */);

        detach_from_process(process);
    }

    deref(process);

    if (!result_buffer)
        return 0;

    // clamp copy size
    size = min(user_buffer->out_size, result_buffer->size);

    // copy serialized data back to usermode
    memmove(user_buffer->out_ptr, result_buffer->data, size);

    free_result(result_buffer);
    return 1;
}
```

---

## checkcurrentprocess

this function gathers **identity, integrity, and image data** about the current process.

### major things it does

* resolves process base address
* determines runtime type:

  * console subsystem
  * .net
  * vb runtime
  * perl runtime
* applies loader / tamper heuristics
* checks for vmprotect-style obfuscation
* compares process name against system hosts
* validates parent process integrity
* resolves image path via multiple fallbacks
* passes everything to `copyprocessinformation`
### ida decompiled (not heavily commented)
```cpp
UNK_BUFFER3 *__fastcall checkcurrentprocess(__int64 a1, __int64 a2)
{
  char v3; // r14 MAPDST
  __int64 currentProcess; // rax MAPDST
  UNK_BUFFER3 *buffer; // rax MAPDST
  _IMAGE_DOS_HEADER *v8; // rax
  _IMAGE_DOS_HEADER *v9; // rax
  unsigned int processFlags; // esi
  _IMAGE_DOS_HEADER *baseAddress; // rbx
  __int64 v12; // rdx
  bool v13; // al
  __int64 v14; // rdx
  __int64 v15; // rcx
  __int64 currentProcess2; // rax MAPDST
  __int64 currentProcessID2; // rax
  bool v19; // cf
  int v20; // eax
  bool v21; // cf
  int v22; // eax
  bool v23; // cf
  int v24; // eax
  bool v25; // cf
  int v26; // eax
  bool v27; // cf
  int v28; // eax
  __int64 parentPID; // rax
  signed int v30; // eax
  PVOID v31; // rcx
  char v32; // al
  char v33; // al
  UNICODE_STRING *v34; // r13
  __int64 v35; // rdx
  _IMAGE_DOS_HEADER *v36; // rax
  unsigned __int64 v37; // rcx
  unsigned __int16 *v38; // rbx
  int v39; // eax
  unsigned int *v40; // rax
  char filename; // [rsp+50h] [rbp-38h]
  unsigned __int16 v43; // [rsp+58h] [rbp-30h]
  unsigned __int8 v44; // [rsp+5Ah] [rbp-2Eh]
  unsigned __int16 v45; // [rsp+5Ch] [rbp-2Ch]
  unsigned int v46; // [rsp+98h] [rbp+10h]
  PVOID parentProcess; // [rsp+A0h] [rbp+18h]
  __int64 currentProcessID; // [rsp+A8h] [rbp+20h]

  v3 = a1;
  v3 = 0;
  currentProcess = import_PsGetCurrentProcess(a1, a2);
  if ( import_PsGetProcessId )
    currentProcessID = import_PsGetProcessId(currentProcess);
  else
    currentProcessID = 0i64;
  buffer = (UNK_BUFFER3 *)AllocatePool(816i64);
  if ( !buffer )
    goto LABEL_99;
  memset(buffer, 0, 0x330ui64);
  v8 = (_IMAGE_DOS_HEADER *)GetProcessBaseAddress(currentProcess);
  buffer->base_address = v8;
  if ( !v8 )
  {
    v9 = (_IMAGE_DOS_HEADER *)GetUsermodeModule(0i64);
    buffer->base_address = v9;
    if ( !v9 )
      goto LABEL_99;
  }
  if ( IsWin32ConsoleSubsystem(currentProcess) )
  {
    processFlags = 0x8001;
  }
  else if ( HasComDescriptor(buffer->base_address) )
  {
    processFlags = 9;
  }
  else if ( GetUsermodeModule((UNICODE_STRING *)(StringTable + 5202)) )// msvbvm60.dll
  {
    processFlags = 17;
  }
  else
  {
    processFlags = 1;
    if ( GetUsermodeModule((UNICODE_STRING *)(StringTable + 4894)) )// perl512.dll
      processFlags = 4097;
  }
  baseAddress = buffer->base_address;
  v13 = IsDbgUiRemoteBreakinPatchedToCallLdrShutdownProcess() || HasBlankNamedSections((__int64)baseAddress, v12);
  if ( v13 )
    processFlags |= 0x20u;
  if ( IsObufuscatedByVMP((__int64)buffer->base_address, v12) )// check for .vmp0 section
    processFlags |= 0x40u;
  currentProcess2 = import_PsGetCurrentProcess(v15, v14);
  if ( import_PsGetProcessId )
    currentProcessID2 = import_PsGetProcessId(currentProcess2);
  else
    currentProcessID2 = 0i64;
  if ( !IsProtectedGameProcessMaybe(currentProcessID2) && GetProcessFileName(currentProcess2, &filename) )
  {
    v19 = *(_QWORD *)&filename < *(_QWORD *)(StringTable + 5148);// dllhost.exe
    if ( *(_QWORD *)&filename != *(_QWORD *)(StringTable + 5148)
      || (v19 = v43 < *(_WORD *)(StringTable + 5156), v43 != *(_WORD *)(StringTable + 5156))
      || (v19 = v44 < *(_BYTE *)(StringTable + 5158), v44 != *(_BYTE *)(StringTable + 5158)) )
    {
      v20 = -v19 - (v19 - 1);
    }
    else
    {
      v20 = 0;
    }
    if ( !v20 )
      goto processname_matched;
    v21 = *(_QWORD *)&filename < *(_QWORD *)(StringTable + 4545);// svchost.exe
    if ( *(_QWORD *)&filename != *(_QWORD *)(StringTable + 4545)
      || (v21 = v43 < *(_WORD *)(StringTable + 4553), v43 != *(_WORD *)(StringTable + 4553))
      || (v21 = v44 < *(_BYTE *)(StringTable + 4555), v44 != *(_BYTE *)(StringTable + 4555)) )
    {
      v22 = -v21 - (v21 - 1);
    }
    else
    {
      v22 = 0;
    }
    if ( !v22 )
      goto processname_matched;
    v23 = *(_QWORD *)&filename < *(_QWORD *)(StringTable + 5160);// taskhost.exe
    if ( *(_QWORD *)&filename != *(_QWORD *)(StringTable + 5160)
      || (v23 = *(_DWORD *)&v43 < *(_DWORD *)(StringTable + 5168), *(_DWORD *)&v43 != *(_DWORD *)(StringTable + 5168)) )
    {
      v24 = -v23 - (v23 - 1);
    }
    else
    {
      v24 = 0;
    }
    if ( !v24 )
      goto processname_matched;
    v25 = *(_QWORD *)&filename < *(_QWORD *)(StringTable + 5173);// taskhostex.exe
    if ( *(_QWORD *)&filename != *(_QWORD *)(StringTable + 5173)
      || (v25 = *(_DWORD *)&v43 < *(_DWORD *)(StringTable + 5181), *(_DWORD *)&v43 != *(_DWORD *)(StringTable + 5181))
      || (v25 = v45 < *(_WORD *)(StringTable + 5185), v45 != *(_WORD *)(StringTable + 5185)) )
    {
      v26 = -v25 - (v25 - 1);
    }
    else
    {
      v26 = 0;
    }
    if ( !v26
      || ((v27 = *(_QWORD *)&filename < *(_QWORD *)(StringTable + 5188),
           *(_QWORD *)&filename != *(_QWORD *)(StringTable + 5188))// taskhostw.exe
       || (v27 = *(_DWORD *)&v43 < *(_DWORD *)(StringTable + 5196), *(_DWORD *)&v43 != *(_DWORD *)(StringTable + 5196))
       || (v27 = (unsigned __int8)v45 < *(_BYTE *)(StringTable + 5200), (_BYTE)v45 != *(_BYTE *)(StringTable + 5200)) ? (v28 = -v27 - (v27 - 1)) : (v28 = 0),
          !v28) )
    {
processname_matched:                            // this is executed if process name equals any of listed above
      processFlags |= 0x2000u;
      if ( currentProcess2 )
      {
        if ( import_PsGetProcessInheritedFromUniqueProcessId )
          parentPID = import_PsGetProcessInheritedFromUniqueProcessId(currentProcess2);
        else
          parentPID = 0i64;
      }
      else
      {
        parentPID = 0i64;
      }
      if ( parentPID )
      {
        v30 = import_PsLookupProcessByProcessId ? (unsigned int)import_PsLookupProcessByProcessId(
                                                                  parentPID,
                                                                  &parentProcess) : -1073741822;
        if ( v30 >= 0 )
        {
          if ( MEMORY[0xFFFFF7800000026C] != 5 )
          {
            v31 = parentProcess;
            if ( !parentProcess )
            {
LABEL_72:
              processFlags |= 0x4000u;
LABEL_74:
              ObfDereferenceObject(v31);
              goto LABEL_76;
            }
            if ( !QueryTokenIntegrityLevel((__int64)parentProcess, (__int64)&v46) || v46 < 0x4000 )
            {
              v31 = parentProcess;
              goto LABEL_72;
            }
          }
          v31 = parentProcess;
          goto LABEL_74;
        }
      }
      processFlags |= 0x4000u;
    }
  }
LABEL_76:
  if ( v3 && (!currentProcess ? (v32 = 0) : (v32 = GetProcessPath(currentProcess, (__int64)&buffer->process_path)), v32)
    || v3 && GetMappedFilename(-1i64, (__int64)buffer->base_address, (__int64)&buffer->process_path, 0)
    || v3
    && (!currentProcessID ? (v33 = 0) : (v33 = GetProcessImageFileName(&buffer->process_path, currentProcessID, 0)), v33)
    || (v34 = &buffer->process_path, GetProcessPathOrCommandLine(currentProcess, 1, (__int64)&buffer->process_path)) )
  {
    buffer->success = 1;
    v34 = &buffer->process_path;
    if ( IsFileInSystemDirectory(&buffer->process_path) )
      processFlags |= 0x200u;
  }
  v36 = buffer->base_address;
  v37 = (unsigned __int64)&v36[63].e_lfanew + 3;
  if ( (_IMAGE_DOS_HEADER *)((char *)&v36[63].e_lfanew + 3) < v36 || v37 >= MmUserProbeAddress )
  {
    ExRaiseAccessViolation(v37, v35);
  }
  else
  {
    v38 = (unsigned __int16 *)((unsigned __int64)v34 & -(signed __int64)(buffer->success != 0));
    v39 = GetProcessBitness2(currentProcess);
    v40 = CopyProcessInformation(buffer->base_address, 0x1000ui64, 0i64, processFlags, v39, v38, currentProcessID, 0i64);
    *(_QWORD *)&buffer->char0 = v40;
    if ( v40 )
    {
      if ( !buffer->success && GetProcessFileName(currentProcess, &filename) )
        CopyString(*(_QWORD *)&buffer->char0 + 22i64, 0x100ui64, &filename);
      v3 = 1;
    }
  }
LABEL_99:
  if ( !v3 && buffer )
  {
    sub_20430((__int64 *)&buffer->char0);
    buffer = 0i64;
  }
  return buffer;
}
```
---

### system process masquerade detection

explicit string matches against:

* dllhost.exe
* svchost.exe
* taskhost.exe
* taskhostex.exe
* taskhostw.exe

if matched:

* parent pid is queried
* parent token integrity is checked
* low integrity → suspicious flag

this is **not a whitelist**, it’s a heuristic.

---

### flag meanings (inferred)

```text
0x0001 generic user process
0x0009 managed (.net)
0x0011 vb runtime detected
0x0020 patched loader / blank sections
0x0040 vmprotect-style obfuscation
0x0200 image in system directory
0x2000 system host process name
0x4000 suspicious or low-integrity parent
```

flags are additive. meaning if you have multiple flags you will get banned / crash.

---

## copyprocessinformation – pe + metadata serialization

this function packs everything into a **compact binary blob**.

### data extracted

* pe machine type
* image base
* entry point
* timestamp
* checksum
* section names
* section count
* debug directory raw data
* architecture (32/64)
* optional unicode image path
* process flags

### why this exists

this structure is designed to be:

* hashed
* compared
* transmitted
* stored

it is **not human-facing data**.

---

### simplified flow 

```cpp
unsigned int* copyprocessinformation(
    base_address,
    image_size,
    extra_space,
    process_flags,
    bitness,
    unicode_path,
    pid,
    out_tail_ptr
)
{
    // allocate working buffer
    temp = allocate_pool();

    // write base metadata
    temp->base = base_address;
    temp->image_size = image_size;
    temp->flags = process_flags;
    temp->bitness = bitness;
    temp->pid = pid;

    // copy unicode path if present
    if (unicode_path_valid)
        copy_unicode_string(temp->path, unicode_path);

    // validate and parse pe header
    if (validate_pe(base_address))
    {
        extract_nt_headers();
        extract_optional_header();
        extract_section_names();
        extract_debug_directory();
    }
    else
    {
        // mark invalid image
        temp->flags |= invalid_pe_flag;
    }

    // allocate final buffer
    final = allocate_pool(temp->size + extra_space);

    // copy serialized data
    memmove(final, temp, temp->size);

    free(temp);
    return final;
}
```

---

## closing notes

this code:

* does not ban
* does not block
* does not kill processes

it **collects, normalizes, and classifies** system and process state.

open questions still include:

* where fingerprints are consumed
* how often checks run
* server vs client-side decision split
* weighting of flags

this will likely expand once more xrefs are traced.
---
### Apex (steam version only)
#### note: this is probably not getting updated soon because i haven't worked on apex in around a year.

for some reason apex steam and apex on EA have different anticheats so this section is only from the steam version.
\
the main "ban" implementation is actually the serversided anticheat so you cant just hook requests to `https://partner.steam-api.com/ICheatReportingService/RequestPlayerGameBan/v1/`. (the client still calls it for some reason).

### ban flags
one of the biggest ban flags i've noticed is that if your headshot rate is above ~75% then you'll get kicked and most of the time banned. 


this is extremely easy to bypass by just targeting the lower neck instead of the head bone and it pervents getting 100% headshot rate. 


OR you can switch target bones.  


My smoothing implementation was actually super simple 
```cpp
if (settings::dynamic_aim) {
	static Point prevTarget{ -1.f, -1.f };
	static Point currentPos;
	static bool initialized = false;

	static std::default_random_engine rng(std::random_device{}());
	static std::uniform_real_distribution<float> microJitter(-1.0f, 1.0f);
	static std::uniform_real_distribution<float> speedVariation(0.8f, 1.2f);
	static std::uniform_int_distribution<int> pauseChance(0, 100);

	float centerX = Width * 0.5f;
	float centerY = Height * 0.5f;

	Point target{ static_cast<float>(x), static_cast<float>(y) };

	if (!initialized) {
		currentPos = { centerX, centerY };
		initialized = true;
	}

	if (std::hypot(target.x - prevTarget.x, target.y - prevTarget.y) > 5.0f) {
		prevTarget = target;
	}

	float dx = target.x - currentPos.x;
	float dy = target.y - currentPos.y;

	float dist = std::hypot(dx, dy);

	if (dist < 1.0f) {
		driver::mouse_move(microJitter(rng), microJitter(rng));
		return;
	}

	// randomly pause to simulate hesitation ~5% chance
	if (pauseChance(rng) < 5) {
		driver::mouse_move(microJitter(rng) * 0.5f, microJitter(rng) * 0.5f);
		return;
	}

	float dirX = dx / dist;
	float dirY = dy / dist;

	float baseSpeed = std::clamp(dist / 10.0f, 2.0f, 20.0f);
	float speed = baseSpeed * speedVariation(rng);
	float stepX = dirX * speed;
	float stepY = dirY * speed;

	// avoid straight line
	// perp vector: (-dirY, dirX)
	float jitterAmount = std::clamp(dist / 30.0f, 0.3f, 1.5f);
	float jitterX = -dirY * microJitter(rng) * jitterAmount;
	float jitterY = dirX * microJitter(rng) * jitterAmount;

	stepX += jitterX;
	stepY += jitterY;

	if (std::hypot(stepX, stepY) > dist) {
		stepX = dx;
		stepY = dy;
	}
  // uses mouse service callback to move mouse. https://github.com/moonlightrblx/reversing/blob/main/utils/kernelmouse.md for more info
	driver::mouse_move(stepX, stepY);

	currentPos.x += stepX;
	currentPos.y += stepY;
}
```
