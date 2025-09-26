# Part 1 – Fundamentals: Windows Loader & Image Activation

**What this chapter covers**

* How images (EXEs/DLLs) are mapped: sections, relocations, imports, TLS, entry routines
* The user-mode loader path (`LdrLoadDll`, `Ldrp*`) vs. kernel-assisted image activation
* DLL search order, SxS/activation contexts, delay-load, and KnownDLLs
* How the loader publishes state (PEB/Ldr lists) and how manual maps evade it
* Practical knobs that change behavior: `LoadLibraryEx` flags, default DLL directories, WOW64

## Core concepts

### Image mapping is not “load and copy”—it is sections and views

The loader maps a PE **image** by creating a **section object** from the file and mapping **views** (RX, R, RW) into the process. If the preferred image base collides, **relocations** patch absolute addresses. Imports are materialized into the **IAT** by walking the import tables and resolving symbols from dependency modules. Many defensive signals (e.g., RX private vs. image-backed) arise from these differences.

```c
// Minimal peek at loader state via PEB->Ldr (x64, error checks omitted)
#include <windows.h>
#include <winternl.h>

typedef struct _LDR_DATA_TABLE_ENTRY64 {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY64, *PLDR_DATA_TABLE_ENTRY64;

int main() {
    PPEB peb = (PPEB)__readgsqword(0x60);               // PEB from GS on x64
    PPEB_LDR_DATA ldr = peb->Ldr;
    for (LIST_ENTRY* e = ldr->InLoadOrderModuleList.Flink; e != &ldr->InLoadOrderModuleList; e = e->Flink) {
        PLDR_DATA_TABLE_ENTRY64 m = (PLDR_DATA_TABLE_ENTRY64)e;
        wprintf(L"%wZ @ %p (%lu KiB)\n", &m->BaseDllName, m->DllBase, m->SizeOfImage/1024);
    }
    return 0;
}
```

**Analyst note:** **manual-mapped** modules usually do not appear in these lists and lack a backing section/file mapping, changing how debuggers and ETW attribute code.

### Entry sequencing: DllMain, TLS callbacks, and loader lock

After mapping, the loader: fixes **relocations**, resolves **imports**, registers **exception/unwind** data, runs **TLS callbacks**, and finally calls `DllMain` with `DLL_PROCESS_ATTACH` (for EXEs, the process “entry” is ultimately reached after CRT setup). Reentrancy is guarded by the **loader lock**; re-entry or heavy work in `DllMain` can deadlock or crash.

**Practical guidance:** keep `DllMain` trivial; do real work in a worker thread after `DLL_PROCESS_ATTACH`.

### Imports, export forwarding, and delay-load

* **IAT**: functions the image consumes; populated during load.
* **EAT**: functions an image exports; can **forward** to another DLL (e.g., `API-MS-Win-*` forwarding).
* **Delay-load**: imports resolved on first call via a helper thunk; defenders flag late network or path lookups tied to delay-load edges.

### DLL search order and its hardening

Default search historically favored the application directory and current directory, enabling **DLL search-order hijacks**. Modern hardening uses:

* `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS)`
* `AddDllDirectory` / `RemoveDllDirectory` to whitelist paths
* `LoadLibraryExW` with `LOAD_LIBRARY_SEARCH_*` flags
* **KnownDLLs** (kernel-managed) for core OS DLLs

```powershell
# Harden search path per-process (PowerShell with Add-Type)
Add-Type -Name K32 -Namespace X -MemberDefinition @"
    using System;
    using System.Runtime.InteropServices;
    public static class K32 {
        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern bool SetDefaultDllDirectories(uint DirectoryFlags);
    }
"@
# 0x00000800 | 0x00001000: SYSTEM32 + default dirs; no current dir
[void][X.K32]::SetDefaultDllDirectories(0x800 + 0x1000)
```

**Security impact:** this breaks many trivial side-loading chains and stabilizes dependency resolution.

### SxS and activation contexts

**Side-by-side (SxS)** manifests and **activation contexts** pick specific assembly versions and redirect dependencies (COM classes, fusion assemblies). Malware and packers sometimes ship fake or local manifests to steer loads; defenders correlate **ActCtx** activations with unexpected module resolution.

### WOW64: two `ntdll`s, two views of the world

On x64 Windows, 32-bit processes use a WOW64 `ntdll` and a different loader path. PE sizes, pointer math, and tool output differ. Cross-bitness loaders must inject the correct stub and interact with the correct `PEB/Ldr`.

### What the kernel does vs. what `ntdll` does

The **kernel** validates the file, creates the **section**, arranges memory protections, and starts the initial thread. The **user-mode loader** (in `ntdll`) finishes the high-level work: imports, TLS, calling `DllMain`. Understanding this split helps when correlating ETW process start events (kernel) with late user-mode anomalies (e.g., TLS-triggered code before main).

```text
; WinDbg quick loader triage
!peb                 ; dump PEB (loader data, process parameters)
!ldr                 ; enumerate loader module lists (if available)
lmv m kernel32       ; view one module's ranges/sections
!dh <mod_base> -f    ; parse PE headers (imports/exports/directories)
!address             ; layout (image vs private RX)
```

**Analyst tip:** an RX region not covered by `lm` (no module record) is a strong “manual map / JIT / shellcode” clue.

### Manual mapping and “unhookable” images

**Manual mapping** implements the loader’s work: map sections, relocate, resolve imports, register EH tables, run TLS, and optionally call the entry. Because it skips the OS loader’s **bookkeeping** (PEB/Ldr lists, `LdrpHashTable`), it evades many user-mode heuristics and simple API hooks. The trade-off: you must mimic quirks (guard CF tables, SEH unwind registration, delay-load helpers) correctly or crash under pressure.

### Loader-relevant PE header bits

PE fields influence loader behavior and mitigations:

* **`DllCharacteristics`**: `NXCompat`, `DynamicBase` (ASLR), `NoSEH`, `GuardCF`, `HighEntropyVA`
* **Section flags**: `IMAGE_SCN_MEM_EXECUTE`, `WRITE`—watch for W→X transitions
* **Data directories**: imports/exports, relocation table, TLS directory, load config (CFG guard tables)

**Reminder:** policy-centric detail (CFG/CET, DEP, CI) belongs to Part 2’s mitigations chapters; here we only identify how the loader consumes these fields.

### Activation flow in one breath

Open → create section → map image → relocate if needed → build imports → register exception info → run TLS → call `DllMain`/entry. Any hook or detection placed along this chain changes reliability and observability: e.g., **Early-Bird** code can land before full user-mode init; **ETW ImageLoad** events give you provenance and signature state.

### Why this matters for exploitation / anti-exploit / malware analysis

Side-loading and delay-load hijacks abuse search and resolution rules; defenders harden with KnownDLLs and `LoadLibraryEx` flags. Manual mapping evades user-mode visibility but leaves memory-provenance breadcrumbs (private RX, atypical unwind tables). Many evasions (IAT patching, import spoofing, EAT forwarding tricks) only make sense when you can mentally “run the loader by hand.”

## APIs and functions

* `LdrLoadDll` – native DLL load; bypasses Win32 veneers and common user-mode hooks.
* `LoadLibraryExW` – controlled DLL loading with `LOAD_LIBRARY_SEARCH_*` and mapping flags.
* `SetDefaultDllDirectories` / `AddDllDirectory` – opt-in hardening of search order.
* `NtCreateSection` / `NtMapViewOfSection` – low-level creation/mapping of image sections.
* `RtlImageNtHeader` / `RtlImageDirectoryEntryToData` – parse PE headers and directories in memory.
* `RtlAddFunctionTable` – register unwind/exception data for custom/just-in-time code regions.
* `ResolveDelayLoadedAPI` (runtime helper) – participates in delay-load thunk resolution.
* `LdrGetProcedureAddress` – export resolution at the NT layer.

## Pitfalls, detection notes, and anti-analysis gotchas

* **`DllMain` reentrancy:** doing work that loads more DLLs or takes locks deadlocks under the loader lock.
* **Delay-load surprises:** first-call network/UNC resolutions can look like exfiltration or cause timeouts in sandboxes.
* **Search-order regressions:** calling `LoadLibraryW` without hardened directories reopens side-loading; fix with `SetDefaultDllDirectories`.
* **Manual map crashers:** skipping `RtlAddFunctionTable` leaves threads without unwind info (AV on exceptions, broken SEH).
* **WOW64 mismatches:** parsing headers as 64-bit on a 32-bit target (or vice versa) yields bad field offsets and false signals.
* **SxS leaks:** failing to deactivate activation contexts bleeds redirections into unrelated loads; intermittent, hard-to-repro bugs.
* **Hook visibility:** hooking `kernel32!LoadLibrary*` is trivial to bypass; anchor detection closer to `LdrLoadDll` or section mappings.
* **KnownDLLs assumptions:** only core OS DLLs live there; “it’s in KnownDLLs so it’s safe” is not a general rule.

## Cross-references

* Process/thread scaffolding, suspended start, and token context are in **Processes & Threads** (Part 1).
* Memory provenance (image vs. private), VADs, and page protections appear in **Memory & Virtual Address Space** (Part 1).
* NT system call stubs and direct-syscall variants belong to **Syscalls & the NTAPI Boundary** (Part 1).
* Anti-disassembly, IAT/EAT patching, and unhooking tactics continue in **Anti-Disassembly** and **Telemetry Tampering & Unhooking (ETW, Direct Syscalls)** (Part 3).
* Policy bits in PE headers (CFG/CET/DEP/Code Integrity) are fully treated in **DEP / NX / W^X**, **ASLR / KASLR**, and **Compiler & Hardware CFI: CFG, CET (Shadow Stack/IBT)** (Part 2).

## Glossary

* **IAT (Import Address Table)**: per-module table of function pointers populated during load (or on first use for delay-load).
* **EAT (Export Address Table)**: functions a module exposes; may forward to another module.
* **Relocations**: patches applied when an image cannot load at its preferred base.
* **TLS Callback**: function invoked by the loader before `DllMain`, for each thread/process event.
* **Loader Lock**: internal lock guarding loader state; reentrancy hazards in `DllMain`.
* **KnownDLLs**: OS-managed mapping of core DLLs into processes from a trusted section.
* **Activation Context (ActCtx)**: SxS runtime describing redirects/bindings for assemblies/COM.
* **Manual Mapping**: loading an image without the OS loader’s bookkeeping, implemented by the caller.
* **DllCharacteristics**: PE flags that influence loader/mitigation behavior (ASLR, NX, CFG).
* **Section Object**: kernel abstraction backing memory-mapped files and images.

## Key takeaways

* The loader is a **state machine**: map → relocate → import → TLS → entry; each step is a hook and a signal.
* **Search order and SxS** decide *which* DLL you run; harden with `LoadLibraryEx` flags and default directory policies.
* **Manual maps** evade loader lists but betray themselves via memory provenance and missing unwind/CFG metadata.
* PE header bits (`DllCharacteristics`, directories) steer both **mitigations** and **resolution paths**—read them first.
* Anchor analysis near **`ntdll`** and **section mappings**; Win32 veneers are easy to spoof or bypass.

