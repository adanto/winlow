# Part 3 – Telemetry Tampering & Unhooking (ETW, Direct Syscalls)

**What this chapter covers**

* How Windows telemetry is produced (ETW, script logging) and where user-mode hooks sit relative to it
* Common tamper attempts: patching user-mode stubs, “unhooking” `ntdll`, and switching to direct syscalls
* Why kernel ETW and policy (PPL/WDAC/VBS/CET/CFG) outlive most user-mode games
* Practical ways to verify posture and distinguish real stealth from lab drift or brittle demos

## Core concepts

### The observability stack

On modern Windows, defenders see you from **multiple vantage points**:

* **ETW (Event Tracing for Windows):** kernel providers (Process, ImageLoad, FileIO, Registry, Thread, Network) and user-mode providers (PowerShell Script Block, AMSI Operational, AppLocker/WDAC).
* **User-mode hooks/shims:** EDRs may layer API shims (e.g., in `kernel32`, `advapi32`) to enrich telemetry or block dangerous calls; they do **not** replace ETW.
* **Policy:** PPL/WDAC/HVCI/CET/CFG change what code runs and who can tamper.

Attackers try to (1) **silence** user-mode hooks, (2) **avoid** user APIs (direct syscalls), or (3) **starve** ETW (disable providers, kill sessions). Only the first is usually reachable from low privilege; the others require **admin** or **kernel** effects and are noisy.

---

### User-mode hook evasion ≠ invisibility

Hooking commonly modifies the first bytes of a function (inline/trampoline) or redirects imports (IAT). “Unhooking” restores original bytes from a clean image or by re-mapping from disk. This may hide from **that** product’s user-mode logic, but kernel ETW still observes:

* Process/thread start/stop
* Image loads and memory map events
* Handle opens, registry/file I/O
* Network connects/accepts

When you measure stealth, ask: **did the kernel provider go quiet?** If not, the “bypass” is theater.

---

### Direct syscalls: change path, not outcome

“Direct syscall” stubs jump from user code to `syscall` with the right **system call number** and arguments, skipping user-mode hooks in `ntdll`. This avoids **that** hook, but:

* Kernel still receives the same **NT operation** (e.g., `NtWriteFile` → I/O manager).
* ETW **kernel** providers still log **the effect** (thread creation, file write, image load).
* Syscall numbers **change across builds**; hard-coded stubs are brittle.

CFG/CET, ACG, and **signing/policy** constraints continue to apply after the syscall returns.

---

### ETW shape and failure modes

ETW consists of **providers** (emitters) and **sessions** (consumers). Tamper options:

* **Disable provider** or **stop session:** requires admin; leaves logs (Service Control Manager, Security).
* **Patch `EtwEventWrite` in the process:** affects only that process; does not silence **kernel** ETW or other processes.
* **Starve consumers** (e.g., block Sysmon): again admin/noisy, and only reduces **that** consumer’s view.

Analysts should favor **first-party** kernel ETW (e.g., `Microsoft-Windows-Kernel-Process`) as the source of truth, then join with **user-mode** streams for context.

---

### CET/CFG & unhooking collisions

CET (Shadow Stack/IBT) and CFG punish sloppy inline patching and “unhooking”:

* Missing **ENDBR64** on a patched indirect entry → **IBT fault**.
* Trampolines that move indirect calls to non-CT addresses → **CFG guard** failure.
* Manual re-maps that forget **unwind** → exceptions/stack walking break during stress.

These are reliability landmines that defenders can watch for (fail-fasts with characteristic codes).

---

### Small, safe probes

```c
// Probe: compare first bytes of ntdll!NtCreateFile in memory vs. on-disk mapping
// cl /W4 /EHsc check_ntdll.c
#include <windows.h>
#include <stdio.h>

int wmain() {
    HMODULE ntd = GetModuleHandleW(L"ntdll.dll");
    FARPROC p   = GetProcAddress(ntd, "NtCreateFile");
    BYTE live[16] = {0}; memcpy(live, p, sizeof(live));

    // Map clean ntdll from disk without loading it into the module list
    HANDLE hFile = CreateFileW(L"C:\\Windows\\System32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
    HANDLE hMap  = CreateFileMappingW(hFile, 0, PAGE_READONLY | SEC_IMAGE, 0, 0, 0);
    LPVOID clean = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)clean;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)((BYTE*)clean + dos->e_lfanew);
    DWORD rva = 0; // naive export lookup omitted for brevity in this short probe
    // In practice: walk export dir to find NtCreateFile RVA
    // Here we just show the shape: compare 'live' to 'clean' and report diffs

    printf("Live ntdll!NtCreateFile bytes: ");
    for (int i=0;i<16;i++) printf("%02X ", live[i]); printf("\n");
    // ...compare against 'clean+rva' after resolving the export...
    UnmapViewOfFile(clean); CloseHandle(hMap); CloseHandle(hFile);
    return 0;
}
```

*Use:* sanity-check whether inline hooks changed `ntdll` in-memory. In real tooling, add proper export resolution and ignore benign hotpatch bytes.

```powershell
# Observe ETW sessions & kernel providers from user space (read-only)
Get-EtwTraceSession | Select Name, State, LoggerId, BufferSize, MaximumBuffers
# Quick kernel-process events snapshot (if you have rights to start a session, do so in a lab only)
Get-WinEvent -LogName 'Microsoft-Windows-Kernel-Process/Operational' -MaxEvents 10 |
  Select TimeCreated, Id, Message
```

---

### “Unhooking” patterns and tells

* **Re-map `ntdll`/`kernel32` as images** and copy over `.text` → look for **SEC\_IMAGE** views and **memcpy** into RX.
* **IAT re-seeding** (resolve imports from a clean view) → **PAGE\_READWRITE** flips on **FirstThunk**.
* **Syscall-only stubs** → short private RX pages with `mov r10, rcx; mov eax, <id>; syscall; ret`.

Defenders can stitch: **(W→X or RW on .text)** + **EtwEventWrite drop** + **continued high-risk ops** = strong tamper signal.

---

### Where policy bites tamper

* **WDAC/App Control:** blocks unsigned/unapproved DLLs that would perform unhooking; blocks LOLBins that loaders rely on.
* **PPL:** prevents opening protected processes to patch their telemetry.
* **VBS/HVCI:** blocks runtime changes to **kernel** code; neuters many “turn off ETW” kernel tricks.
* **CET/CFG:** breaks fragile trampolines and indirect entries used by patchers.

## Why this matters for exploitation / anti-exploit / malware analysis

Post-exploitation implants must **survive observation**. User-mode unhooking and direct syscalls buy **tactical** relief from specific products but rarely produce **strategic** invisibility because **kernel ETW** and **policy** persist. For defenders, this is good news: prioritize **kernel-level facts** and the **sequence** (patch → silence → sensitive action), and you will separate credible stealth from brittle lab showpieces.

## APIs and functions

* `EtwEventWrite` / `EventRegister` — user-mode ETW emission; common tamper target (patching in-process).
* `NtTraceControl` — controls ETW in the kernel; admin-level and noisy when abused.
* `GetModuleHandleW` / `GetProcAddress` / `MapViewOfFile` — used by “unhookers” to fetch clean bytes from disk.
* `VirtualProtect` / `NtProtectVirtualMemory` — permission flips (RW on `.text`, W→X on private RX).
* `RtlAddFunctionTable` — needed for stable manual maps (exceptions); absence betrays crude loaders during stress.
* `IsProcessorFeaturePresent(PF_SHADOW_STACK)` — CET availability probe; predicts whether sloppy patches crash.
* `AmsiScanString` / `EtwEventWrite` (PowerShell/AMSI providers) — correlate script scanning and logging with tamper attempts.

## Pitfalls, detection notes, and anti-analysis gotchas

* **Silent providers vs. no provider:** “AMSI/ETW is quiet” can mean **absent** provider or disabled session, not stealth; verify posture first.
* **Bitness mismatches:** WOW64 has **two** `ntdll`s; unhooking x86 does nothing for x64 processes and vice-versa.
* **Over-trusting strings:** API hashing removes names, not **effects**; kernel ETW still shows process/thread/file/registry.
* **IAT vs inline confusion:** restoring imports is lower risk than rewriting prologues; misclassify carefully.
* **Crash misattribution:** IBT/CFG fail-fasts caused by sloppy patching look like “random instability” without symbols and codes.
* **“Direct syscalls are invisible” myth:** they bypass **user-mode hooks** only; NT effects remain logged and enforce policies.
* **Session tamper noise:** stopping base kernel sessions is admin-only and leaves **auditable** Security/SCM traces.

## Cross-references

* Hook mechanics and metadata (ENDBR, CFG, unwind) are introduced in **Compiler & Hardware CFI: CFG, CET (Shadow Stack/IBT)** and **Compiler & EH Hardening**.
* Memory provenance and permission flips live in **Memory & Virtual Address Space** and **DEP / NX / W^X**.
* Process/handle identity constraints (PPL, WDAC, VBS/HVCI) are detailed in **Trust & Integrity**.
* AMSI and script host scanning appears in **AMSI & Script Host Internals**.
* Loader internals and “manual map” gotchas are in **Windows Loader & Image Activation**.

## Glossary

* **ETW (Event Tracing for Windows):** OS framework for structured telemetry from kernel and user mode.
* **User-mode hook:** Inline/IAT modification that intercepts API calls inside a process.
* **Direct syscall:** User stub that invokes `syscall` directly, skipping `ntdll` wrappers.
* **Unhooking:** Restoring original code bytes to remove user-mode hooks.
* **PPL (Protected Process Light):** Policy restricting which processes can be opened or injected into.
* **WDAC/App Control:** Allow-list policy controlling which code loads.
* **CET/CFG:** Hardware/compile-time control-flow integrity features that break sloppy patches.
* **SEC\_IMAGE mapping:** Read-only image mapping used to fetch clean bytes for comparison or restore.
* **Kernel provider:** ETW source in kernel mode (e.g., Process, ImageLoad) that user-mode patches cannot silence.
* **Fail-fast:** Immediate termination when guards detect invalid control flow or memory invariants.

## Key takeaways

* User-mode unhooking and direct syscalls only dodge **that** hook; kernel ETW and policy still see and enforce.
* Favor **kernel** telemetry as truth and correlate **sequence**: patch → drop in user-mode events → sensitive NT effects.
* CET/CFG/WDAC/VBS/PPL shrink the blast radius of tamper and turn many “stealth” tricks into **crashes** or **denied loads**.
* Verify **posture** before calling something a bypass (providers present, sessions running, policy mode).
* In triage, prioritize **provenance + permissions + control-transfer** over strings; effects outlive obfuscation.
