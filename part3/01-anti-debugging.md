# Part 3 – Anti-Reversing & Evasion

**What this chapter covers**

* Threat model and goals behind anti-analysis and evasion on Windows
* Common anti-debugging, anti-disassembly, and sandbox/VM checks—what they do and what they actually prove
* Loader-level evasion (manual mapping, API hashing, delayed resolution) and how it collides with mitigations
* Practical signals analysts can hunt for in memory, ETW, and module state without “chasing tricks”
* Minimal, safe examples that demonstrate the shape of checks—anchored in detection and triage

## Core concepts

### What “evasion” tries to buy

Evasion buys **time** and **ambiguity**. Malware aims to (1) avoid running in analysis sandboxes, (2) degrade tools (disassemblers, debuggers, EDR shims), and (3) lower its telemetry footprint so post-facto forensics cannot reconstruct intent. The trick family is broad but collapses to a few categories: **who is watching** (anti-debug), **where am I** (sandbox/VM), **how am I mapped** (loader visibility), and **what logs me** (telemetry tamper/avoid).

---

### Anti-debugging: checks, traps, and time

Most anti-debugging is not magic; it’s the same kernel signals you already know from the **Syscalls & NTAPI** chapter, surfaced via Win32 or `ntdll`.

```c
// Three debugger tells (illustrative, not comprehensive)
#include <windows.h>
#include <winternl.h>
#include <stdio.h>

typedef NTSTATUS (NTAPI *PFN_NtQueryInformationProcess)(
    HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

int main() {
    printf("IsDebuggerPresent: %d\n", IsDebuggerPresent());

    BOOL crd = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &crd);
    printf("CheckRemoteDebuggerPresent: %d\n", crd);

    PROCESS_BASIC_INFORMATION pbi = {0};
    PFN_NtQueryInformationProcess NtQIP =
        (PFN_NtQueryInformationProcess)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
    NTSTATUS s = NtQIP(GetCurrentProcess(), ProcessDebugPort, &pbi, sizeof(pbi), NULL);
    printf("NtQueryInformationProcess(ProcessDebugPort): 0x%08X\n", s);
    return 0;
}
```

Other patterns:

* **Hide-from-debugger**: `NtSetInformationThread(ThreadHideFromDebugger)` changes how exceptions deliver into a debugger.
* **OutputDebugString** traps: call with a long string and time the return; some debuggers eat the call slowly.
* **Timing**: `QueryPerformanceCounter`/`GetTickCount64` around regions that breakpoints will stretch; some code also probes **APC delivery** anomalies (see scheduling chapter).
* **Exception gymnastics**: VEH/SEH chains used as poor-man’s obfuscation; naive debuggers lose “first-chance” context.

**Analyst stance:** treat these as *presence* signals, not *proof* of analysis. Many enterprise tools legitimately set debug flags. Join with **call stack provenance** (private RX stubs vs. expected veneers) and **token/handle behavior** before you escalate.

---

### Anti-disassembly: make static tools lie

Static tools expect clean control flow. Evasive code uses:

* **Opaque predicates**: conditions that are always true/false at runtime but look complex statically.
* **Instruction overlap** (mostly x86): place data in code and branch into the “middle”; linear sweep gets confused.
* **Junk bytes & decoy exports**: inflate function bodies or place exports that do nothing.
* **API hashing**: avoid import names; compute `GetProcAddress` targets by hash at runtime.

```c
// Tiny API hash demo: resolve kernel32!Sleep without import name (educational only)
#include <windows.h>
#include <stdint.h>
#include <stdio.h>

static uint32_t djb2w(const wchar_t* s){ uint32_t h=5381; while(*s) h=((h<<5)+h) + (uint32_t)towupper(*s++); return h; }

int main(){
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC found = NULL;
    // Iterate exports; pick a tiny subset just to show shape
    ULONG size=0; PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)ImageDirectoryEntryToData(k32, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &size);
    DWORD* names = (DWORD*)((BYTE*)k32 + exp->AddressOfNames);
    WORD* ords = (WORD*)((BYTE*)k32 + exp->AddressOfNameOrdinals);
    for (DWORD i=0;i<exp->NumberOfNames;i++){
        const wchar_t wbuf[32] = L"Sleep"; // pretend this is “hidden”; the point is hashing, not stealth
        if (djb2w(wbuf) == djb2w(L"Sleep")){
            found = (FARPROC)((BYTE*)k32 + ((DWORD*)((BYTE*)k32 + exp->AddressOfFunctions))[ords[i]]);
            break;
        }
    }
    printf("Sleep @ %p\n", found);
    return 0;
}
```

**Analyst stance:** API hashing does not hide **behavior**. Dynamic traces (ETW stacks, call targets) and **image provenance** defeat it. For disassembly, pivot to **recursive traversal** from real entry points and cross-check with runtime traces.

---

### Sandbox & VM evasion: environment and economics

Typical probes look for **resource limits** and **artifacts** rather than specific vendors.

* **Time dilation**: long sleeps, `WaitForSingleObject(INFINITE)` on non-signaled events, or watchdog patterns that look for user interaction (mouse entropy).
* **Hardware/firmware hints**: low RAM/CPU cores, hypervisor brand strings, virtual device IDs, SCSI vendor tags.
* **File/registry canaries**: looking for well-known analysis tools or sandbox user profiles.
* **Network predictability**: low-latency DNS/resolver quirks and blocklisted subnets.

```powershell
# Benign environment probe (shape only): cores, RAM, uptime
$envInfo = [pscustomobject]@{
  Cores  = (Get-CimInstance Win32_Processor).NumberOfLogicalProcessors
  RAMGB  = [math]::Round((Get-CimInstance Win32_OperatingSystem).TotalVisibleMemorySize/1MB,1)
  Uptime = (Get-Date) - (gcim Win32_OperatingSystem).LastBootUpTime
}
$envInfo
```

**Analyst stance:** a single “VM tell” is weak. Stack them. If malware gates payload on three or more probes and you see **branching to dead paths** in a rich, non-VM environment, you’ve found evasive gating.

---

### Loader visibility and “unhookable” execution

Manual mapping and delayed resolution try to avoid **loader** and **import** visibility (see “Windows Loader & Image Activation”). Indicators:

* **RX Private** with no module record and missing **unwind/CFG** metadata.
* Imports resolved late via **downloaded** modules or **export-forward chains**.
* **Direct syscalls** to skip user-mode hooks (telemetry still sees the NT operation).

```text
; WinDbg triage sketch
!address                    ; classify RX regions: Image vs Private
lmv m ntdll                ; confirm real system ntdll (signer, base) before trusting stubs
!peb / !ldr                ; manual maps won’t show; correlate with RX Private
```

**Analyst stance:** provenance-first. Module lists lie; VADs do not. If code executes from RX Private and never registers **function tables** or **CFG** call targets, it is fragile and loud under pressure.

---

### Telemetry tampering & “low-noise” execution

Common attempts:

* **Patching ETW providers**: flip enable flags or stub out `EtwEventWrite` in user mode.
* **AMSI bypasses**: short-circuit scanning in script hosts (see its dedicated chapter).
* **Living off the land (LOLBins)**: push behavior into signed tools (PowerShell, `rundll32`, `mshta`, WMI) that already have telemetry allow-lists.

```powershell
# Analyst-side: spot sudden ETW quietness in a process that was chatty
Get-WinEvent -LogName "Microsoft-Windows-Kernel-Process/Operational" -MaxEvents 100 |
  ? { $_.Message -match "Image Load" -or $_.Message -match "Process Start" } |
  Group-Object Id | Select Name,Count
```

**Analyst stance:** treat **silence** as a signal only when you expected noise. Join with **recent memory flips** (W→X), **thread creation**, and **handle opens** to sensitive targets.

---

### What actually survives contact with defenders

Tricks decay; **behavior** endures. The pieces that consistently help attackers are: (1) **capability gating** (only run payload if conditions are met), (2) **loader independence** (operate without import tables), and (3) **privilege surface shaping** (use brokers/IPC to perform actions with cleaner provenance). Defenders win by correlating **memory provenance + object access + control-flow changes**.

### Why this matters for exploitation / anti-exploit / malware analysis

Evasion techniques define the **first 60 seconds** of an investigation: why a sample did not run, why a tool crashed, why telemetry went quiet. Exploit reliability also depends on **debugger**, **scheduler**, and **loader** behaviors these tricks manipulate. Analysts who can reduce each evasion to **one sentence of ground truth** (“it checks for a debugger and sleeps if found; it manual-maps a DLL and executes from RX Private”) keep focus on capability and intent, not theatrics.

## APIs and functions

* `IsDebuggerPresent` / `CheckRemoteDebuggerPresent` – quick debugger probes; easy to detect, easy to spoof.
* `NtQueryInformationProcess` (e.g., `ProcessDebugPort`, `ProcessDebugFlags`) – native debugger state queries.
* `NtSetInformationThread(ThreadHideFromDebugger)` – alters exception delivery to attached debuggers.
* `QueryPerformanceCounter` / `GetTickCount64` – timing probes that detect breakpoints/slow emulation.
* `AddVectoredExceptionHandler` – VEH-based anti-debug and obfuscation patterns; also used legitimately by instrumentation.
* `LdrLoadDll` / `GetProcAddress` – delayed resolution, hashing; correlate with missing import tables.
* `NtAllocateVirtualMemory` / `NtProtectVirtualMemory` – W→X transitions; pair with provenance (Private vs Image).
* `EtwEventWrite` (user-mode stub) – tamper target; kernel ETW remains authoritative.

## Pitfalls, detection notes, and anti-analysis gotchas

* **Tool bias:** single-stepping changes timing and can “prove” fake anti-debug claims; corroborate with ETW and off-box tracers.
* **Overfitting to strings:** API hashing removes names, not behavior. Dynamic traces and memory provenance still reveal intent.
* **VM tells are noisy:** low resources are common on real endpoints (VDI, laptops on battery). Require several independent signals.
* **Manual map crashers:** no unwind/CFG/CET metadata means exceptions or indirect calls may fail-fast; use this to your advantage.
* **Tamper illusions:** patching `EtwEventWrite` in one module does not silence **kernel** ETW; don’t declare “stealth” from user-mode stubs.
* **WOW64 mismatches:** x86-on-x64 inserts an extra thunk; attach the right-bit debugger and collect both user-mode `ntdll`s.
* **Global hooks collateral:** `SetWindowsHookEx`-style global hooks for “anti-debug” can trip PPL/CI policies and leave crisp logs.

## Cross-references

* Low-level entry and memory permission changes rely on **Syscalls & the NTAPI Boundary** and **Memory & Virtual Address Space** (Part 1).
* Manual mapping, import resolution, and image metadata are in **Windows Loader & Image Activation** (Part 1).
* APC timing and Early-Bird patterns intersect **Scheduling, APCs & Callback Surfaces** (Part 1).
* Telemetry unhooking and direct-syscall nuances expand in **Telemetry Tampering & Unhooking (ETW, Direct Syscalls)** (Part 3).
* Script-specific evasion (AMSI, LOLBins) lives in **AMSI & Script Host Internals** (Part 3).
* Mitigations that break sloppy obfuscation (DEP/W^X, CFG/CET) are in **Part 2** chapters.

## Glossary

* **API hashing**: computing export addresses by hash to avoid readable import names.
* **Opaque predicate**: a branch condition known at build time but difficult for static tools to simplify.
* **Manual mapping**: loading an image without the OS loader’s book-keeping (no PEB/Ldr entries).
* **RX Private**: executable, anonymous memory region (not backed by an image or file).
* **VEH/SEH/UEF**: vectored, structured, and unhandled exception layers; often abused for anti-debug tricks.
* **Direct syscall**: invoking `syscall` with a custom stub to skip user-mode hooks (still visible to the kernel).
* **ETW tamper**: attempts to neuter user-mode event writes; usually incomplete against kernel providers.
* **Sandbox gating**: conditional execution based on environment/signal checks designed to avoid analysis.
* **Opaque loader**: a custom loader that hides imports, relocations, and TLS callbacks from standard tooling.
* **LOLBins**: signed system utilities repurposed to execute attacker logic.

## Key takeaways

* Reduce tricks to **capability statements**—who watches, where we are, how code is mapped, what logs it—and hunt those, not strings.
* Memory **provenance** and **sequence** (W→X → execute; delayed import → sensitive call) beat name-based obfuscation.
* ETW and kernel views outlive user-mode patching; treat unexpected **silence** as a correlation signal, not a conclusion.
* Many evasions are fragile under modern mitigations (CFG/CET, PPL, WDAC); push analysis where they fail-fast.
* For reliable triage, always join **thread/process identity**, **region provenance**, and **object/handle activity**—that graph is hard to fake.
