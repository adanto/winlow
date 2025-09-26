# Part 1 – Fundamentals: Introduction

**What this chapter covers**

* The mental model for Windows internals used throughout the book (kernel vs. user mode, NT layer, objects/handles)
* How to read Windows from an attacker/defender perspective without getting lost in trivia
* Minimum lab setup and safety habits for experimenting with low-level code
* Conventions: naming, call stacks, symbols, and how we reference Win32 ↔ NTAPI ↔ syscalls
* A tiny set of hands-on examples to anchor the concepts

## Core concepts

### Two worlds, one boundary: user mode, kernel mode, and the NTAPI

Windows runs most applications in **user mode** and reserves **kernel mode** for the OS core and drivers. The seam between them is the **system call** interface provided by `ntdll.dll` (the **NTAPI**). Win32 APIs (in `kernel32`, `advapi32`, `user32`, etc.) are convenience layers that frequently funnel into the NTAPI.

```c
// Example: calling an NT native API directly (x64, minimal error handling)
#include <windows.h>
typedef NTSTATUS (NTAPI *pNtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);

int main(void) {
    pNtQuerySystemInformation NtQSI =
        (pNtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    BYTE buf[4096]; ULONG retLen = 0;
    NTSTATUS s = NtQSI(5 /*SystemProcessInformation*/, buf, sizeof(buf), &retLen);
    return (int)s;
}
```

Direct NT calls are common in malware, EDR agents, and exploits for precision and to avoid high-level patching. We’ll treat the **NT layer** as the reference truth for behavior and semantics; Win32 is a caller-friendly facade.

### Objects and handles: Windows’ universal currency

Nearly everything is an **object** (process, thread, file, registry key, section, event). User-mode code gets a **handle** with an **access mask** describing allowed operations. The **Security Reference Monitor (SRM)** evaluates the caller’s **access token** against the object’s **security descriptor** to grant/deny access. Understanding this flow is essential for both exploitation (stealing/duplicating handles, token games) and defense (least privilege, broker processes).

```powershell
# Example: inspect handles with PowerShell + SysInternals Handle.exe-style output via CIM/WMI
Get-Process | ForEach-Object {
  "{0,-28} PID {1}" -f $_.ProcessName,$_.Id
}
# (For deep handle enumeration you’ll learn to use NtQuerySystemInformation/SystemHandleInformation.)
```

We will constantly reason in “object → handle → access” terms, because most “impossible” actions fail here—not in API sugar.

### Loader shapes execution: images, sections, imports

When you start a process or load a DLL, the **loader** (in `ntdll` + `kernel32`) maps the PE image into memory, resolves imports, applies relocations, runs TLS callbacks, and calls `DllMain`. The **Process Environment Block (PEB)** and **Loader Data (Ldr)** maintain module lists and lookup structures attackers love to traverse, tamper with, or hide from.

```text
!peb    ; WinDbg example: dump the Process Environment Block to see loader state
!teb    ; Thread Environment Block for current thread (stack limits, TLS, etc.)
lm      ; List loaded modules (trust, order, suspicious gaps)
```

This is the foundation for Part 3 topics like **anti-disassembly** and **unhooking**, and for Part 4’s **ROP/JOP** planning, where section permissions and import layout drive gadget availability.

### Scheduling and async surfaces: threads, APCs, callbacks

Windows schedules **threads**. Work is often delivered asynchronously through **APCs**, completion ports, window messages, and ETW/user callbacks. That yields rich **callback surfaces** where defenders instrument and attackers pivot (e.g., Early-Bird APC, queueing into a suspended thread before the loader finishes, or tampering with notification routines).

### IPC is everywhere, so is trust

**ALPC**, **RPC**, **COM**, and **named pipes** are how processes cooperate—or how low-privilege code persuades a high-privilege service to do work. Exploit chains frequently cross integrity levels or sessions via IPC. Defensive broker processes and WDAG/AppContainer sandboxes depend on correct boundary checks here.

### Working model for this book

* We reason from **observables** (ETW, call stacks, handles, sections) back to **intent**.
* We default to **native semantics** (NTAPI) and treat Win32 as a convenience layer that might be shimmed, hooked, or virtualized.
* We carry a **lab triad**: a debugger (WinDbg Preview), a disassembler, and a telemetry view (ETW trace or your EDR).

### Why this matters for exploitation / anti-exploit / malware analysis

Exploits bend rules at the **object/handle** and **loader** layers; anti-exploit hardening observes or blocks those bends (token misuse, RX pages, suspicious image loads). Malware evasion shifts behavior down to NT to dodge user-mode hooks, or abuses loader/PEB quirks to disappear. Analysts who speak “NTAPI + objects + loader” can pivot fast between reversing, building reliable exploits, and writing resilient detections.

## APIs and functions

* `NtQuerySystemInformation` – enumerate system objects (processes, handles, modules) from the NT layer.
* `NtOpenProcess` / `NtOpenThread` – obtain handles with specific access; core to injection and detection.
* `NtMapViewOfSection` – map executable/writable memory across processes; backbone of manual mapping.
* `RtlCreateUserThread` / `NtCreateThreadEx` – create/hijack threads with fine-grained attributes.
* `LdrLoadDll` – the loader’s native entry for DLL mapping and initialization.
* `ZwProtectVirtualMemory` (user alias of `NtProtectVirtualMemory`) – change page protections; watch for W→X flips.
* `AlpcConnectPort` / `NtAlpcSendWaitReceivePort` – ALPC primitives for broker/service IPC.
* `EtwEventWrite` – user-mode event write; useful for observing/self-telemetry in PoCs (and for tamper hunts).

## Pitfalls, detection notes, and anti-analysis gotchas

* “It’s Win32, not NT” confusion: high-level APIs may fail or be virtualized while the NT path behaves differently. Validate at the NT layer.
* Handle leaks and duplicated tokens: a single over-privileged inherited handle can collapse isolation.
* Implicit loader execution: TLS callbacks and `DllMain` reentrancy can deadlock your PoC or skew traces.
* Page protections lie: injected code may reside in **mapped sections** that don’t look like a classic RWX heap.
* Sandbox artifacts: timing, small RAM/CPU, odd device lists, and missing UI queues affect behavior.
* Debugger side effects: breakpoints and page-guard tricks change memory protections and timing; account for this in perf/timing checks.
* Hook visibility: user-mode hooks in `kernel32`/`advapi32` are trivial to skirt; measure at `ntdll` or below when possible.

## Cross-references

* We only gestured at loader internals; the deep dive is in **Windows Loader & Image Activation** (Part 1).
* System calls and the NT boundary get rigorous treatment in **Syscalls & the NTAPI Boundary** (Part 1).
* Threading, APCs, and scheduling mechanics continue in **Scheduling, APCs & Callback Surfaces** (Part 1).
* IPC details and broker patterns appear in **IPC (ALPC, RPC, COM, Pipes)** (Part 1).
* Mitigations that constrain memory and control flow are in **DEP / NX / W^X**, **ASLR / KASLR**, and **Compiler & Hardware CFI: CFG, CET (Shadow Stack/IBT)** (Part 2).
* Trust boundaries like **Secure Boot, WDAC/App Control, Code Integrity, PatchGuard, VBS/HVCI, PPL** are summarized in Part 2’s **Trust & Integrity** chapter.

## Glossary

* **NTAPI**: The native API exported by `ntdll.dll` that marshals user-mode requests into kernel system calls.
* **Object/Handle**: Kernel-mode resource + user-mode reference used to perform operations on that resource.
* **Access Token**: Security descriptor representing a subject (user, groups, privileges) used during access checks.
* **Security Descriptor (SD)**: ACL-backed policy on an object defining who can do what.
* **PEB/TEB**: User-mode structures with process/thread metadata (modules, TLS, stacks).
* **Section Object**: Memory-mapped file or anonymous shared memory primitive; basis for image mapping and shared code.
* **APC (Asynchronous Procedure Call)**: Mechanism to queue code execution into a thread’s context at safe points.
* **ALPC**: High-performance local IPC used by the OS and brokers; replaces classic LPC.
* **ETW**: Event Tracing for Windows; high-fidelity telemetry bus used by the OS and security tools.
* **Broker**: Higher-privilege service that performs restricted operations on behalf of a lower-privilege client via IPC.

## Key takeaways

* Think in **NT primitives**: objects, handles, tokens, sections, and the loader’s state.
* Always map **Win32 behavior** back to **NT semantics**; that’s where exploits and mitigations actually meet.
* Loader and memory layout dictate both **evasion** options and **exploit** reliability.
* Robust analysis blends a debugger, a disassembler, and **telemetry** (ETW/EDR) to reconcile ground truth.
* Practice in a **snapshot-backed VM**, and expect sandboxes and hooks to perturb your observations.

