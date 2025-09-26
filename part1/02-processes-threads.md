# Part 1 – Fundamentals: Processes & Threads

**What this chapter covers**

* The Windows process/thread model: boundaries, tokens, and execution context
* Creation paths (`CreateProcessW`, `NtCreateUserProcess`) and why suspended start matters
* Thread lifecycles, stacks, contexts, affinity, and impersonation
* Practical handles-and-access mindset for analysis, exploitation, and defense
* Job objects, mitigation policies, and WOW64 quirks that change behavior

## Core concepts

### The process as a security and resource boundary

A **process** is a container: an address space (VADs/sections), a primary token (identity/privileges), and state (PEB, handle table, job membership, mitigation policies). A **thread** is the unit of scheduled execution: it owns a stack, a **TEB**, a CPU context, and optional impersonation. Most “how did this execute?” questions reduce to “which thread, with which token, in which process address space.”

```c
// Create a process suspended, then decide what to run (x64, error checks omitted)
#include <windows.h>

int main() {
    STARTUPINFOEXW si = { .StartupInfo.cb = sizeof(si) };
    PROCESS_INFORMATION pi = {0};

    DWORD flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_NEW_CONSOLE;
    wchar_t cmd[] = L"C:\\Windows\\System32\\notepad.exe";

    if (CreateProcessW(NULL, cmd, NULL, NULL, FALSE, flags, NULL, NULL, &si.StartupInfo, &pi)) {
        // Inspect/modify address space or thread context here…
        ResumeThread(pi.hThread);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    return 0;
}
```

**Why it matters:** creating suspended lets you examine/shape the initial thread before the loader finishes (e.g., setting **entry point hijacks**, **mitigations**, or **APC** delivery). Defenders look for anomalous suspended lifetimes, context edits, and memory writes around process start.

### Threads, stacks, and contexts

A thread’s **context** (registers, flags, segment bases) and **stack** (commit/reserve, guard pages) define what it executes next. The **TEB** stores per-thread data (TLS, fiber data, stack bounds) and is a common **anti-analysis** and **injection** target (e.g., reading `TEB->ThreadLocalStoragePointer`, walking TLS callbacks, or checking `NtGlobalFlag`).

Key attributes you will rely on:

* **Start address**: where the thread begins (often the runtime loader thunk for new processes).
* **Suspend count**: zero means runnable; nonzero blocks scheduling.
* **Affinity/ideal processor**: placement matters for timing/synchronization bugs and perf artifacts.
* **Impersonation token**: thread-scoped identity that can differ from the process token.

```powershell
# Inspect processes and thread counts quickly (PowerShell)
Get-Process | Select-Object Name, Id, @{n="Threads";e={$_.Threads.Count}} | Sort-Object Threads -Descending | Select -First 10
```

**Analyst tip:** abnormal thread counts, CPU pinning, or threads whose start addresses point into anonymous RX memory are high-value pivots.

### Tokens and effective identity

The **primary token** lives at the process; **impersonation tokens** can attach to threads. Integrity levels (Low/Medium/High/System), groups, and privileges (e.g., `SeDebugPrivilege`) shape access. Many privilege escalations are “token games”—duplicate a handle to a privileged process, open its token with `TOKEN_DUPLICATE`, and impersonate.

Defense hinges on **access checks**: desired access on `NtOpenProcess`/`NtOpenThread` must pass the Security Reference Monitor. Least privilege and **job**/sandbox policies reduce the blast radius of a token compromise.

### Creation paths and attributes

There are two faces of process creation:

* **Win32:** `CreateProcess*`—high-level, feature-rich, common in benign apps and many tools.
* **NT:** `NtCreateUserProcess`—native, exposes attributes directly (section handles, mitigation policy, parent process, protection level).

The **attribute list** (`STARTUPINFOEX` and `PROC_THREAD_ATTRIBUTE_*`) controls:

* **Parent process spoofing** (audit lineage vs. reality)
* **Handle inheritance** (leaky security if unspecified)
* **Mitigation policy** (e.g., CFG, DEP, dynamic code)
* **AppContainer and capability SIDs** (sandboxing)

### Job objects and the “process herd”

A **job object** groups processes and enforces quotas and policies: limit handles, commit, breakaway, UI restrictions, and child process creation. EDRs, sandbox brokers, and modern apps use jobs to pin down sprawl. Attackers try to “break away” or spawn helpers outside the job to bypass constraints.

### WOW64 and architecture edges

On 64-bit Windows, 32-bit processes run under **WOW64** (a thunking layer and a separate `ntdll`). Some APIs behave differently, pointers truncate, and toolchains can misreport addresses. Cross-bit injection (x64 → x86 target) requires the right `ntdll` and careful pointer math.

```text
; WinDbg commands you will use often
!process 0 1         ; enumerate processes with details
!handle 0 3          ; system-wide handle dump (beware volume)
~*                   ; list threads in current process
!thread <ETHREAD>    ; inspect one thread (TEB, stack, start address)
```

**Caution:** live system-wide `!handle` dumps are noisy and can stall the box; prefer targeted queries.

### Thread creation, hijack, and control

New threads arrive via `CreateRemoteThread`, `NtCreateThreadEx`, or runtime helpers (`RtlCreateUserThread`). Three classic control points:

* **Start at your stub**: remote allocation + start address = immediate payload.
* **Write + SetThreadContext**: point `RIP/EIP` at your code while suspended.
* **Queue APC to alertable thread**: deliver code at a safe point (tied to the APC model; covered later).

**Defenders** profile call stacks, look for RX transitions, and flag suspicious start addresses or context changes. Good detections anchor on the **NT** layer and memory provenance (mapped section vs. private, image vs. data).

### Scheduling in one paragraph

The kernel scheduler picks runnable threads by **priority** (dynamic + base), **quantum**, **affinity**, and fairness. Preemption, DPCs, and I/O completion shift runnable states rapidly. For exploit reliability and anti-debug timing, know that **suspend/resume**, **alertable waits**, and **APCs** gate execution—race windows emerge around those transitions.

### Why this matters for exploitation / anti-exploit / malware analysis

Exploit payloads need a **thread** to run and a **token** that grants the next action; EDRs gate both with policies and telemetry. Process creation, suspended starts, and thread context edits are common choke points—and sources of high-signal detections. Understanding job objects, WOW64, and attribute lists lets you both implement stealthy loaders and build robust, low-noise detections around atypical creation patterns.

## APIs and functions

* `CreateProcessW` – high-level process creation; pairs with `STARTUPINFOEX` for attributes/mitigations.
* `NtCreateUserProcess` – native creation with fine-grained process/thread attribute blocks.
* `NtOpenProcess` / `NtOpenThread` – obtain handles with explicit access masks; the gateway to control.
* `NtCreateThreadEx` – create (remote) threads with extended attributes; common for injection/hijack.
* `SetThreadContext` / `GetThreadContext` – read/write CPU context; used for suspended-start hijacks.
* `ResumeThread` / `SuspendThread` – gate scheduling; often abused for timing and Early-Bird tricks.
* `InitializeProcThreadAttributeList` / `UpdateProcThreadAttribute` – build `STARTUPINFOEX` attribute lists.
* `AssignProcessToJobObject` / `CreateJobObjectW` – constrain process trees with quotas and policies.

## Pitfalls, detection notes, and anti-analysis gotchas

* **Inherited handles:** forgetting `bInheritHandles=FALSE` or not scrubbing the attribute list leaks power to children.
* **Parent spoofing vs. lineage:** a forged parent (`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`) fools naive ancestry checks; corroborate with ETW `ProcessStart/ProcessStop` and token data.
* **WOW64 thunking:** cross-architecture injection fails if you allocate/code for the wrong bitness or call the wrong `ntdll`.
* **Mitigation policy collisions:** enabling “no dynamic code” or strict CFG in the child breaks your own instrumentation later.
* **Jobs with deny-breakaway:** your helper spawns but instantly dies; check `JOBOBJECT_EXTENDED_LIMIT_INFORMATION`.
* **Thread start address illusions:** many legitimate threads start in runtime thunks (e.g., `BaseThreadInitThunk`); provenance of the *next* hop matters.
* **Debugger timing:** stepping alters suspend counts and alertable waits, masking APC behaviors or races.
* **Sandbox quotas:** tight job limits produce false positives (frequent process churn, odd exit codes); adjust heuristics for known sandboxes.

## Cross-references

* This chapter assumes the mental model laid down in **Introduction** (Part 1) for NT vs. Win32 terminology and object/handle thinking.
* Detailed loader behavior (PEB/TEB fields, TLS callbacks, image sections) is covered in **Windows Loader & Image Activation** (Part 1).
* Memory layout, VADs, page protections, and section mapping appear in **Memory & Virtual Address Space** (Part 1).
* System call dispatch, stubs in `ntdll`, and direct-syscall variants are in **Syscalls & the NTAPI Boundary** (Part 1).
* APC mechanics, alertable waits, and callback terrains expand in **Scheduling, APCs & Callback Surfaces** (Part 1).
* Creation-time mitigations (DEP, CFG, CET) and integrity policy are discussed in **DEP / NX / W^X**, **ASLR / KASLR**, and **Trust & Integrity: Secure Boot, WDAC/App Control, Code Integrity, PatchGuard, VBS/HVCI, PPL** (Part 2).
* Injection and thread hijack strategies move to **Process Injection & Hooking** (Part 3).

## Glossary

* **PEB/TEB**: Per-process and per-thread user-mode structures with loader and thread metadata.
* **Primary/Impersonation Token**: Process identity vs. thread-scoped identity used for access checks.
* **WOW64**: Compatibility layer allowing 32-bit processes to run on 64-bit Windows.
* **Job Object**: Kernel object enforcing quotas/restrictions over a group of processes.
* **Start Address**: Function where a thread begins execution (often a thunk to the real entry).
* **Context**: CPU register state of a thread; controls what executes next.
* **Affinity**: Processor set a thread may run on; affects timing and cache locality.
* **Mitigation Policy**: Creation-time flags restricting code loading/execution patterns (e.g., CFG, dynamic code).
* **Suspend Count**: Nonzero blocks scheduling; used to park/hijack threads.
* **Attribute List**: Structured creation options (parent, handles, mitigations, security capabilities).

## Key takeaways

* Processes define **identity and memory**; threads define **execution**. You need both to reason about attack/defense.
* Prefer **NT-level** views for fidelity: handle rights, tokens, and section provenance trump API sugar.
* Suspended creation, context edits, and remote thread starts are high-signal choke points for both offense and detection.
* Jobs, mitigations, and WOW64 shape behavior—validate assumptions before porting techniques between targets.
* Keep experiments **isolated**; corrupted contexts and leaked handles can destabilize the host fast.

