# Part 1 – Fundamentals: Scheduling, APCs & Callback Surfaces

**What this chapter covers**

* How Windows schedules threads (priorities, quanta, affinity) and where execution can be “parked” or “nudged”
* APCs (Asynchronous Procedure Calls): user vs. kernel APCs, alertable waits, and common abuse/detection patterns
* The major callback surfaces analysts care about: window messages, completion ports, threadpool, ETW, DLL/image notifications
* Practical triage in WinDbg/ETW for timing-sensitive activity (Early-Bird, suspend/resume, APC queues)
* Reliability gotchas: reentrancy, loader lock, and debugger artifacts that skew timing

## Core concepts

### Scheduling in one page: priorities, quanta, and runnable states

Windows schedules **threads**. Each thread has a **base priority** (derived from process priority class) and a **current/dynamic priority** that the scheduler may boost (I/O completion, foreground activity) or decay. Threads move among **runnable**, **waiting**, and **terminated** states. A thread becomes **runnable** when it has a zero **suspend count**, no blocking wait, and an eligible **affinity** (CPU mask it may run on).

* **Quantum**: time slice before preemption; longer for background/low-contention cases, shorter for interactive workloads.
* **Affinity/ideal processor**: pinning influences cache locality and timing; attackers sometimes use this to stabilize races or ROP timing.
* **Priority inversion/boosts**: the kernel boosts priorities for threads releasing contended resources; anti-debug timing checks can be fooled by these boosts.

**Analyst tip:** anomalous **suspend/resume** sequences and tight **affinity** masks on suspicious threads are useful pivots when reviewing process behavior.

### APCs: queued execution that rides scheduler safe points

An **APC (Asynchronous Procedure Call)** is a payload (function + context) queued to a **specific thread**. The OS delivers APCs at **well-defined safe points**:

* **Kernel APCs** run in kernel mode to the target thread when it reaches an APC delivery point.
* **User APCs** run in user mode when the thread is **alertable** (e.g., `SleepEx(INFINITE, TRUE)`, `WaitForSingleObjectEx(..., TRUE)`, `NtTestAlert`).
* Queueing requires the **thread handle** and the right access (typically `THREAD_SET_CONTEXT` or `THREAD_SET_LIMITED_INFORMATION` depending on API).

Because the payload runs **in the context of the target thread**, APCs are ideal for **queue-then-resume** tricks.

```c
// Queue a user APC and force delivery via alertable wait (self-injection demo; error checks omitted)
#include <windows.h>
#include <stdio.h>

void __stdcall MyApcProc(ULONG_PTR ctx) {
    puts("APC ran!");
}

int main() {
    // Queue APC to current thread
    QueueUserAPC((PAPCFUNC)MyApcProc, GetCurrentThread(), 0x1337);
    // Force alertable state so the APC is delivered in user mode
    SleepEx(0, TRUE); // or WaitForSingleObjectEx(h, INFINITE, TRUE);
    return 0;
}
```

**Key constraints:** APCs do not preempt arbitrary code; they piggyback on waits or APC delivery points. Many threads never enter **alertable** waits—hence the value of **Early-Bird** techniques that queue before the runtime loop begins.

### Early-Bird APC and suspend/resume choreography

The classic pattern: create a process **suspended**, write or map your stub, **queue a user APC** to the **primary thread**, then **resume**. The thread reaches an APC delivery point during startup (e.g., in `BasepPostSuccessAppXExtension`/loader waits) and executes your code **before** the target’s main code runs. This happens prior to many user-mode agents setting hooks.

```c
// Early-Bird APC sketch: create suspended → queue APC to primary thread → resume
#include <windows.h>

void __stdcall ShellStub(ULONG_PTR) {
    // …do something minimal, then return to avoid destabilizing startup…
}

int main() {
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {0};
    wchar_t cmd[] = L"C:\\Windows\\System32\\notepad.exe";

    if (CreateProcessW(NULL, cmd, NULL, NULL, FALSE,
        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {

        QueueUserAPC((PAPCFUNC)ShellStub, pi.hThread, 0);
        ResumeThread(pi.hThread);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    }
    return 0;
}
```

**Reliability notes:** keep the stub tiny; the **loader lock** may be held. Heavy work or extra DLL loads from inside the APC can deadlock or crash. Mature loaders queue a **second-stage** after process initialization completes.

### Other callback surfaces you’ll meet every day

APCs are not the only queued execution surface. A non-exhaustive list of **user-mode callback** ecosystems you’ll triage:

* **Window messages**: GUI threads pump messages; `SetWindowsHookEx`, CBT/WH\_GETMESSAGE chains, and classic window-proc subclassing are common redirection points. Malware piggybacks on message pumps for **reentrancy** and stealth.
* **I/O completion ports (IOCP)**: threadpools block on `GetQueuedCompletionStatus` (often alertable); queueing fake completions drives code in predictable threads with **service** privileges.
* **Threadpool callbacks**: `CreateThreadpoolWork`/`SubmitThreadpoolWork`; defenders watch for threadpool threads executing from **private RX** or unknown modules.
* **ETW consumer callbacks**: user providers receive events via registered callbacks; tampering is discussed later in “Telemetry Tampering & Unhooking”.
* **DLL/image notifications**: user-mode loader publishes module events (via `LdrRegisterDllNotification`); abused to trigger code when specific DLLs appear.
* **WMI/RPC/ALPC** brokering: “server-side” callbacks fire on new requests—see **IPC** chapter.

These are **structured reentrancy** vectors—legitimate pathways that accept external stimuli and then execute caller-provided or caller-influenced routines.

### Alertable vs. non-alertable waits

**Alertable** waits (`SleepEx`, `WaitFor*Ex(..., TRUE)`) accept user APC delivery; **non-alertable** waits do not. A thread can also call `NtTestAlert` to drain pending user APCs immediately. When a target never becomes alertable, **APC-only** injection fails; you pivot to thread creation/hijack or hook a surface the target *does* service (message loop, completion port).

### Kernel APCs and their user-mode ripples

**Kernel APCs** perform work in kernel mode (e.g., I/O completion delivery). Their presence explains why user code sees certain callbacks “just before/after” I/O returns and why timing in debuggers changes: stepping across alertable waits or I/O boundaries can reorder APC delivery.

### Reentrancy and loader lock hazards

Code invoked from APCs, notifications, or message hooks runs **inside** other subsystems. Doing heavy work, blocking, or loading DLLs can deadlock (e.g., **loader lock** still held). Good engineering: queue **work items** to a private threadpool or signal an event and return immediately from the callback.

```text
; WinDbg triage for APCs/callback timing
~* kv                 ; list threads with call stacks (look for alertable waits)
!teb @#               ; inspect TEB of the current thread (TLS/stack bounds)
!apc                  ; (if available) summarize APC queue; otherwise inspect user stacks near waits
!symsrv               ; confirm symbols—mis-symboling looks like “mystery” frames
```

**Analyst tip:** on a suspicious thread, a stack like `WaitForSingleObjectEx → ntdll!NtWaitForSingleObject → ntdll!KiUserApcDispatcher → <your code>` is a smoking gun for **user APC** delivery.

### Timing and the debugger observer effect

Attaching a debugger changes timing: breakpoints and single-stepping can **prevent** or **delay** alertable waits, mask race windows, and alter priority boosts. Reproduce with and without a debugger, and capture ETW at the same time to separate logical flow from debugger artifacts.

### Scheduling knobs that matter in practice

* **Suspend/resume**: not just for APC choreography; it also gates exploit races (e.g., “park” a thread while patching its code).
* **Priority/affinity**: pin a helper thread to stabilize a JIT spray or ROP gadget read; defenders notice unusual pinning in short-lived processes.
* **Quantum exploitation**: rare, but timing-based checks sometimes assume a minimum observable delay per slice—high-priority busy loops can influence outcomes.

## Why this matters for exploitation / anti-exploit / malware analysis

A huge fraction of **covert execution** happens on callback paths the OS already owns: APCs, message loops, completion ports, loader notifications. Attackers queue themselves into **trusted threads** to inherit their tokens and telemetry profile; defenders hunt for **who executed where** (thread identity), **from what memory** (image vs. private), and **via which surface** (APC, message, IOCP). Understanding the timing and reentrancy rules lets you build **reliable** payloads and **low-noise** detections.

## APIs and functions

* `QueueUserAPC` / `NtQueueApcThread` – queue a user APC to a target thread (alertable delivery required).
* `SleepEx` / `WaitForSingleObjectEx` – enter an alertable wait so user APCs can run.
* `CreateProcessW` + `CREATE_SUSPENDED` – set up Early-Bird/loader-window execution.
* `ResumeThread` / `SuspendThread` – gate scheduling and race windows.
* `RegisterWaitForSingleObject` / threadpool APIs – route callbacks through the threadpool.
* `LdrRegisterDllNotification` – subscribe to per-process image load/unload notifications.
* `GetQueuedCompletionStatus` / `PostQueuedCompletionStatus` – IOCP delivery (often alertable).
* `SetThreadAffinityMask` / `SetThreadPriority` – adjust placement and scheduling characteristics.

## Pitfalls, detection notes, and anti-analysis gotchas

* **Non-alertable targets:** APC-only plans fail if the thread never goes alertable; be ready to pivot.
* **Loader lock deadlocks:** executing complex logic inside Early-Bird APCs often freezes the process; keep the first stage minimal.
* **Reentrancy bugs:** callbacks run *inside* someone else’s critical path; blocking or waiting on GUI/COM locks can deadlock.
* **Debugger skew:** breakpoints alter timing and can suppress delivery; corroborate with ETW.
* **Thread identity mismatch:** you queued to a GUI thread with a **different token** than expected; your access checks later fail.
* **IOCP detection:** fake completions without matching I/O history stand out in ETW; defenders join IOCP activity with file/socket provenance.
* **Message hooks visibility:** global hooks (`SetWindowsHookEx` with WH\_\*) load your DLL into other processes; code integrity and PPL/WDAC policies may block this and generate clean telemetry.

## Cross-references

* Handle rights needed to queue APCs or adjust threads are covered in **Object Manager & Handles** (Part 1).
* The loader windows in which Early-Bird APCs land, and `DllMain`/TLS behavior, are in **Windows Loader & Image Activation** (Part 1).
* Memory provenance of callback stubs (private RX vs. image) is explained in **Memory & Virtual Address Space** (Part 1).
* The `Nt*` entry points and marshalling for `NtQueueApcThread`/waits belong to **Syscalls & the NTAPI Boundary** (Part 1).
* IPC-driven callbacks (ALPC/RPC/COM) are detailed in **IPC (ALPC, RPC, COM, Pipes)** (Part 1).
* Policy interactions (CFG/CET altering return paths, DEP/NX) appear in **Compiler & Hardware CFI: CFG, CET (Shadow Stack/IBT)** and **DEP / NX / W^X** (Part 2).
* ETW tampering and unhooking of callback dispatch is addressed in **Telemetry Tampering & Unhooking (ETW, Direct Syscalls)** (Part 3).

## Glossary

* **APC (Asynchronous Procedure Call)**: queued function executed in the context of a target thread at safe points.
* **Alertable Wait**: wait state where user APCs may be delivered (e.g., `WaitFor*Ex(..., TRUE)`).
* **Early-Bird APC**: queueing a user APC to a newly created suspended process’s primary thread, then resuming to run before main.
* **IOCP (I/O Completion Port)**: kernel-managed queue delivering completion packets to worker threads.
* **Threadpool**: shared worker infrastructure that runs user callbacks for timers, waits, and I/O.
* **Loader Lock**: synchronization protecting loader state; reentrancy here causes deadlocks.
* **Quantum**: scheduler time slice allotted to a running thread before preemption.
* **Affinity**: CPU set eligible for a thread; influences placement and timing.
* **Reentrancy**: executing code inside a subsystem’s critical path; requires minimal, fast callbacks.
* **KiUserApcDispatcher**: user-mode dispatcher in `ntdll` that invokes queued user APCs.

## Key takeaways

* Scheduling explains **when** code can run; APCs and callbacks explain **how** it gets there without new threads.
* APC-based execution hinges on **alertable waits**; Early-Bird works because startup naturally hits delivery points.
* Treat every callback as **reentrant**—do the minimum, hand off work, and return.
* For detection, join **who ran (thread/token) + where (memory provenance) + how (surface: APC/IOCP/message)**.
* Debuggers change timing; always validate findings with ETW and non-interactive traces.


