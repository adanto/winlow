# Part 4 – ROP & JOP

**What this chapter covers**

* How return-oriented (ROP) and jump-oriented (JOP) programming turn bugs into policy-compliant execution
* Gadget discovery and selection on modern Windows (ASLR/DEP/CFG/CET/ACG in mind)
* Building minimal but reliable chains: stack pivots, argument setup, and syscaller patterns
* Telemetry footprints of ROP/JOP and how defenders separate real chains from crashes
* Practical tips to make chains deterministic under WOW64, CFG, and Shadow Stack

## Core concepts

### ROP/JOP in one paragraph

**ROP** stitches short instruction sequences that end in `ret` so that a compromised return address produces controlled computation without injecting new code (bypassing **DEP**). **JOP** is similar but uses indirect `jmp` (or call) sequences and a **dispatcher** gadget to drive execution. On Windows today, chains must also respect **ASLR** (need a leak), **CFG** (indirect-call targets), **CET** (Shadow Stack and Indirect Branch Tracking), and **ACG**/dynamic-code policies (no new RX). The end-goal is usually to invoke a **single powerful API/syscall** (e.g., `NtProtectVirtualMemory`) and then continue execution cleanly.

---

### Minimal chain anatomy

A practical chain has four phases:

1. **Pivot** – redirect the stack (or control register used by your dispatcher) to a buffer you control.
2. **Set registers** – use `pop r?; ret` or equivalent gadgets to load call arguments.
3. **Invoke** – transition into a valid call target (API function or syscall stub) consistent with **CFG/IBT**.
4. **Hand-off** – land in a stable continuation (return to original code path, small shell stub, or another chain).

```text
; Shape of a tiny x64 pivot (illustrative)
[ overwritten return RIP ] -> gadget:  pop rsp ; ret
[ next qword on old stack ] = address of your controlled ROP stack
; Now each qword is: gadget address, data, gadget address, ...
```

*Why this still works under CET:* Shadow Stack protects **returns**, but if you pivot using a legitimate `ret` and then perform **real function calls** (not just endless `ret`-chains), you can keep the shadow and architectural stacks roughly aligned. IBT affects **indirect** branches; ordinary `ret` into a function **prologue** that has `ENDBR64` is acceptable.

---

### Gadget sources that age well

* **`ntdll.dll`** always loads early and has dense, high-quality gadgets (including syscall stubs).
* **`kernel32.dll`/`kernelbase.dll`** provide argument-massage gadgets and stable exported call targets.
* **The target module itself** (esp. non-ASLR plugins or add-ins) removes the need for a leak—rare on hardened hosts but still seen.

Prefer gadgets that **don’t touch flags or callee-saved registers** you care about, and avoid gadgets that **fault under CET** (e.g., landing mid-function without `ENDBR64`).

---

### Working with CFG/CET

* **CFG** guards **indirect calls/jumps**. ROP that *returns* into a **real function prologue** is fine; JOP that jumps into random middle-of-basic-block addresses will fault.
* **CET-IBT** requires `ENDBR64` at **indirect entry** points. Functions compiled with CET have it; small thunks often do too.
* **CET Shadow Stack** checks returns. Options:

  * Use **function-call chains** (ROP that culminates in `call <api>` via a gadget that preserves the normal call/return pairing).
  * Use **`setcontext`-like** or dispatch-into-functions that naturally unwind.
  * On hosts with CET *off*, classical long `ret`-only chains remain viable; design for both.

---

### JOP: when `ret` is scarce

JOP replaces `ret`-driven flow with a **dispatcher** that repeatedly indirect-jumps through a table you control. On Windows with CFG/IBT, viable JOP dispatchers are rarer; still, a pattern like `xchg rax, [rdi]; jmp rax` can work if you can make each `rax` target a **valid** IBT entry (a real function prologue or thunk). Many chains mix **few** JOP hops to set up state and then switch to **ROP** to call into stable APIs.

---

### Chains that respect policy

When **ACG** forbids creating or modifying executable memory, ditch RWX dreams. Build chains that:

* Call **`NtProtectVirtualMemory`** only to flip a **pre-existing RX** region **X→RW** for small data patching, or
* Don’t change permissions at all—perform everything via **syscalls** and already-executable code, or
* Use legitimate **JIT**/host surfaces that already produce RX (e.g., `Add-Type` in PowerShell), then avoid ACG by never writing to RX yourself.

---

### Example: bare-bones x64 ROP call to VirtualProtect

This “paper” chain shows the register shaping you need; addresses are placeholders resolved from a leak.

```text
; Assumptions:
;  - You leaked kernel32 and have addresses for gadgets and VirtualProtect
;  - `buf` is a RW region you control, `rx` is the target region to make RWX

[0]  pop rsp ; ret                          ; pivot
[1]  &rop_stack

; -- rop_stack --
[2]  pop rcx ; ret                          ; rcx = lpAddress
[3]  rx
[4]  pop rdx ; ret                          ; rdx = dwSize
[5]  0x1000
[6]  pop r8  ; ret                          ; r8  = flNewProtect
[7]  0x40                                ; PAGE_EXECUTE_READWRITE
[8]  pop r9  ; ret                          ; r9  = lpflOldProtect
[9]  &buf
[10] mov rax, [kernel32!VirtualProtect] ; ret ; rax = target
[11] jmp rax                                ; or: call rax  (prefer call to keep CET happy)
[12] <address in rx>                         ; continuation: your RX stage (already mapped)
```

*Notes:* On CET-SS, prefer a sequence that **calls** the API (e.g., through a thunk with `ENDBR64`) rather than `jmp`, so the shadow stack records a sensible return. If CFG is enforced, ensure your `call` target is a **valid** CFG entry.

---

### Example: a simple WOW64 syscall hop

ROP on **WOW64** often aims to reach `ntdll`’s 32-bit or 64-bit **syscall stubs**. A tiny “syscaller” stage keeps noise low.

```c
// shape-only: a minimal x64 syscall stub you might return into from ROP (no inline asm)
typedef NTSTATUS (NTAPI *pNtProtectVirtualMemory)(
    HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);

NTSTATUS do_protect(pNtProtectVirtualMemory NtProtect,
                    HANDLE h, PVOID *addr, SIZE_T *len, ULONG newp, ULONG *oldp)
{
    return NtProtect(h, addr, len, newp, oldp);
}
```

*Use it:* point your ROP call at a **real function** that just tail-calls the **syscall stub** resolved from a leak—valid prologue, valid CFG/IBT entry, simple arguments.

---

### Telemetry shape (what blue teams see)

* **Abnormal returns** and dense sequences of short `ret`-terminated basic blocks in a tight window.
* **W→X** or X→RW flips on private pages near the time of the crash/exploit.
* **No new images**, yet sensitive syscalls are invoked with attacker-friendly arguments (e.g., `NtWriteVirtualMemory`, `NtCreateThreadEx`).
* CET/CFG **fail-fasts** on sloppy chains (“random crashes” that are in fact guards doing their job).

Defenders should prioritize **kernel ETW** and **memory-provenance** joins (DEP chapter) over user-mode hooks; ROP doesn’t have to call `kernel32` wrappers.

## Why this matters for exploitation / anti-exploit / malware analysis

ROP/JOP are the lingua franca of post-mitigation exploitation: they let attackers comply with DEP and sometimes ACG, while leveraging existing, signed code. Analysts must read chains as **intent graphs** (“why call `NtProtectVirtualMemory` here, then spawn a thread?”) and recognize defense-driven crashes as **success cases** of CFG/CET. Understanding chain construction makes exploit triage faster and hardening advice more specific.

## APIs and functions

* `VirtualProtect` / `NtProtectVirtualMemory` — common chain target to flip memory protections.
* `NtCreateThreadEx` — follow-on primitive to transfer control to a staged region without new images.
* `SetProcessValidCallTargets` — CFG bookkeeping; relevant for in-process loaders that register targets.
* `IsProcessorFeaturePresent(PF_SHADOW_STACK | PF_IBT_SUPPORTED)` — detect CET presence to choose strategies.
* `RtlLookupFunctionEntry` / `RtlAddFunctionTable` — stabilize custom code under EH/stack unwinding if you must run longer stages.
* `VirtualAlloc` / `VirtualAllocEx` — staging memory in (remote) processes; sometimes avoided under ACG.
* `GetModuleHandle` / `GetProcAddress` — compute gadget/API addresses once you have a base leak.

## Pitfalls, detection notes, and anti-analysis gotchas

* **No valid entry:** jumping into the **middle** of a function without `ENDBR64` under IBT will fault immediately.
* **Shadow-stack desync:** long `ret`-only chains on CET machines crash on return; prefer **function-call** transitions.
* **CFG denial:** indirect `call` into non-whitelisted thunks is blocked; return into **real prologues** or valid CFG entries.
* **Unreliable pivots:** overwriting `rsp` without ensuring the pivot gadget exists in the target build leads to “works-on-my-VM” chains.
* **WOW64 confusion:** x86 vs x64 gadgets and calling conventions differ; keep stacks and arg ordering architecture-correct.
* **ACG walls:** chains that try to allocate RWX or change RX without policy fail—design **syscall-only** or **existing-RX** strategies.
* **EDR observer effect:** user-mode hooks can slow timing; guard logic (sleep checks) may bite—pair debugger with **ETW** for ground truth.

## Cross-references

* Initial memory corruption and getting to control belong in **Buffer Overflows** and **Use-After-Free & Type Confusion**.
* Memory permissions and provenance joins are in **DEP / NX / W^X** and **Memory & Virtual Address Space**.
* CFG/CET mechanics and why some entries need **ENDBR**: **Compiler & Hardware CFI: CFG, CET (Shadow Stack/IBT)**.
* Telemetry view and fail-fast interpretation: **Windows Eventing & ETW Playbook**.
* Post-chain execution mechanics (injection, APC): **Process Injection & Hooking** and **Scheduling, APCs & Callback Surfaces**.

## Glossary

* **ROP**: chaining `ret`-terminated gadgets to compute without new code.
* **JOP**: chaining `jmp`-driven gadgets with a dispatcher instead of returns.
* **Gadget**: short instruction sequence ending in control-transfer, reused by an exploit.
* **Pivot**: redirecting stack/dispatcher state to attacker-controlled memory.
* **CFG**: Control Flow Guard; validates indirect-call targets.
* **CET-IBT/SS**: Indirect Branch Tracking and Shadow Stack; validate indirect entries and returns.
* **ACG**: policy preventing creation/modification of executable memory.
* **Syscaller**: tiny stage that invokes `syscall`/`sysenter` directly.
* **ENDBR64**: landing instruction required for IBT-valid indirect entries.
* **WOW64**: x86 processes on x64 Windows, with different thunks and calling conventions.

## Key takeaways

* Design **short, purpose-built** chains: pivot → set args → one powerful call → clean hand-off.
* Land only on **valid** prologues/thunks (CFG/IBT) and keep **shadow stack** coherent with real calls where possible.
* Prefer **syscall-only** or **existing-RX** strategies when ACG is on; avoid gratuitous W→X flips.
* Base leaks decide reliability; build chain addresses **relative** to leaked modules and tolerate versions.
* In triage, interpret chains as **intent** and use **kernel ETW** to confirm effects; many “random” crashes are guards doing their job.
