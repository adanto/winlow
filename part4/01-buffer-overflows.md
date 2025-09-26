# Part 4 – Practical Exploitation: Buffer Overflows

**What this chapter covers**

* Stack and heap overflow mechanics on Windows and how mitigations reshape them
* Finding, triggering, and proving control over instruction pointer and data flow
* Modern payloading: DEP-safe primitives (ROP/JOP), stack cookies, SEH history, and Unicode/wide-byte quirks
* Reliable exploitation strategy: stabilization, info leak use, and post-exploit hygiene/telemetry

## Core concepts

### The overflow in one picture

A **buffer overflow** writes outside the bounds of a memory region, corrupting adjacent control or data. On Windows, classic stack bugs target the saved return address (x86) or structured exception metadata (historically SEH). Today, **/GS** stack cookies, **ASLR/DEP/CFG/CET**, and compiler hardening mean raw “overwrite RIP→shellcode” is the exception. The practical goal becomes: **a) position-independent control**, **b) a write primitive you can aim**, and **c) a path to invoke useful syscalls under policy**.

```c
// Minimal vulnerable pattern (for lab only; do not compile in production builds)
#include <stdio.h>
#include <string.h>

void greet(const char *name) {
    char buf[64];
    // BUG: no bounds check
    strcpy(buf, name);
    printf("Hello %s\n", buf);
}

int main(int argc, char **argv) {
    if (argc > 1) greet(argv[1]);
    return 0;
}
```

*Shape:* input > 64 bytes overwrites the saved frame (and cookie in hardened builds). Real bugs hide in protocol parsers, custom allocators, and conversion routines (UTF-16/UTF-8, wide/ANSI).

---

### Stack layout and control targets

On x64 Windows with **/GS**, the compiler emits a **cookie** between locals and the saved non-volatile state. Overwrites that pass the cookie check are rare; more often you get **adjacent data** corruption (vtable/func pointers, size fields, object headers) or **partial overwrites** (least-significant bytes of saved RIP on x86, indices, or flags). On **WOW64** (x86 inside x64), classic SEH overwrite is mostly gone (**SEHOP/SafeSEH**), but handler hijacks still exist in legacy modules.

Key attack surfaces:

* **Return address / saved RIP** (when cookie is absent/defeated).
* **Function pointers/vtables** in adjacent objects (C++/COM).
* **Exception and unwind metadata** (rarer on x64 due to table-driven EH).
* **Allocator metadata** for heap overflows (see UAF/heap chapters for depth).

---

### From crash to control: a repeatable workflow

1. **Crash shaping**: create an input that deterministically corrupts the same byte window; use ASAN builds if you own the code.
2. **Triage**: confirm corruption target (stack vs. heap) with WinDbg/VMMap; print the immediate surroundings and registers at fault.
3. **Stabilize the primitive**: can you write **N bytes at offset O** with chosen content? Is it truncating or wide?
4. **Find leverage**: identify a reachable indirect call, return, or function pointer you can steer **without** violating mitigations.
5. **Plan the call**: with DEP, you need **ROP/JOP** to invoke `VirtualProtect`/`NtProtectVirtualMemory` or to call a “Syscall gadgets → native API” path.
6. **Make it survive**: ASLR needs **info leak** or a module with predictable base (e.g., non-ASLR DLL, but rare in 2025 estates). Fallbacks include **module-relative** addressing, **GS cookie side channels** (broken seldom), or **JIT/LD\_LIBRARY\_PATH misconfigs** in specific apps.

---

### ROP/JOP realities on Windows

With DEP, you pivot to **ROP** (return-oriented programming) or **JOP** (jump-oriented) chains sourced from loaded, executable images. Constraints:

* **ASLR** randomizes bases—find a leak or a non-randomized module.
* **CFG** guards indirect calls; ROP **returns** still work because call sites are direct, but **indirect-call targets** must be valid.
* **CET-Shadow Stack/IBT**: returns are checked against a protected stack; many chains now use **call-preceded gadgets** or **shadow-stack sync techniques** (e.g., `setcontext`-style or calling into functions that naturally unwind). IBT requires **ENDBR64** at indirect branch targets; pure JOP into non-ENDBR stubs fault.

Minimal Windows ROP goal: flip a region **W→X** or **X→RW** (via `VirtualProtect`/`NtProtectVirtualMemory`) and land in RWX or existing RX with your staged code. When ACG/Dynamic Code Policy forbids new RX, prefer **syscall-only** logic chains or target **existing RX** plus **stack pivot gadgets** to drive syscalls.

---

### Heap overflows and adjacent-object corruption

Windows’ modern heaps (LFH, segment heaps) randomize and harden metadata. Raw “unlink” tricks are obsolete; the reliable route is **adjacent-object** corruption: overwrite a **size**, **vtable**, or **function pointer** embedded in a neighbor. This blends into “type confusion” and is covered later, but remember: a “heap overflow” is often really a **control-data** overwrite scenario, not a chunk-metadata exploit.

---

### Encoding, conversions, and partial writes

Windows code frequently transforms strings (UTF-16↔UTF-8, ANSI, OEM code pages). Off-by-one and **wide-byte truncation** bugs create **partial overwrite** primitives (clobbering a **null terminator** or LSByte of a pointer/index). Exploits that succeed without full control survive defenses better: a single-bit flip in an **access mask** or **length** can bypass checks or create **oversized copy** later.

---

### Example: proving EIP/RIP influence in the lab

In a debugger, the first task is to show **input controls a return** (or a function pointer). A controlled pattern (e.g., cyclic sequence) proves exact offsets.

```text
# WinDbg quick path (x64)
> .symfix; .reload
> g                      ; run until crash
> r                      ; inspect registers
> k                      ; backtrace; note the crashing function and return address
> !teb                   ; if stack questions arise (guard pages, size)
> db rsp L100            ; dump around current stack pointer
> u rip-20               ; disassemble around the fault to spot pattern-influenced bytes
```

Once you align an offset, swap the cyclic pattern for a unique marker and show it lands in `rip`. Under **/GS**, expect the cookie check to fire first; that’s your proof the write crosses the cookie.

---

### Building a minimal ROP on a hardened target

1. **Leak a base**: many real programs log or return a pointer (format string, info page, object address). Even an **ntdll** or **kernel32** base is enough to compute gadget/`VirtualProtect` addresses.
2. **Stack pivot**: overwrite saved `rsp` or a function pointer so control lands at a gadget that sets `rsp=controlled`.
3. **Call gadget sequence**: place `pop r?`/`ret` gadgets to set arguments:

   * `rcx = lpAddress`, `rdx = dwSize`, `r8 = PAGE_EXECUTE_READWRITE`, `r9 = &oldProt`, then call `kernel32!VirtualProtect`.
4. **Land** in your RWX region (or return to an existing RX stage) and continue.

With **CET-SS**, prefer a gadget path that uses **`call`-aligned** gadgets or a legal function call to keep shadow stack in sync.

---

### Post-exploit hygiene and telemetry

Overflows that “work” still leave a lot of **noise**: W→X flips, thread starts/APC injections, image loads, and abnormal returns. Blue teams watch these via **kernel ETW** and **CFG/CET fail-fasts**. A reliable exploit minimizes transitions (e.g., a single `NtProtectVirtualMemory` + already-mapped stage) and avoids “global” changes (e.g., no DLL loads if a syscaller stub suffices).

## Why this matters for exploitation / anti-exploit / malware analysis

Buffer overflows remain a **high-severity** class because they often yield **arbitrary control** with a single bug. Modern Windows transforms the problem: exploits must be **composed** (leak → pivot → ROP/syscalls), and defenders get crisp **signals** (permission flips, CFG/CET events). Analysts who can articulate the primitive (“write N bytes at O under encoding X”) and map it to a **mitigation-aware** plan move quickly from crash to either **credible exploit** or **defensible dismissal**.

## APIs and functions

* `VirtualProtect` / `NtProtectVirtualMemory` — change page protections to enable/disable execution; common ROP target.
* `VirtualAlloc` / `VirtualAllocEx` — stage memory; watch for JIT-like allocations during payloading.
* `RtlAddFunctionTable` — needed for stable custom code when exceptions/unwinding occur (manual-mapped stages).
* `SetProcessValidCallTargets` — register indirect-call targets under CFG; sloppy ROP/JOP ignores this and can crash.
* `IsProcessorFeaturePresent(PF_SHADOW_STACK)` — detect CET Shadow Stack; informs gadget strategy.
* `GetModuleHandle` / `GetProcAddress` — post-leak resolution of function addresses.
* `memcpy` / `strcpy` / `strcat` (CRT) — unsafe patterns; triage for direct sinks and inline expansions.

## Pitfalls, detection notes, and anti-analysis gotchas

* **Cookie false negatives:** a bypassed `/GS` is rare; more often, the crash you see is the cookie **working**. Prove where you actually wrote.
* **ASLR optimism:** assuming a fixed base on modern Windows is wishful; plan a **leak** or find a **non-PIE**/non-ASLR module (uncommon).
* **Unicode traps:** wide-char copies double sizes and introduce embedded nulls; many “offset 64” plans fail under UTF-16.
* **CFG/CET collisions:** indirect calls into unregistered/non-ENDBR gadgets fault; prefer **return-chains** and legal call targets.
* **WOW64 confusion:** x86 processes have different calling conventions and SEH semantics; pick the right debugger and payload ABI.
* **ACG/Dynamic Code Policy:** prevents creating/modifying executable memory; ROP must rely on existing RX and syscalls-only logic.
* **Noisy payloading:** excessive DLL loads or new threads help defenders; minimize with **in-place** syscalls and single-thread flow.

## Cross-references

* ROP/JOP internals and call-target constraints: **ROP & JOP** and **Compiler & Hardware CFI: CFG, CET (Shadow Stack/IBT)**.
* Memory permissions, VAD layout, and W→X detection: **Memory & Virtual Address Space** and **DEP / NX / W^X**.
* Loader behavior and image metadata (manual maps, unwind): **Windows Loader & Image Activation**.
* Telemetry and how your exploit appears in logs: **Windows Eventing & ETW Playbook** and **Telemetry Tampering & Unhooking**.
* Follow-on stages (injection, APC, shellcode discipline): **Process Injection & Hooking** and **Shellcoding**.

## Glossary

* **/GS (stack cookie)**: compiler-inserted canary that detects stack-based overwrites before returning.
* **DEP/NX**: policy/bit that forbids executing from writable memory.
* **ASLR**: randomizes module bases to break hard-coded addresses.
* **CFG/CET**: control-flow integrity features that constrain indirect control transfers and returns.
* **ROP/JOP**: programming with existing code snippets via returns or jumps to bypass DEP.
* **ACG**: dynamic code policy restricting creation/modification of executable pages.
* **Leak**: any disclosure of addresses or sensitive state used to defeat ASLR/CFI.
* **Stack pivot**: redirecting the stack pointer to attacker-controlled memory.
* **Wide-byte overwrite**: corruption arising from UTF-16/Unicode copies, often creating partial overwrites.
* **SEH/VEH**: structured/vectored exception handling; historical overflow targets on x86.

## Key takeaways

* Think in **primitives**: define precisely what you can overwrite and how; everything else derives from that.
* A modern Windows overflow is a **chain**: leak → pivot → ROP/syscalls → minimal stage, all under ASLR/DEP/CFG/CET.
* Prefer **behavioral anchors** (W→X, thread start, abnormal returns) for detection and triage; signatures age.
* Encoding and ABI details (UTF-16, WOW64) make or break reliability—treat them as first-class constraints.
* Keep payloading minimal and **policy-aware**; the less you change (modules, threads, protections), the more stable—and stealthy—your exploit.
