# Part 4 – Use-After-Free & Type Confusion

**What this chapter covers**

* How dangling pointers (use-after-free) and mismatched types (type confusion) arise in real Windows code
* What modern heaps (LFH/Segment Heap) mean for grooming, reuse, and reliability
* Practical exploitation flows under DEP/ASLR/CFG/CET, including vtable hijack, fake objects, and argument herding
* Triage and debugging techniques that separate “just a crash” from a controllable primitive
* Defensive patterns: ownership discipline, lifetime guards, and allocator hardening knobs you can actually turn on

## Core concepts

### Two bugs, one mindset

A **use-after-free (UAF)** occurs when code dereferences a pointer after its target memory has been freed (dangling pointer). **Type confusion** occurs when code treats a memory region as a different type than it actually is (wrong vtable/layout/length), often due to missing dynamic checks or stale tags. In both cases, you aim to turn **arbitrary data you can shape** into **execution control** (indirect call, virtual dispatch, function pointer, length/size for later copies) while surviving Windows mitigations.

```c
// Minimal UAF shape (toy). Do NOT run outside a lab.
#include <windows.h>
#include <stdio.h>

typedef struct Widget {
    void (*do_it)(const char*);
    char name[32];
} Widget;

void hello(const char* s){ printf("hello %s\n", s); }

int main() {
    Widget* w = (Widget*)HeapAlloc(GetProcessHeap(), 0, sizeof(Widget));
    w->do_it = hello;
    lstrcpyA(w->name, "world");
    HeapFree(GetProcessHeap(), 0, w);     // BUG: dangling 'w'
    // Attacker grooms: alloc same size so freed slot gets re-used
    char* spray = (char*)HeapAlloc(GetProcessHeap(), 0, sizeof(Widget));
    // Fake object in reclaimed slot (shape-only)
    ((Widget*)spray)->do_it = (void(*)(const char*))GetProcAddress(GetModuleHandleA("kernel32"), "Beep");
    // UAF: call through freed pointer's function pointer
    w->do_it(w->name);
}
```

*Idea:* free the object, re-allocate a buffer of the **same size class**, plant a **fake object** (e.g., a vtable or function pointer), then trigger the stale pointer’s usage to gain control.

---

### Why Windows heaps matter

Windows uses **LFH** (Low Fragmentation Heap) and, for many user-mode processes on recent builds, the **Segment Heap** (default for many apps). Both are **bucketized** allocators: objects of similar size land in the same bin. This **helps** exploitation (predictable reuse) and **hurts** it (metadata hardening, delayed coalescing).

Key effects:

* **Size matches → high reuse probability** in the same bucket after a free.
* **No unsafe unlink**: classic heap metadata attacks are largely dead; focus on **adjacent-object** corruption.
* **Isolated subsegments**: grooming usually targets **per-bucket churn** to raise the odds your freed slot reappears quickly.

**Practical tactic:** groom with **many same-sized** allocations/frees to seed the bucket, then free the victim and immediately allocate your **fake object** of the **exact same size**.

---

### Type confusion in practice

Confusion often arises at **ABI boundaries**: COM interfaces, plug-in systems, serialization/deserialization, and JITs. Two classic shapes:

* **Wrong dynamic type**: a base pointer actually points to a derived object with **smaller/larger** layout or a different **vtable**.
* **Stale tag**: code reads a **tag/enum** once, then uses it later after a mutation (TOCTOU), interpreting raw bytes with the wrong schema.

```c++
// Type confusion sketch (lab only)
struct Base { virtual void f(); int len; };
struct Derived : Base { void (*cb)(char*); char buf[16]; };

void sink(Base* b, char* p) {
    if (b->len < 32)  // stale check
        memcpy(((Derived*)b)->buf, p, b->len + 64); // interprets as Derived unconditionally
}
```

If `b` is truly a `Base`, the cast to `Derived` is wrong: you overwrite past the end into the **vtable pointer** or the **callback pointer**. If `b` is **smaller** than assumed, you get a **heap overflow**; if it’s **larger**, later code may call through a **wrong vfunc** entry.

---

### From primitive to control: reliable flows

#### UAF → fake vtable hijack

C++ virtual dispatch compiles to `call [rcx]`-style loads of a **vtable** pointer, then an indirect call to an entry. Plan:

1. Free a C++ object with virtual methods.
2. Reclaim the slot with controlled bytes (**same size class**).
3. Place a pointer at offset 0 (fake **vtable**).
4. Point a vtable entry at a **valid** call target under **CFG/IBT** (e.g., `kernel32!VirtualProtect` or a small function that later pivots).

**Mitigations:**

* **CFG** validates **indirect-call targets**; your target must be a **valid** entry. You can still call legitimate APIs as gadgets.
* **CET-IBT** requires **ENDBR64** at indirect targets; normal functions have it.
* **CET-SS** (shadow stack) protects **returns**, not indirect calls—your virtual call still works, but your follow-on ROP must keep shadow stack coherent (prefer real calls over `ret`-chains where possible).

#### UAF → argument herding

Not all UAFs yield function-pointer control. Many let you **edit fields** read later: lengths, pointers to buffers, or **reference counts**.

* Overwrite a **length** to create a later **overflow** into RX.
* Change a **function pointer argument** (e.g., callback in a later API call) while leaving the callsite intact.
* Nudge a **reference count** to 0 or huge to cause double-free or leak.

#### Type confusion → arbitrary read/write

If confusion yields **pointer + length** pair control, chain two bugs: first to get **read/write** (e.g., treat an array of DWORDs as pointers), then a second to **pivot** control (function pointer, vtable, SEH/VEH-aware field).

---

### Grooming on LFH/Segment Heap

Heap reliability is won or lost in **grooming**:

* **Prepare the bucket**: allocate many objects of the target size (e.g., 0x80).
* **Stagger** frees to avoid coalescing or decommit.
* **Pin** neighbors you care about by holding references so the only candidate to reuse is your target slot.
* **Spray** with **same-size** buffers that carry the fake object (vtable pointer first, then fields used by the callsite).

Windows adds **heap termination on corruption** and random checks. For lab work, ensure the crash is your **dangling pointer**, not allocator poison.

---

### Leaks, ASLR, and “good” call targets

ASLR forces you to either leak a module base or use **non-PIE** modules (rare in hardened estates). Common, realistic leaks:

* Format strings or `%p`-like logs that reveal an object or module address.
* In-process structures that store pointers (handle tables, object caches) and can be printed via scripting.
* Predictable **JIT** bases in specific apps.

With a leak, compute call-target addresses (e.g., `kernel32!VirtualProtect`) and put them into vtable entries or function pointers your UAF/confusion can reach.

---

### Debugging & triage: decide if it’s exploitable

1. **Catch the first invalid use**: set breakpoints on free (`!htrace` in user heaps; application-side logs) and on the object’s **type method** usage; the delta is your exploit window.
2. **Dump the freed slot** before and after grooming; confirm reuse by content change and address equality.
3. **Single-step** the indirect callsite (`u ip-10`) to observe where the call target is fetched from; compute the offset for your fake pointer.
4. **Prove control** with a **known crash**: point to `0x4141414141414141` (will fault) or a **known API** with benign args (e.g., `Beep`) to show redirection without harm.

## Why this matters for exploitation / anti-exploit / malware analysis

UAF and type confusion dominate modern memory-safety bugs because they slip through static checks and only manifest under specific lifetimes or cast paths. Attackers like them for **post-mitigation power**: they yield **indirect-control** without needing raw stack overwrites. Defenders detect them by **sequence** (free → reuse → odd indirect call) and by **heap forensics**, and prevent them with **ownership discipline**, **quarantined frees**, and **policy** (CFG/CET/ACG) that converts sloppy exploits into clean crashes.

## APIs and functions

* `HeapAlloc` / `HeapFree` — primary per-process allocator calls; UAF lifetimes and size classes hinge on these.
* `RtlSetHeapInformation` — enable **heap termination on corruption** and other hardening flags.
* `VirtualProtect` / `NtProtectVirtualMemory` — favorite post-control target to flip W→X or make RX writable.
* `GetProcessHeap` — the heap handle you’ll often groom; multiple heaps complicate reuse.
* `CoTaskMemAlloc` / `CoTaskMemFree` — COM allocation; mismatched lifetime across COM boundaries often seeds UAF.
* `IsProcessorFeaturePresent(PF_SHADOW_STACK)` — detect CET Shadow Stack to choose gadget strategy.
* `SetProcessValidCallTargets` — register legitimate indirect-call targets under CFG (relevant to hardened, in-process loaders).
* `HeapSetInformation` — per-heap knobs (e.g., LFH tuning) that affect determinism and fuzz harnesses.

## Pitfalls, detection notes, and anti-analysis gotchas

* **Wrong size class**: reclaim fails if your spray isn’t the **exact** bucket size; Segment Heap rounds differently than LFH.
* **CFG/CET reality**: pointing a vtable at an arbitrary gadget often **faults**—choose **valid** function entries (with ENDBR) and plan arguments.
* **Torn writes**: racing threads touch freed memory; flakiness ≠ unexploitable. Quiesce with synchronization in the harness.
* **Quarantine & delayed free**: some heaps defer reuse; add **pressure** (allocate/fill/free) to force recycling.
* **Non-determinism in labs**: EDR hooks and CET can change timing; pair WinDbg with **ETW** to separate mitigation side-effects from the bug.
* **Unicode & structure packing**: confusion via wide/ANSI conversions shifts offsets; recompute fake layouts for `#pragma pack` or UTF-16.
* **ACG policy**: if dynamic code is forbidden, your chain must **avoid creating new RX**; prefer syscall-only chains and existing RX regions.

## Cross-references

* For post-control payloading and gadget construction, see **ROP & JOP**.
* For memory permissions, provenance, and W→X detection, see **Memory & Virtual Address Space** and **DEP / NX / W^X**.
* For how CFG/CET constraint indirect calls/returns, see **Compiler & Hardware CFI: CFG, CET (Shadow Stack/IBT)**.
* For triaging behavior in logs and timelines, see **Windows Eventing & ETW Playbook**.
* For follow-on techniques (injection/hooking), see **Process Injection & Hooking**.

## Glossary

* **Use-after-free (UAF)**: dereferencing a pointer after its target memory was freed.
* **Type confusion**: treating memory as the wrong type/layout, leading to misinterpreted fields or vtables.
* **Grooming**: allocator manipulation to make a freed slot reappear under attacker control.
* **Vtable hijack**: replacing an object’s virtual method table pointer to control an indirect call.
* **LFH/Segment Heap**: modern Windows heap front-ends with bucketized allocation.
* **CFG**: Control Flow Guard; restricts indirect-call targets to a set of valid entries.
* **CET-IBT/SS**: Intel Indirect Branch Tracking / Shadow Stack; guard indirect targets and returns.
* **Quarantine**: allocator behavior that defers reuse of freed chunks to reduce UAF risk.
* **Fake object**: attacker-built bytes matching a victim’s expected layout to steer behavior.
* **Argument herding**: using data-only control to shape arguments to a powerful but legitimate call.

## Key takeaways

* Model the bug as a **lifetime/type** problem first, then derive a **control primitive** (vtable, function pointer, length/pointer pair).
* Groom **size classes** precisely; LFH/Segment Heap determinism comes from buckets, not luck.
* Plan for **CFG/CET/ACG**: choose **valid** call targets, keep shadow stack coherent, and avoid creating new RX if blocked.
* Prove **reuse and control** with before/after dumps and benign redirections (e.g., `Beep`) before pursuing payloading.
* Prevent with **ownership discipline** (unique\_ptr/ComPtr, ref-count guards), **quarantined frees**, and allocator hardening; detect with **sequence-aware** telemetry (free → reuse → indirect call).
