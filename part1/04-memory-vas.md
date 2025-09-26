# Part 1 – Fundamentals: Memory & Virtual Address Space

**What this chapter covers**

* How Windows carves a per-process virtual address space: images, sections, and private allocations
* Page protections, states, and transitions (commit, guard, copy-on-write, execute)
* VADs (Virtual Address Descriptors) and why memory provenance matters for detection
* Heaps, stacks, large pages, shared memory, and WOW64 quirks that affect tooling
* Practical triage: what to look for in WinDbg/ETW to separate benign from suspicious mappings

## Core concepts

### One address space, many provenances

A process owns a **virtual address space** whose regions are backed by different sources:

* **Image-backed**: views of a section created from a PE file (EXE/DLL).
* **Mapped (data) sections**: memory-mapped files or pagefile-backed shared segments.
* **Private (anonymous) memory**: heap/stack/JIT/shellcode via `VirtualAlloc`/`NtAllocateVirtualMemory`.

Memory provenance is your first discriminant: image vs. mapped vs. private. Most evasive code runs from **private RX** or **image sections not present in the loader lists** (manual map). Analysts check both protection **and** source.

```c
// Carve RW private memory, write code/data, then flip to RX (x64; error checks omitted)
#include <windows.h>

int main() {
    SIZE_T sz = 0x1000;
    void* p = VirtualAlloc(NULL, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    // ... write your stub ...
    DWORD old = 0;
    VirtualProtect(p, sz, PAGE_EXECUTE_READ, &old);
    FlushInstructionCache(GetCurrentProcess(), p, sz);
    return 0;
}
```

**Why it matters:** the **W→X transition** is high signal for exploit payloads and loaders. Defenders focus on `VirtualProtect`/`NtProtectVirtualMemory` joins with RX regions that are **not image-backed**.

### Pages, states, and protections

Each page has **state** and **protection**:

* **State**: `MEM_FREE`, `MEM_RESERVE`, `MEM_COMMIT`. Reserve carves address space without backing; commit consumes physical/commit charge.
* **Protection**: `PAGE_READWRITE`, `PAGE_EXECUTE_READ`, `PAGE_NOACCESS`, plus modifiers (e.g., `PAGE_GUARD`).
* **DEP/NX**: on x86 with PAE and on x64, the **NX bit** in the PTE blocks execution for non-X pages. Policy is covered in Part 2, but the artifact is here: an attempt to execute non-X faults with `STATUS_ACCESS_VIOLATION`.

**Copy-on-write (CoW)**: image and mapped data start shared/readonly; writing triggers a private copy. This is normal for relocations and import fixups; suspicious when a process **patches RX** regions after making them `RW` temporarily.

### VADs: the map of the map

The kernel tracks regions with **VADs (Virtual Address Descriptors)**. A VAD encodes range, type (image/section/private), protection, and flags (e.g., **NoChange**, **Guard**). Tools like `!vad` and `!address` summarize these. Manual mappers often leave **private executable** VADs without corresponding loader metadata—classic hunting indicator.

```text
; WinDbg quick tour
!address                 ; classify ranges (Image, Private, Mapped) + protections
!vad 0                   ; dump VAD tree (be selective on busy processes)
!memusage                ; high-level working set/commit view
```

**Analyst tip:** RX regions reported as **Private** with **Commit** and no module entry (`lm`) are prime candidates for JIT/shellcode/manual map stubs.

### Sections, views, and shared memory

A **section** object abstracts shared backing storage:

* **Image sections**: created from PE files; views are typically RX for `.text`, R for `.rdata`, RW for `.data`.
* **Pagefile-backed sections**: anonymous shared memory (e.g., ALPC, Chrome’s shared buffers).
* **File-backed data sections**: map arbitrary files as memory (zero-copy I/O patterns).

`NtCreateSection` + `NtMapViewOfSection` appears in both benign IPC and advanced injectors (manual map across processes). Provenance is visible in VADs and ETW **ImageLoad/MapView** events.

### Stacks, guard pages, and `PAGE_GUARD`

Each thread owns a **stack** with **reserve** and **commit** regions. The grow-on-demand mechanism uses a **guard page**; touching it raises `STATUS_GUARD_PAGE_VIOLATION`, after which the OS commits the next chunk. Exploit developers abuse predictable guard behavior; defenders must avoid mistaking normal guard faults for exploitation.

### Heaps and LFH (low-fragmentation heap)

User-mode allocations flow through the **NT heap** and front-end allocators like **LFH**. In practice: you often see private commit with `PAGE_READWRITE`, later toggled to RX by loaders. For UAF/type-confusion bugs, knowing bucket sizes and LFH activation thresholds helps craft reliable sprays, but full exploitation detail belongs to Part 4.

### Large pages and performance/stealth tradeoffs

**Large pages** (2 MiB on x64) reduce TLB pressure and can hide code behind coarse-grained page accounting. They require `SeLockMemoryPrivilege` and alignment; in the wild you rarely see executable large pages, but malware has used them to resist page-granular scanning.

### WOW64 and split address ranges

WOW64 processes have a 4 GiB user view, thunked `ntdll`, and different loader/TEB/PEB layouts. Tooling must match bitness when calling `VirtualQueryEx`, reading PEB/Ldr lists, or interpreting `!address`.

### Working set, commit, and memory pressure

Two counters drive behavior:

* **Commit**: reservation of backing store (RAM + pagefile). Private commit spikes with sprays or manual maps.
* **Working set (WS)**: pages resident in RAM. EDRs sometimes prune WS to pressure evasive code; sandboxes with small RAM exaggerate paging.

```powershell
# Coarse per-process memory posture (PowerShell)
Get-Process | Sort-Object -Descending PM | Select-Object -First 10 `
  Name, Id, PM, NPM, WS, VM
```

### Why this matters for exploitation / anti-exploit / malware analysis

Most payloads live or pass through **private RW→RX** regions. Manual maps and JITs create executable memory that **does not correspond to an image** and often lack unwind/CFG metadata—rich detection surface. Conversely, defenders that only hook Win32 (`VirtualAlloc/VirtualProtect`) miss direct `NtAllocateVirtualMemory`/`NtProtectVirtualMemory` and section-mapping paths; analysts should reason from VADs/ETW and NT calls, not wrappers.

## APIs and functions

* `NtAllocateVirtualMemory` / `VirtualAlloc` – reserve/commit anonymous pages in a target process.
* `NtProtectVirtualMemory` / `VirtualProtect` – change page protections; watch for W→X transitions.
* `NtCreateSection` / `NtMapViewOfSection` – create/map image/data sections; basis for manual map/shared memory.
* `VirtualQueryEx` – enumerate regions (state/protection/type) for triage tooling.
* `FlushInstructionCache` – ensure CPU sees new code after writes.
* `CreateFileMappingW` / `MapViewOfFile` – file-backed mappings (data sections) in Win32 veneer.
* `GetWriteWatch` – discover pages dirtied by the caller (useful in JIT/shellcode hunts and instrumentation).
* `RtlAddFunctionTable` – register unwind data for custom executable regions (stability signal for “well-formed” loaders).

## Pitfalls, detection notes, and anti-analysis gotchas

* **False positives on RX private**: some JITs (e.g., .NET NGen variants, JS engines) legitimately create RX private; correlate with **unwind tables** and module lineage before alerting.
* **Ignoring section provenance**: image-backed RX is normal; RX private with no unwind/CFG data is not. Always join protection with **Type** (Image/Mapped/Private).
* **Guard page noise**: sandboxes with tiny stacks or heavy exception handlers generate frequent guard faults—tune signatures accordingly.
* **WOW64 misreads**: using x64 `VirtualQueryEx` logic on x86 targets yields bad region sizes and bogus conclusions.
* **Hook surface gaps**: hooking `kernel32!VirtualProtect` misses `ntdll!NtProtectVirtualMemory` and direct syscalls; anchor at NT.
* **Large-page surprises**: tools that assume 4 KiB granularity mis-attribute ranges; verify `MEM_LARGE_PAGES`.
* **Copy-on-write confusion**: import/reloc fixups write to image-backed pages—these become **private**; do not flag this alone as tampering.

## Cross-references

* We assume the object/handle/token framing from **Introduction** and the execution model from **Processes & Threads** (Part 1).
* Loader-driven mappings, TLS callbacks, and relocation behavior are covered in **Windows Loader & Image Activation** (Part 1).
* System call stubs and direct-syscall considerations belong to **Syscalls & the NTAPI Boundary** (Part 1).
* Policy impacts on page executability (DEP/NX), layout randomization (ASLR), and metadata (CFG/CET) are detailed in **DEP / NX / W^X**, **ASLR / KASLR**, and **Compiler & Hardware CFI: CFG, CET (Shadow Stack/IBT)** (Part 2).
* Injection techniques that rely on these primitives continue in **Process Injection & Hooking** (Part 3).

## Glossary

* **VAD (Virtual Address Descriptor)**: kernel record describing a contiguous region’s type and protection.
* **Private Memory**: anonymous commit not backed by a file/section; typical for heaps, JIT, shellcode.
* **Image Section**: section object created from a PE file; maps `.text/.rdata/.data`.
* **Mapped (Data) Section**: file-backed or pagefile-backed shared memory not tied to a PE image.
* **Commit vs. Reserve**: commit consumes backing store; reserve holds address space only.
* **Working Set (WS)**: pages of a process currently resident in physical RAM.
* **Copy-on-Write (CoW)**: page becomes private on first write to a shared/readonly mapping.
* **Guard Page**: page that raises a fault when touched to implement stack growth or probes.
* **Large Page**: larger translation unit (e.g., 2 MiB) to reduce TLB misses; special privileges required.
* **NX/DEP**: page attribute (PTE bit) marking memory non-executable; policy interaction in Part 2.

## Key takeaways

* Always pair **protection** with **provenance**: RX **Private** without unwind/CFG is suspicious; RX **Image** rarely is.
* W→X transitions plus `FlushInstructionCache` are reliable bread crumbs for payload setup—correlate at the **NT** layer.
* VADs tell the truth; loader lists can be spoofed or bypassed by manual mapping.
* WOW64 and large pages change assumptions in tooling—match bitness and page size.
* Treat stacks, guards, and CoW as **normal** phenomena and reduce noise by joining with context (call stacks, ETW ImageLoad/MapView, tokens).

