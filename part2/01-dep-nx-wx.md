# Part 2 – Exploitation Mitigations: DEP / NX / W^X

**What this chapter covers**

* What NX/DEP actually enforces in Windows and how it flows from PTEs to process policy
* How Windows exposes/consumes execute permissions (page protections, image sections, JIT patterns)
* W^X as a goal: practical guardrails (no simultaneous write+execute) and where Windows gets close
* Where bypass attempts happen (RW→RX flips, loader stubs, JITs) and how defenders distinguish benign from malicious
* Minimal, safe examples to read/shape protections and to baseline telemetry

## Core concepts

### NX/DEP in one page

The **NX (No-eXecute)** bit in a page table entry marks data pages non-executable. Windows layers **DEP (Data Execution Prevention)** policy on top of NX: processes may opt-in/opt-out (subject to system policy), and the kernel enforces execution only from **X** pages. On x64, NX is always present; on old x86 without PAE, hardware NX does not exist (legacy “DEP” reduces to limited checks). Attempting to execute from a non-X page raises `STATUS_ACCESS_VIOLATION` (`0xC0000005`) with an execute flag.

Windows still permits **RWX** mappings if explicitly requested and policy allows it. Modern hardening encourages **W^X**—memory is *write or execute*, not both—and several mitigations (e.g., **Dynamic Code** policy / ACG) tighten this further. Think: **protection + provenance**—what is the page’s permission *and* what backs it (image/mapped/private)?

```c
// Inspect and flip protections safely (x64; error checks omitted)
#include <windows.h>
#include <stdio.h>

int main() {
    SIZE_T sz = 0x1000;
    void* p = VirtualAlloc(NULL, sz, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
    printf("Allocated at %p\n", p);

    // Write some bytes (not shellcode—just a marker)
    memset(p, 0x90, sz);

    DWORD old = 0;
    VirtualProtect(p, sz, PAGE_EXECUTE_READ, &old);  // RW -> RX
    FlushInstructionCache(GetCurrentProcess(), p, sz);

    MEMORY_BASIC_INFORMATION mbi = {0};
    VirtualQuery(p, &mbi, sizeof(mbi));
    printf("Protect=0x%lx  State=0x%lx  Type=0x%lx\n", mbi.Protect, mbi.State, mbi.Type);
    return 0;
}
```

### Page protections and states

User-mode code expresses execute permissions via `PAGE_*` flags:

* Non-executable: `PAGE_READONLY`, `PAGE_READWRITE`, `PAGE_WRITECOPY`.
* Executable: `PAGE_EXECUTE`, `PAGE_EXECUTE_READ`, `PAGE_EXECUTE_READWRITE`, `PAGE_EXECUTE_WRITECOPY`.
* Modifiers: `PAGE_GUARD`, `PAGE_NOCACHE`.
* State: `MEM_RESERVE`, `MEM_COMMIT`. Type/provenance: **Image**, **Mapped**, **Private**.

**RW→RX transitions** (`VirtualProtect`/`NtProtectVirtualMemory`) are normal in JITs but are also a core exploit step. Pair transitions with **provenance** (Private vs. Image) and **metadata** (unwind/CFG) for signal.

### Image sections vs. private RX

The loader maps `.text` as **RX image-backed**; this is expected. **Private RX** is where JITs and loaders live—and where shellcode likes to hide. Manual mappers often forget to register unwind or guard metadata, leaving **RX Private** with no function tables and no CFG coverage (high suspicion).

```powershell
# Quick survey of RX private across processes (PowerShell + minimal WMI)
Get-Process |%{
  try {
    $h = (Get-Process -Id $_.Id)
    $modPrivRX = $h.Modules |? { $_.FileName -eq $null }  # naive; real tools should use VirtualQueryEx
  } catch {}
}
# Use VMMap/Dbg/ETW in practice; this is just a reminder to look at provenance, not only protections.
```

### Process DEP policy and image flags

Two knobs shape DEP in user mode:

* **Process policy**: `SetProcessDEPPolicy` (one-way during lifetime), system defaults (`OptIn`, `OptOut`, `AlwaysOn`, `AlwaysOff`).
* **Image header**: `DllCharacteristics` carries `NXCompat`. Most OS binaries are NX-compatible; legacy images may not be.

In practice you rarely *turn off* DEP today; instead, bypasses aim to **avoid executing non-X memory** (e.g., ROP to already-executable code) or to **legitimately** create X memory (JIT, AOT caches) and run from there.

### W^X on Windows: where it stands

Windows does not globally enforce W^X for all processes, but there are policies that make it **practically W^X** for many:

* **Dynamic Code** policy (aka **ACG**): disables creating executable pages from writable ones and disallows `WriteProcessMemory` into RX memory.
* **CFG/CET**: not execution permission per se, but constrain *where* control flow may land.
* **AppContainer / PPL / WDAC**: trust frameworks that narrow which binaries can supply X code.

W^X thinking remains valuable even when the OS does not strictly enforce it: design your loader/tools to avoid RWX, prefer **RW→RX with metadata** (unwind/CFG), and close the loop by locking dynamic code where possible.

### How bypass/abuse typically looks

* **ROP/JOP**: stay within RX image pages, chain gadgets, then call `VirtualProtect`/`NtProtectVirtualMemory` to flip your RW buffer to RX.
* **JIT camouflage**: mimic a JIT’s RW→RX behavior and function table registration to evade naive hunts.
* **Section trickery**: map a **PAGE\_EXECUTE** view of a data section or remap a section with different protections across processes.
* **Driver assist**: have a vulnerable driver set PTEs executable, sidestepping user-mode policy (outside this chapter’s scope; see Kernel Primer).

**Defensive lens:** follow **who** flips protections (**token**), **where** (**Private vs. Image**), and **what next** (newly RX region actually executes? Stacks/ETW say yes/no).

### WinDbg/ETW triage micro-playbook

* `!address` to tag **Image vs. Private** RX.
* `!vad` for per-region flags (NoChange, Guard).
* ETW: join `VirtualProtect`/`NtProtectVirtualMemory` with `ImageLoad` and call stacks; an RX transition immediately followed by `CreateThread`/`QueueUserAPC` landing in that region is high-signal.

```text
; WinDbg quick view
!address                ; inspect protections and types
!vad 0                  ; beware: noisy on big processes—scope first
lmv m <modname>         ; confirm image-backed RX
```

## Why this matters for exploitation / anti-exploit / malware analysis

Exploitation must either **execute from RX** (ROP/JOP) or **create RX** (RW→RX) at some point. Malware loaders chase the same endpoints, trying to look like JITs. DEP/NX force attackers to burn techniques that defenders can see: RW→RX transitions, executable section mappings, or jumps into known images. Analysts who anchor on **protection + provenance + sequence** distinguish benign JIT churn from staged payloads with much less noise.

## APIs and functions

* `VirtualProtect` / `NtProtectVirtualMemory` – change page protections; hunt W→X transitions here.
* `VirtualAlloc` / `NtAllocateVirtualMemory` – create anonymous memory; watch for later flips to executable.
* `SetProcessDEPPolicy` / `GetProcessDEPPolicy` – set/read process DEP options (one-way enable during lifetime).
* `SetProcessMitigationPolicy` – configure **ProcessDynamicCodePolicy** (ACG-like behavior), **StrictHandleCheck**, CFG knobs (details in CFI chapter).
* `VirtualQueryEx` – enumerate memory regions with protection and type; foundation for scans.
* `CreateFileMappingW` / `MapViewOfFile` – map sections that can be made executable; watch for unexpected `PAGE_EXECUTE*`.
* `RtlAddFunctionTable` – register unwind info; benign JIT/loader behavior vs. sloppy shellcode.

## Pitfalls, detection notes, and anti-analysis gotchas

* **RWX ≠ automatic evil**: some legacy engines request `PAGE_EXECUTE_READWRITE`; judge in context (caller, module, frequency). Prefer policy to *prevent* RWX for your estate.
* **JIT false positives**: JavaScript/CLR runtimes do frequent RW→RX. Join with **module lineage** (JIT DLLs loaded) and **function table registration** to avoid noise.
* **WOW64 mismatches**: 32-bit processes on x64 use a different `ntdll`; ensure your hooks/telemetry see both.
* **Guard page confusion**: stack growth and probes raise guard faults; don’t conflate with DEP.
* **Service flips as noise**: security products also flip protections while deploying trampolines/shims; distinguish signed/known modules from anonymous RX.
* **One-way DEP**: `SetProcessDEPPolicy` can **enable** but not fully disable DEP in many modes; don’t assume you can “turn it off.”
* **Large pages**: executable large pages exist but are rare; tools assuming 4 KiB granularity misattribute protections.
* **Copy-on-write**: relocation/import fixups create **private** variants of image pages—RX-after-write does not necessarily mean self-modifying code.

## Cross-references

* Memory provenance and VAD inspection are introduced in **Memory & Virtual Address Space** (Part 1).
* How loaders create image-backed RX (and how manual maps differ) is in **Windows Loader & Image Activation** (Part 1).
* The precise NT entry points, marshalling, and direct-syscall variants appear in **Syscalls & the NTAPI Boundary** (Part 1).
* Control-flow constraints and shadow stacks are detailed in **Compiler & Hardware CFI: CFG, CET (Shadow Stack/IBT)** (Part 2).
* Trust frameworks that strengthen “who may create execute” (WDAC, PPL, HVCI, ACG context) are in **Trust & Integrity: Secure Boot, WDAC/App Control, Code Integrity, PatchGuard, VBS/HVCI, PPL** (Part 2).
* Offensive use (ROP to `VirtualProtect`, section mapping) and injection patterns continue in **Process Injection & Hooking** (Part 3).

## Glossary

* **NX (No-eXecute)**: CPU page attribute disallowing instruction fetches from the page.
* **DEP (Data Execution Prevention)**: Windows policy layer using NX to block executing from data pages.
* **W^X**: Security principle enforcing **write XOR execute** memory.
* **RW→RX Transition**: Changing a region from writable to executable; common in JITs and payload staging.
* **Provenance (Image/Mapped/Private)**: What backs a region; core discriminant in detection.
* **ACG / Dynamic Code Policy**: Mitigation that restricts making/altering executable pages at runtime.
* **Function Table (Unwind Info)**: Metadata for exception unwinding; often missing in crude shellcode.
* **Large Page**: 2 MiB (x64) mappings; unusual for user executable memory.
* **Guard Page**: A page that raises a fault when touched; used for stack growth/probing.
* **`DllCharacteristics`**: PE header flags including `NXCompat` and `DynamicBase`.

## Key takeaways

* Think **permissions + provenance**: an RX page is interesting only in the context of what backs it and how it appeared.
* DEP forces attackers into **ROP/JOP or RW→RX**—both leave crisp artifacts defenders can join with ETW/VADs.
* Prefer **W^X-friendly** engineering: no RWX, minimal and well-annotated RW→RX with unwind/CFG data, and lock dynamic code via mitigation policy.
* Telemetry anchored at the **NT layer** (`NtProtectVirtualMemory` + VAD/type + call stack) outlives user-mode hook games.
* Always validate across **bitness** and beware of **JIT noise**—use metadata and sequence analysis to keep signals clean.
