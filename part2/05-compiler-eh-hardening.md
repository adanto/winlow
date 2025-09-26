# Part 2 – Exploitation Mitigations: Compiler & EH Hardening (/GS, SafeSEH/SEHOP history, EHCONT)

**What this chapter covers**

* How compiler features (/GS, /guard\:ehcont, SafeSEH) and OS policies (SEHOP) harden Windows exception and stack behavior
* What changes between x86 SEH chains and x64 table-driven unwinding—and why that matters
* How modern codegen (unwind metadata, function tables) interacts with DEP/CFI/CET and loader behavior
* Practical posture checks, triage hints, and common failure modes in apps, packers, and injectors

## Core concepts

### Stack canaries: /GS then and now

The **/GS** compiler switch inserts a **stack cookie** (a canary) between a function’s local buffers and its saved return state. On function epilogue, the compiler compares the cookie against a known value; if it differs, the process raises a fail-fast exception instead of performing the return. The cookie is process-specific and salted with per-module entropy to reduce predictability. `/sdl` and modern CRTs extend checks to more patterns (e.g., `_CRT_GSStackCookie` initialization, safer CRTs).

```c
// Compile with: cl /GS /O2 gs_demo.c
#include <stdio.h>
#include <string.h>

void vulnerable(const char* s) {
    char buf[32];
    // Deliberately unsafe to trigger /GS (DO NOT run with attacker data)
    strcpy(buf, s);
    printf("Echo: %s\n", buf);
}

int main(int argc, char** argv) {
    const char *p = argc > 1 ? argv[1] : "hello";
    vulnerable(p);  // On overflow, /GS detects cookie corruption and terminates
    return 0;
}
```

**What /GS stops:** classic stack smashing that overwrites the return address or adjacent metadata.
**What it doesn’t:** non-contiguous corruptions (e.g., **heap** or **object vtables**), **read-only** info leaks, or **ROP** chains that never touch the protected frame. It also relies on the compiler’s ability to **see** a risky frame; hand-rolled assembly shims or opaque inline `memcpy` may reduce its coverage.

### Exception handling on Windows: SEH, VEH, UEF—in two architectures

Windows has three user-mode exception mechanisms:

* **SEH (Structured Exception Handling):** function-scoped handlers registered via the compiler; on **x86**, a per-thread linked list (TEB-anchored) of `_EXCEPTION_REGISTRATION` frames; on **x64**, SEH is **table-driven** using unwind metadata—no walkable linked list exists.
* **VEH (Vectored Exception Handling):** process-wide handlers called **before** SEH, useful for instrumentation.
* **UEF (Unhandled Exception Filter):** last-chance handler invoked when no one handles the exception.

The move from x86’s **linked list** to x64’s **unwind tables** eliminated a class of stack-based SEH overwrites and shifted reliability to correctly generated **.pdata/.xdata** (function tables and unwind info).

### SafeSEH (x86) and SEHOP (OS policy)

**SafeSEH** (linker option) records a **table of valid exception handlers** for an image (x86 only). During dispatch, the OS verifies that the handler pointer appears in that table. This breaks the classic `SEH overwrite → jump to attacker buffer` pattern—**if** all loaded x86 images are SafeSEH-aware.

**SEHOP (Structured Exception Handler Overwrite Protection)** is an **OS-level** mitigation that validates the x86 SEH chain’s integrity (walkable and ends in a known “safe” record) **before** dispatching. It does not require recompilation and covers non-SafeSEH modules, making SEH overwrite exploitation unreliable even on legacy binaries.

**Reality today:** on x64, SafeSEH is irrelevant (no SEH chain to corrupt). On x86, SEHOP plus SafeSEH drastically raises the bar, but info leaks and non-SEH corruption still matter.

### EHCONT: guarding exception continuations

Modern toolchains can emit **EH Continuation metadata** (`/guard:ehcont`) so the OS/runtime validates **where** an exception may resume (continuation targets) similar to how **CFG** validates indirect call targets. This limits abuse of exception machinery to pivot control flow to **non-canonical** landing pads.

* The metadata lives in the **Load Configuration Directory** (per-image tables) and/or per-process registries maintained by the runtime.
* If enabled and enforced, unwinding into an unregistered continuation triggers a fail-fast—catching many “return-into-data” and malformed handler targets.

**Interaction:** EHCONT complements **CFG** (indirect calls) and **CET** (returns and IBT). Together they reduce “weird machine” surfaces during exception dispatch and resumption.

### Unwind metadata and function tables: the new single point of truth

On x64, structured exception dispatch and `__try/__except` rely on **.pdata/.xdata** (unwind info per function). Correct metadata is essential for:

* **Exceptions** (stack unwinds, finally blocks)
* **C++ EH** (destructors, catch handlers)
* **Stack walking** (profilers, crash dumps)
* **CFI** cooperation (e.g., function table integrity with CFG/CET)

JITs, packers, and manual mappers must call **`RtlAddFunctionTable`** (or publish equivalent load-config data) for dynamically generated code; otherwise exceptions through those regions are undefined and often crash under pressure.

```c
// Minimal pattern: register unwind data for JIT/manual map regions (illustrative; not complete)
#include <windows.h>
#include <dbghelp.h>

typedef struct _UNWIND_INFO_MIN { BYTE data[4]; } UNWIND_INFO_MIN; // placeholder

int main() {
    BYTE *rx = (BYTE*)VirtualAlloc(NULL, 0x1000, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    // emit code + fill UNWIND_INFO for [rx, rx+codeSize) properly in real engines
    DWORD64 base = (DWORD64)rx;
    RUNTIME_FUNCTION rf = { .BeginAddress = 0, .EndAddress = 0x100, .UnwindData = 0x200 }; // offsets from base
    UNWIND_INFO_MIN ui = {0};  // real unwind info omitted
    // Register table so exceptions won’t choke
    RtlAddFunctionTable(&rf, 1, base);
    // ...
    return 0;
}
```

**Analyst tip:** an exception through **private RX** without a registered function table often ends in `STATUS_INVALID_UNWIND_TARGET` or similar fail-fast; legit JITs register tables early and consistently.

### Putting it together with DEP/CFI/CET

* **/GS** protects **returns** indirectly by detecting adjacent stack writes; **CET-Shadow Stack** protects returns directly; **CFG/EHCONT** constrain indirect calls and exception continuations.
* **DEP/W^X** force payloads into RX memory or require **RW→RX** transitions; robust JITs pair transitions with **function tables** and optional **CFG/EHCONT** updates.
* **Loader metadata** (load config, `DllCharacteristics`) hints whether a module supports ASLR, NX, CFG, and EHCONT; reconcile these flags with observed behavior.

### Posture and verification, quickly

* **x64 binaries** should carry unwind info for all code; apps that mix **hand-rolled** assembly must still publish correct `.pdata`.
* **x86 estates** should have **SEHOP** enabled and avoid loading non-SafeSEH plug-ins into high-risk processes.
* **Build flags**: `/GS`, `/sdl`, `/guard:ehcont` (and `/guard:cf` discussed earlier) should be standard for first-party code.

```powershell
# Coarse posture readout (what the OS thinks about key mitigations for a process)
$h = (Get-Process -Name notepad).Handle
Add-Type @"
using System; using System.Runtime.InteropServices;
public class Mit {
  [StructLayout(LayoutKind.Sequential)] public struct CFG { public uint Flags; }
  [StructLayout(LayoutKind.Sequential)] public struct SS { public uint Flags; }
  [DllImport("kernel32.dll")] public static extern bool GetProcessMitigationPolicy(IntPtr h, int p, out CFG v, int sz);
  [DllImport("kernel32.dll")] public static extern bool GetProcessMitigationPolicy(IntPtr h, int p, out SS v, int sz);
}
"@
$cfg=[Activator]::CreateInstance([type]"Mit+CFG"); $ss=[Activator]::CreateInstance([type]"Mit+SS")
[void][Mit]::GetProcessMitigationPolicy($h, 8, [ref]$cfg, [Runtime.InteropServices.Marshal]::SizeOf($cfg)) # CFG
[void][Mit]::GetProcessMitigationPolicy($h, 27, [ref]$ss,  [Runtime.InteropServices.Marshal]::SizeOf($ss))  # User Shadow Stack
"CFG flags: 0x{0:X}, ShadowStack flags: 0x{1:X}" -f $cfg.Flags, $ss.Flags
```

**Note:** there is no single “EHCONT enabled” flag exposed via this API; verify at **binary** level (load-config entries) and by observing fail-fast reasons in crash telemetry.

## Why this matters for exploitation / anti-exploit / malware analysis

Memory corruption now collides with **multiple guardrails**: canary checks, exception chain validation, continuation target validation, control-flow guards, and (on modern hardware) return/branch enforcement. Attackers respond by pivoting to **info leaks**, **data-only** attacks, or subverting **JIT/loader** edges that legitimately generate code. Defenders and analysts who tie **build flags + image metadata + runtime events** can tell robust JIT activity from fragile manual-map stubs and can spot weak links (legacy x86 plug-ins, missing unwind info).

## APIs and functions

* `RtlAddFunctionTable` / `RtlDeleteFunctionTable` – register/unregister unwind metadata for dynamic code regions.
* `RtlLookupFunctionEntry` – resolve unwind info for a given PC; useful for triage tooling.
* `RaiseException` – synthetic exceptions for testing handlers (use sparingly in isolated labs).
* `AddVectoredExceptionHandler` / `RemoveVectoredExceptionHandler` – register/unregister VEH; common in packers/instrumentation.
* `SetUnhandledExceptionFilter` – last-chance handler; often neutered by **Extension Point Disable Policy** in hardened apps.
* `GetProcessMitigationPolicy` / `SetProcessMitigationPolicy` – read/tune process mitigations (CFG/CET context for EH hardening).
* `IsProcessorFeaturePresent(PF_GUARD_EH_CONTINUATION)` – if available, coarse signal that EHCONT guards are recognized on the platform.

## Pitfalls, detection notes, and anti-analysis gotchas

* **Assuming x64 ≈ x86:** there is **no** SEH linked list on x64; SafeSEH/SEHOP reasoning does not transfer directly.
* **Missing unwind info:** JIT/manual-map code without function tables breaks exceptions and stack walking; under pressure it looks like “random” AVs.
* **/GS blind spots:** small or frame-pointer-omitted functions may have no cookie; whole-program optimization can coalesce frames—verify at the binary, not by assumption.
* **VEH order dependency:** multiple vectored handlers fire in **reverse registration** order; debugging artifacts change timing and mask races.
* **EHCONT + CET interactions:** hand-rolled thunks that resume at non-ENDBR addresses or skip continuation registration fault even if the code is otherwise valid.
* **Packers and trampolines:** hot-patching must preserve prologues, unwind info, and any EHCONT/CFI metadata—sloppy patches create heisenbugs under stress.
* **Legacy x86 plug-ins:** mixing non-SafeSEH modules into modern processes silently re-introduces SEH overwrite avenues; vet third-party modules aggressively.

## Cross-references

* Execution permissions and RW→RX behavior are covered in **DEP / NX / W^X** (Part 2).
* Indirect call/return defenses (CFG, CET) appear in **Compiler & Hardware CFI: CFG, CET (Shadow Stack/IBT)** (Part 2).
* Unwind tables, loader behavior, and metadata live in **Windows Loader & Image Activation** and **Memory & Virtual Address Space** (Part 1).
* Syscall perspectives on `NtProtectVirtualMemory` and exception raising are in **Syscalls & the NTAPI Boundary** (Part 1).
* ROP/JOP techniques that collide with /GS and CET are detailed in **ROP & JOP** (Part 4).

## Glossary

* **/GS**: MSVC stack-canary option that detects overwrites of return-adjacent data.
* **SEH/VEH/UEF**: Structured, Vectored, and Unhandled exception handling tiers in Windows.
* **SafeSEH**: x86 linker table of valid exception handlers; dispatcher rejects others.
* **SEHOP**: OS-level validation of the x86 SEH chain integrity before dispatch.
* **Unwind Info**: Per-function metadata that drives x64 exception unwinding and stack walking.
* **EHCONT**: Guarded exception continuation; validates legal resumption targets during exception handling.
* **RUNTIME\_FUNCTION**: Structure indexing x64 function ranges and their unwind data.
* **Fail-fast**: Immediate process termination on guard violation (cookie mismatch, invalid continuation).
* **Load Config Directory**: PE directory carrying security metadata (CFG/EHCONT tables, security flags).
* **Extension Point Disable Policy**: Process mitigation that blocks UEF tampering/shims.

## Key takeaways

* /GS, SafeSEH/SEHOP, and EHCONT collectively raise the cost of turning **memory corruption** into **control flow**—but do not fix logic flaws or leaks.
* x64’s **table-driven unwinding** shifts correctness onto **unwind metadata**; dynamic code must register **function tables** to be reliable.
* Treat exception machinery as part of **CFI**: validate **continuations** and preserve **unwind/landing pads** when patching or injecting.
* In triage, correlate **build flags** and **image metadata** with **runtime events** (fail-fast reasons, unwind failures) to separate bad loaders from benign JITs.
* Harden builds by default: `/GS /sdl /guard:ehcont` (plus CFG/CET where appropriate), and keep legacy x86 modules out of high-risk processes.
