# Part 2 – Exploitation Mitigations: Compiler & Hardware CFI: CFG, CET (Shadow Stack/IBT)

**What this chapter covers**

* What Control-Flow Guard (CFG) and Intel CET (Shadow Stack/IBT) enforce and where they sit (compiler vs. CPU)
* How CFG encodes valid indirect-call targets and how CET defends RET/JMP/IND flows
* Practical interactions with loaders, JITs, exception unwinding, and RW→RX transitions
* How to inspect a process’s CFI posture and how red teams/defenders detect evasion attempts
* Minimal, safe examples for reading policies and authoring valid indirect-call stubs

## Core concepts

### The split: compiler CFI vs. hardware CFI

**CFG** is a **compiler- and linker-assisted** user-mode mitigation. The toolchain inserts checks before **indirect calls** (e.g., through function pointers, vtables) and builds a **per-module bitmap** of **valid call targets** (CTs). The runtime verifies that an intended target is marked valid; if not, the call is blocked with a guard failure.

**CET** (Control-flow Enforcement Technology) is **hardware-assisted** (x86-64). In Windows user mode it has two pieces:

* **Shadow Stack (SS)**: the CPU writes return addresses to a **write-only, separate stack** and checks they match on `RET`. Mismatches trigger a shadow-stack fault.
* **Indirect Branch Tracking (IBT)**: the CPU requires indirect branches (`JMP/CALL r/m64`) to land at an **ENDBR** landing pad. Missing/garbled pads fault early.

CFG protects **where** indirect calls may go; CET protects **return addresses** and **entry pads** for indirect targets.

---

### CFG in practice: bitmaps and call-site thunks

When you build with `/guard:cf`, the compiler:

* Emits **guard checks** at every indirect call site.
* Populates a **bitset** of valid targets for each image.
* Optionally exports **helper metadata** for dynamic languages/JITs.

At runtime, a check gates the call roughly like: “is `target` a **callable function entry** recorded for some module in this process?” If **false**, the kernel raises a **CFG violation**.

Important case: **dynamically generated code** (JITs, loaders) that should be callable indirectly must **register** their CTs, or calls into that region will fault—even if the code is valid and executable.

```c
// Mark a tiny stub as a valid CFG call target (x64; minimal checks)
#include <windows.h>
#include <cfgmgr32.h>   // for SET_PROCESS_VALID_CALL_TARGETS (via Windows SDK; not cfgmgr API)
#include <stdio.h>

typedef struct _CFG_CALL_TARGET_INFO {
    ULONG_PTR Offset;    // offset from base
    ULONG Flags;         // e.g., CFG_CALL_TARGET_VALID
} CFG_CALL_TARGET_INFO;

int main() {
    SIZE_T sz = 0x1000;
    BYTE*  base = (BYTE*)VirtualAlloc(NULL, sz, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!base) return 1;

    // Write a trivial stub: ret
    base[0] = 0xC3;

    CFG_CALL_TARGET_INFO ct = {0};
    ct.Offset = 0;                     // target at base+0
    ct.Flags  = 0x1;                   // CFG_CALL_TARGET_VALID

    // Tell the process CFG bitmap this page contains a valid target at offset 0
    BOOL ok = SetProcessValidCallTargets(GetCurrentProcess(), base, sz, 1, (PCFG_CALL_TARGET_INFO)&ct);
    printf("SetProcessValidCallTargets=%d\n", ok);

    // Call through an indirect pointer (guarded)
    void (*fn)(void) = (void(*)(void))base;
    fn();                              // succeeds only if CT is valid and CET IBT permits
    return 0;
}
```

**Notes:**

* `SetProcessValidCallTargets` **does not** grant execute permission; it only annotates CFG metadata. You still need `PAGE_EXECUTE*`.
* If **CET-IBT** is active, your stub must begin with a legal landing pad (e.g., `ENDBR64`) or the CPU will fault before CFG runs. See below.

---

### CET in practice: ENDBR pads and shadow stacks

When IBT is on, **every legal indirect-branch entry** starts with a small **landing pad** instruction (`ENDBR64` on x64). Compilers insert it automatically for functions that may be reached via **indirect** transfer. If an indirect branch lands **anywhere else**, the CPU raises an **indirect branch violation**.

**Shadow Stack** stores return addresses on a protected stack. On `CALL`, the CPU **pushes** the return to both normal and shadow stacks; on `RET` it compares. If someone overwrote the normal stack return (e.g., classic buffer overflow), the mismatch triggers a **shadow-stack fault** before control leaves the function epilogue.

Implications for loaders/JITs/manual maps:

* Hand-made **stubs** that are targets of **indirect** calls should start with **ENDBR64** when IBT is active.
* **RET-oriented (ROP)** chains collide with Shadow Stack unless the attacker finds a way to **synchronize** or **disable** SS (rare in user-mode without a vulnerability).

```text
; WinDbg quick tells for CFI failures
!analyze -v
  // Look for STATUS_STACK_BUFFER_OVERRUN / STATUS_FAIL_FAST_EXCEPTION with reason code
kb
  // CFG: often shows ntdll!LdrpValidateUserCallTarget/guard dispatch
r
  // CET SS: last !analyze shows SHADOW_STACK status; IBT: illegal target landing without ENDBR
uf <module>!<symbol>
  // Disassemble: functions reachable indirectly begin with endbr64 when built with CET support
```

---

### Loader and memory interactions

CFI lives alongside **DEP/W^X** and the **loader**:

* **RW→RX transitions**: creating or modifying executable memory does **not** make it **CFG-callable**; register CTs if you plan to **indirect-call** into it.
* **Manual maps**: if you bypass the loader’s book-keeping, you must replicate **unwind**, **CFG**, and (with CET) **ENDBR** semantics, or your module will crash under exceptions or CFI.
* **Delay-load/vtables**: CFG watches the **call site**, not just the destination. Patching a vtable to an unregistered target becomes noisy.

**Defensive lens:** join **`VirtualProtect`/`NtProtectVirtualMemory` (W→X)** with **`SetProcessValidCallTargets`** and **ImageLoad** to separate benign JITs from covert loaders.

---

### Friction points you will see

* **JIT engines**: do frequent RW→RX with **function table** registration and **CT updates**. Their patterns are regular and signed—good allow-listing anchors.
* **Hooking frameworks**: create **trampolines** and sometimes emit **indirect thunks**. Correctly engineered hooks install **ENDBR64**, mark **CTs**, and maintain unwind info.
* **Third-party plugins**: old binaries without CFG/CET support expose **unprotected indirect entries**; the OS may still enforce IBT at module boundaries depending on policy, which can break them.
* **CFG short-circuits**: attackers try to **direct-call** or **jump** around the guard thunk; defenders look for call-site shapes and atypical stacks.

### Reading a process’s CFI posture

```c
// Query CFG and user Shadow Stack policies (x64; minimal checks)
#include <windows.h>
#include <stdio.h>

int main() {
    PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfg = {0};
    PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY  ss  = {0};

    GetProcessMitigationPolicy(GetCurrentProcess(),
        ProcessControlFlowGuardPolicy, &cfg, sizeof(cfg));
    GetProcessMitigationPolicy(GetCurrentProcess(),
        ProcessUserShadowStackPolicy, &ss, sizeof(ss));

    printf("CFG: Enabled=%u Strict=%u SuppressExports=%u\n",
        cfg.EnableControlFlowGuard, cfg.StrictMode, cfg.SuppressExports);
    printf("CET-SS: Enabled=%u SetContextIpValidation=%u BlockNonCetBinaries=%u\n",
        ss.EnableUserShadowStack, ss.SetContextIpValidation, ss.BlockNonCetBinaries);
    return 0;
}
```

**Field hints:**

* `StrictMode` tightens CT validation at call sites.
* `SuppressExports` reduces the surface of auto-valid exported functions.
* `BlockNonCetBinaries` (policy) rejects modules without CET metadata in strict estates.

---

### Why this matters for exploitation / anti-exploit / malware analysis

CFG/CET force attackers to **earn** control flow: either land on **legitimate CTs** and **ENDBR** pads or get stopped, and preserve **return address integrity** or trip a shadow-stack fault. For defenders, this concentrates signal: **indirect-call to non-CT** and **RET mismatch** are high-confidence events. Analysts who map **RW→RX → CT registration → execution** can separate everyday JIT churn from covert staging and spot fragile loaders that forget CFI plumbing.

## APIs and functions

* `GetProcessMitigationPolicy` – read CFG and user Shadow Stack posture in a process.
* `SetProcessMitigationPolicy` – opt into stricter policies where allowed (e.g., block non-CET images in your process).
* `SetProcessValidCallTargets` – register CFG call targets in dynamically generated regions.
* `VirtualProtect` / `NtProtectVirtualMemory` – permission flips; correlate with CT registration for dynamic code.
* `RtlAddFunctionTable` – register unwind info for generated code; keeps exceptions sane beside CFI.
* `GetModuleInformation` / `GetProcAddress` – audit whether targets fall within **image CTs** or **private RX**.
* `IsProcessorFeaturePresent(PF_SHADOW_STACK)` – coarse check for CET availability on the CPU/OS.
* `LdrRegisterDllNotification` – observe module loads to validate CET/CFG flags per image before calls happen.

## Pitfalls, detection notes, and anti-analysis gotchas

* **“CFG bypassed” false alarms:** a **direct call** to a symbol is legal even under CFG; only **indirect** calls are guarded.
* **Forgotten ENDBR:** on CET systems, hand-rolled thunks without **ENDBR64** fault before CFG runs.
* **CT drift after relocations:** moving or rebasing generated code without re-registering CTs yields sporadic faults.
* **WOW64 differences:** CET/IBT and CFG posture can differ for 32-bit processes on x64; match bitness when testing.
* **Export over-trust:** `SuppressExports=0` may mark many exports as valid CTs; attackers prefer exported preambles as landing pads.
* **Hook collisions:** hot-patching prologues must preserve **landing pads** and **guard checks**; sloppy hooks create heisenbugs under CET.
* **Telemetry blind spots:** user-mode hooks cannot “see” CPU-enforced IBT/SS faults; rely on **first-party crash telemetry/ETW** or debugger analysis.

## Cross-references

* Page permissions and W→X are in **DEP / NX / W^X** (Part 2); CFI sits on top of those basics.
* Memory provenance (image vs. private), unwind registration, and loader behavior are in **Memory & Virtual Address Space** and **Windows Loader & Image Activation** (Part 1).
* Syscall semantics for `NtProtectVirtualMemory` and friends appear in **Syscalls & the NTAPI Boundary** (Part 1).
* ROP/JOP tradecraft that collides with CET Shadow Stack is discussed in **ROP & JOP** (Part 4).
* Evasion and unhooking angles touching guard checks surface again in **Telemetry Tampering & Unhooking (ETW, Direct Syscalls)** (Part 3).

## Glossary

* **CFG (Control-Flow Guard)**: compiler/runtime system that validates **indirect call** destinations against a bitmap of allowed targets.
* **CET (Control-flow Enforcement Technology)**: CPU features (Shadow Stack, IBT) that protect returns and indirect-branch entries.
* **Shadow Stack**: write-protected stack of return addresses checked on `RET`.
* **IBT (Indirect Branch Tracking)**: CPU enforcement requiring indirect branches to land on **ENDBR** pads.
* **Call Target (CT)**: an address registered as legal for indirect calls under CFG.
* **ENDBR64**: landing instruction for IBT on x64; marks legal indirect-branch entries.
* **StrictMode**: CFG policy that tightens validation rules at call sites.
* **JIT**: runtime that emits code dynamically; must register CTs and unwind info to coexist with CFI.
* **Trampoline/Hook**: small stub that redirects execution; must preserve CFI invariants.
* **Fail-fast**: intentional process termination on CFI violations (guard failures, SS/IBT faults).

## Key takeaways

* **CFG** gates **indirect calls**; **CET** guards **returns** and **indirect-branch entries**—they complement, not replace, DEP/ASLR.
* Dynamic code that is a target of **indirect** calls must add **ENDBR** (for IBT) and **register CTs** (for CFG) or it will fault.
* Join **W→X → CT registration → execution** in telemetry to distinguish JITs from covert loaders.
* Hooks and trampolines must preserve **landing pads, guard thunks, and unwind info** to stay stable under CFI.
* Treat CFI violations as **high-confidence** signals; they usually indicate memory corruption, bad loaders, or attempted redirection.

