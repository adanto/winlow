# Part 3 – Anti-Disassembly

**What this chapter covers**

* Why static disassemblers make assumptions and how malware violates them
* The main anti-disassembly patterns on Windows (overlap, opaque predicates, computed control flow, SEH/VEH tricks, packers/virtualizers)
* How loader/runtime behavior (RW→RX, function tables) interacts with static views
* Practical triage: minimal heuristics and dynamic anchors that outlive obfuscation
* Safe, tiny examples that show shape—not weaponization

## Core concepts

### What disassemblers assume (and attackers break)

Most static tools rely on **recursive descent** (follow reachable control flow from known entry points) or **linear sweep** (decode bytes sequentially). They assume:

* Every **branch target** is visible or derivable.
* Execution uses **canonical fall-through**; no secret jumps into the middle of instructions.
* The code section contains **only code**; data lives elsewhere or is marked.
* Exceptions and callbacks are **rare** redirections, not the main control vehicle.

Anti-disassembly undermines those assumptions. The goal is not unbreakable secrecy but **time and doubt**—to slow analysts, fuzz triage tools, and frustrate pattern-matching.

---

### Variable-length encoding is a feature (to attackers)

On x86/x64, instruction lengths vary (prefixes, ModRM/SIB, immediates). Attackers place **decoy bytes** so a linear decoder sees a bogus stream while the true control path **jumps into the middle** of a multi-byte instruction (or uses prefixes to “slide” decode state).

```asm
; x86 illustrative overlap (do not run; for reading only)
start:
    db 0xE8, 0x00, 0x00, 0x00, 0x00 ; call $+5  (linear sweep "sees" a CALL)
    db 0xEB, 0x05                   ; jmp +5   (but we'll jump here from elsewhere)
path_b:
    ; Target jumps into the 2nd byte of the CALL's immediate — decoding diverges
    ; Many linear sweepers now decode garbage; actual runtime never reaches it via fall-through.
```

**Why it works:** linear sweeps treat **every byte** as a potential opcode; recursive decoders still get confused if they cannot prove the “mid-instruction” entry is impossible.

---

### Opaque predicates and control-flow flattening

An **opaque predicate** is always true/false at runtime but hard to prove statically. Combine many with a **dispatcher** (a loop that switches on a “state” variable) and you get **flattened control flow** that hides high-level structure.

```c
// Shape of a flattened dispatcher (toy)
for (;;) {
    switch (state) {
      case 0: if ((x*x) % 4 == 0) { state = 3; } else { state = 7; } break; // always true for even x chosen upstream
      case 3: block_A(); state = 9; break;
      case 9: block_B(); return;
      default: state ^= salt; break; // noise
    }
}
```

**For analysts:** execute to collect a **state→basic-block** map, or lift to IR then **symbolically simplify** predicates. Flatteners seldom preserve source-level structure; dynamic coverage quickly clarifies the real sequence.

---

### Computed control flow and “table tricks”

`switch` statements compile to **jump tables**. Obfuscated code crafts **index arithmetic** to point into **data blobs** located in the code section, deliberately confusing decoders that expect aligned, monotonically increasing table entries.

```c
// Bogus jump table shape (toy)
static const uint32_t jt[] = { 0x101, 0xF00D, 0xDEAD, 0xBEEF }; // mixed code/data
goto * (base + ((key ^ salt) & 3 ? jt[(key & 3)] : jt[0]));
```

**Tell:** references into `.text` that are subsequently dereferenced as **addresses**, especially when bounds are masked in non-obvious ways.

---

### SEH/VEH-directed control

On x86, overwriting SEH used to be an exploit; modern Windows adds **SEHOP** and encourages **SafeSEH** (see mitigations chapters). Evasive code still uses **exceptions as control flow** to mislead static tools, especially via **Vectored Exception Handlers (VEH)** that run **before** SEH.

```c
// Minimal VEH redirection (educational; not robust)
#include <windows.h>
static LONG CALLBACK vh(EXCEPTION_POINTERS* e){
    if (e->ExceptionRecord->ExceptionCode==EXCEPTION_INT_DIVIDE_BY_ZERO){
        e->ContextRecord->Rip = (DWORD64)GetProcAddress(GetModuleHandleW(L"kernel32"), "Beep"); // jump target
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
int main(){
    AddVectoredExceptionHandler(1, vh);
    volatile int z = 0;  // deliberate fault
    (void)(1/z);
}
```

**Why it confuses:** the static CFG sees a divide instruction; **real control** jumps into an API via VEH. On x64, **table-driven unwinding** prevents classic SEH overwrite, but VEH-based pivots still exist.

---

### Packers, self-modifying code, and virtualizers

* **Packers** decrypt/decompress at runtime, then **RW→RX** (or **RWX→RX**) and transfer control.
* **Self-modifying code** patches opcodes or immediates on the fly; disassembly of the original bytes is misleading.
* **Virtualizers** (VMProtect-class) convert functions into a **bytecode** interpreted by a custom VM—static disassembly sees only the interpreter.

```c
// The benign skeleton of a decrypt-then-execute stub (shape only)
#include <windows.h>
int main(){
    SIZE_T sz=4096; BYTE* p=(BYTE*)VirtualAlloc(NULL,sz,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    // …fill p with encrypted bytes…
    // …decrypt in place…
    DWORD old=0; VirtualProtect(p, sz, PAGE_EXECUTE_READ, &old);
    FlushInstructionCache(GetCurrentProcess(), p, sz);
    ((void(*)(void))p)(); // jump
}
```

**Analyst tactic:** treat **RW→RX** and **execute-from-Private-RX** as primary anchors. Statics can wait; dump the post-decrypt region and analyze *that*.

---

### API hashing, import elimination, and delayed resolution

Replace readable imports with **runtime-resolved** addresses (hash over export names, resolve via `GetProcAddress`/`LdrGetProcedureAddress`). Static IAT becomes empty or innocuous.

**Tell:** tight export-iteration loops, unusual **name hashing**, references to **PE export structures** inside `.text`, and **late** calls to sensitive APIs.

---

### CET/CFG interaction you’ll feel

Modern Windows adds **CFG** (guards indirect calls) and **CET** (Shadow Stack / IBT). Hand-rolled thunks and unusual entry points must:

* Start indirect targets with **ENDBR64** (IBT landing pads).
* Register **valid call targets** using `SetProcessValidCallTargets` if they intend to be indirect-callable.
* Provide **unwind info** for exceptions (`RtlAddFunctionTable`) or stack walking breaks.

Obfuscators that ignore CFI metadata **crash** under pressure—use that to your advantage (see mitigations chapters for deeper details).

---

### Practical triage heuristics that scale

* **Provenance before opcodes**: Is execution in **Image RX** or **Private RX**? Manual maps and decrypted stubs almost always start in Private RX.
* **Sequence > strings**: `VirtualProtect(W→X)` followed by **thread/APC** into the region is more meaningful than a thousand API hashes.
* **Stacks matter**: Call stacks that jump from normal veneers into **short private stubs** are the hallmark of loader indirection.
* **Join static and dynamic**: Disassemble only **what executed** (coverage-guided). IR lifting + simplification defeats many opaque predicates.

## Why this matters for exploitation / anti-exploit / malware analysis

Exploits and loaders use anti-disassembly to **slow reverse engineering** and to **confuse detections** that depend on static signatures. Defenders who focus on **where code runs**, **how control transfers**, and **what objects are touched** neutralize most of the theater. Analysts who can translate “clever byte tricks” into **capabilities** (decryption, late binding, VEH redirection) decide remediation faster and build resilient detectors.

## APIs and functions

* `VirtualProtect` / `NtProtectVirtualMemory` — permission flips (W→X) that frame decrypt-then-execute stubs.
* `FlushInstructionCache` — ensures post-decrypt code actually executes; strong pairing with `VirtualProtect`.
* `VirtualAlloc` / `NtAllocateVirtualMemory` — staging buffers; provenance becomes **Private RX** after flips.
* `AddVectoredExceptionHandler` / `RemoveVectoredExceptionHandler` — VEH-driven redirection and obfuscation.
* `GetProcAddress` / `LdrGetProcedureAddress` — delayed API resolution; common with hashing.
* `RtlAddFunctionTable` — register unwind metadata for runtime code; robust engines do this, fragile loaders do not.
* `SetProcessValidCallTargets` — mark dynamic code as CFG-callable; absence can crash under CFG.
* `IsProcessorFeaturePresent(PF_SHADOW_STACK)` — rough CET availability; informs whether IBT/SS will punish odd thunks.

## Pitfalls, detection notes, and anti-analysis gotchas

* **Linear sweep trust**: linear disassembly of packed/overlapped blocks misleads; anchor on **executed** bytes.
* **Opaque predicate overconfidence**: SMT simplification can time out; use **coverage** to prune dead arms first.
* **SEH intuition on x64**: there is no linked-list SEH to corrupt; focus on VEH and unwind tables instead.
* **“No imports = stealth”**: delayed resolution still touches **PE export tables**—an easy hunting pivot.
* **CET/CFG collisions**: missing **ENDBR** or CT registration turns stealth into crash; don’t misdiagnose as “random instability.”
* **WOW64 illusions**: cross-bitness disasm uses different decoder/ABI rules; match the target bitness.
* **Data-in-code false positives**: compilers place jump tables in `.text`; validate with **use** (is it ever jumped through?).

## Cross-references

* Execution provenance, VADs, and permission changes: **Memory & Virtual Address Space** and **DEP / NX / W^X**.
* NT-layer triage and direct syscalls: **Syscalls & the NTAPI Boundary**.
* APC choreography and “early-bird” execution: **Scheduling, APCs & Callback Surfaces**.
* CFG/CET metadata requirements and behavior: **Compiler & Hardware CFI: CFG, CET (Shadow Stack/IBT)**.
* Wider evasion context (debugger checks, telemetry tamper): **Anti-Reversing & Evasion** and **Telemetry Tampering & Unhooking**.

## Glossary

* **Anti-disassembly**: Techniques that cause static decoders to misidentify or miss code.
* **Opaque predicate**: A condition constant at runtime but difficult to prove statically.
* **Control-flow flattening**: Transforming code into a dispatcher-driven state machine to hide structure.
* **Instruction overlap**: Entering execution at non-aligned/mid-instruction offsets to desynchronize decoders.
* **VEH/SEH**: Vectored/Structured exception handling—used here to redirect control via faults.
* **Packer**: A wrapper that decrypts/decompresses code at runtime, then jumps to it.
* **Virtualizer**: Translates code into custom bytecode executed by an embedded VM.
* **Private RX**: Executable, anonymous memory not backed by a mapped image; common for unpacked payloads.
* **ENDBR64**: CET landing pad required for indirect branches when IBT is enabled.
* **Jump table**: Array of code pointers used by compiled `switch`—often blended with data to confuse tools.

## Key takeaways

* Anchor on **where** code runs (Image vs Private), **when** protections change (W→X), and **how** control transfers; bytes are secondary.
* Most anti-disassembly collapses under **dynamic coverage** and **IR lifting**; spend static effort only on executed regions.
* CET/CFG and unwind metadata turn sloppy obfuscation into **crashes**—a detection ally.
* SEH/VEH tricks redirect control; on modern Windows, **VEH** and **unwind** are the real surfaces to watch.
* Import elimination hides names, not behavior; late binding and export parsing are crisp, huntable patterns.
