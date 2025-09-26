# Part 4 – Shellcoding

**What this chapter covers**

* What “shellcode” means on modern Windows and how mitigations reshape its design
* Position independence, API resolution (PEB/exports/syscalls), and x64 calling conventions
* Staged vs. stageless payloads, WOW64 concerns, and memory permission realities (DEP/ACG/CET)
* Safe lab patterns to craft, load, and debug benign shellcode without tripping protections
* How defenders recognize shellcode behavior in ETW, memory maps, and call stacks

## Core concepts

### Shellcode today

“Shellcode” is **small, position-independent code** delivered into a target process and executed without the usual loader. Historically it popped a shell; today it is any **self-sufficient routine** that runs with minimal assumptions: no imports table, no TLS, and no rich runtime. On Windows since x64 and post-mitigations, credible shellcode:

* Respects **DEP** (executes from RX pages only; often uses ROP/syscalls to obtain them).
* Handles **ASLR** by **resolving APIs at runtime** (PEB walks, export parsing, or syscalls).
* Obeys **x64 fastcall** (RCX, RDX, R8, R9; 32 bytes of shadow space; 16-byte stack alignment).
* Survives **CFG/CET/ACG** by choosing valid call targets and avoiding forbidden transitions.

Your design constraint set is: **PIC + ABI-correct + policy-aware**.

---

### Memory, permissions, and where shellcode lives

You rarely start in an RX page. Common routes:

* **ROP/JOP chain** flips a region’s protection (`NtProtectVirtualMemory`) and jumps into it.
* A host (exploit harness, fuzzer, loader) allocates RX (`VirtualAlloc` with `PAGE_EXECUTE_READWRITE` in the lab).
* **JIT-like** hosts yield RX natively (managed runtimes, `Add-Type`, etc.), though **ACG** can disallow writing to RX afterward.

For defenders, a characteristic signature is a **W→X** or **X→RW** change followed by a control transfer into a **private** region.

---

### Position independence and API resolution

Shellcode can’t rely on an IAT. It typically resolves APIs by:

* **PEB walk**: read `GS:[0x60]` (TEB) → PEB → loader lists → bases of `kernel32.dll`/`kernelbase.dll`/`ntdll.dll`.
* **Export directory** scan: hash function names, then parse `IMAGE_EXPORT_DIRECTORY` to find `GetProcAddress`/`LoadLibraryA` or direct targets.
* **Syscall stubs**: call `ntdll!Nt*` by address (still requires knowing `ntdll` base). Direct syscalls change less often than exports but are build-specific.

Minimalism matters: resolve **as few** entry points as needed, and do so **once**.

---

### x64 ABI essentials for shellcode

Windows x64 uses **fastcall**:

* RCX, RDX, R8, R9 carry the first four integer/pointer args; extras spill to stack.
* The caller must reserve **32 bytes of “shadow space”** on the stack for callees.
* Stack must be **16-byte aligned** at call sites.
* **Non-volatile registers** (RBX, RBP, RDI, RSI, R12–R15) must be preserved if clobbered.

Failing any of these yields weird crashes blamed on “EDR” or “randomness” when it’s just ABI.

---

### Staged vs. stageless, and “what’s inside”

* **Stageless**: everything is inside the first blob; good for lab demos and constrained environments.
* **Staged**: tiny stage resolves APIs and **fetches next bytes** (from disk, resource, or memory). Staging reduces initial size and diffuses indicators but adds network/IO and more telemetry.
* **Behavior**: benign shellcode proves reach (e.g., `MessageBoxW`, `Beep`, writing a file). Real tradecraft usually **adjusts privileges, opens handles, or sets up an IPC/control loop**—all of which are visible to ETW/object callbacks.

---

### WOW64 nuances

x86 shellcode inside a 64-bit OS runs under **WOW64** with a different `ntdll` and calling convention. If you need **kernel** services:

* Either **stay x86** and call 32-bit `ntdll` stubs, or
* **Heaven’s Gate**–style transitions invoke 64-bit stubs from 32-bit code (rare today and fragile).
* Remember SEH differences and limited address space for the 32-bit view.

Prefer writing native x64 shellcode unless the process is truly 32-bit.

---

### Encoders and constraints

Transport can forbid **NULs**, CR/LF, or non-alphanumeric bytes. Encoders (XOR/add/ROL) rewrite bytes and **decode at runtime**. Under CET/CFG, place **decoders** carefully: you still need ABI-compliant calls and valid indirect entries if you call out. Decoders must also keep stack aligned and restore registers they trash.

---

### Debugging shellcode without pain

* **Start in an RX page**: mark it RX in the harness, not via ROP, to isolate ABI and logic before adding mitigations.
* **WinDbg**: set a breakpoint at the entry; single-step to the first external call; check alignment and shadow space.
* **ETW**: enable kernel Process/ImageLoad/FileIO to verify effects (file writes, image loads) even if user-mode logging is quiet.
* **Guard pages**: surround the buffer with no-access pages to catch overruns.

---

## Example-first, then explain

```c
// Lab-only x64 loader that executes a benign, PIC shellcode buffer.
// cl /W4 /EHsc shell_stub.c
#include <windows.h>
#include <stdio.h>

static unsigned char sc[] = {
  /* placeholder for a benign shellcode that calls MessageBeep(OK) and returns.
     We'll JIT-build it at runtime to avoid encoding pitfalls. */
};

typedef BOOL (WINAPI *PFN_VirtualProtect)(LPVOID,SIZE_T,DWORD,PDWORD);

int main() {
    SYSTEM_INFO si; GetSystemInfo(&si);
    SIZE_T sz = 4096;
    void* buf = VirtualAlloc(NULL, sz, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!buf) return 1;

    // generate a tiny position-independent thunk in-place (simplified)
    // mov rcx, 0x00000030 ; MB_OK
    // sub rsp, 0x28       ; align + shadow
    // call qword ptr [rip+imm32] ; &MessageBeep resolved via IAT in our process
    // add rsp, 0x28
    // ret
    unsigned char thunk[] = {
      0x48,0xC7,0xC1,0x30,0x00,0x00,0x00,
      0x48,0x83,0xEC,0x28,
      0xFF,0x15,0x00,0x00,0x00,0x00,
      0x48,0x83,0xC4,0x28,
      0xC3
    };
    memcpy(buf, thunk, sizeof(thunk));

    // Patch RIP-relative import slot with &MessageBeepW (valid CFG/IBT target)
    FARPROC p = GetProcAddress(GetModuleHandleW(L"user32.dll"), "MessageBeep");
    *(void**)((unsigned char*)buf + sizeof(thunk)) = (void*)p;

    DWORD old = 0;
    VirtualProtect(buf, sz, PAGE_EXECUTE_READ, &old);
    printf("Executing benign shellcode at %p\n", buf);
    ((void(*)(void))buf)();
    VirtualFree(buf, 0, MEM_RELEASE);
    return 0;
}
```

*What this shows:*

* **Shadow space** + alignment (`sub/add rsp, 0x28`) around the call.
* A **valid** indirect call target under CFG/IBT (real `MessageBeep` prologue).
* **PIC** via RIP-relative addressing of the call target (we fill the slot at runtime).

This is deliberately simple: no PEB walk, no export hashing, just the ABI discipline your shellcode must obey even when it becomes more dynamic.

---

```text
; WinDbg checklist while single-stepping shellcode
u @rip-10              ; confirm you're at your entry (no mid-instruction landings)
r                      ; inspect RCX,RDX,R8,R9 and RSP alignment (RSP % 16 == 0 at call)
db @rsp L40            ; verify 32 bytes of shadow space are reserved
pt                     ; step over the call to see return behavior (CET shadow stack ok?)
!address @rip          ; ensure region is RX and private (VAD provenance)
```

*Goal:* catch **ABI** mistakes first; they masquerade as “anti-debug” or “EDR interference” but are just alignment or shadow-space failures.

---

```powershell
# Lab-only: observe effects rather than strings. Start kernel ETW for quick proof-of-behavior.
# Run elevated in a disposable VM; stops after a short window.
$session = 'ShellcodeKernelTrace'
logman start $session -p "Microsoft-Windows-Kernel-Process" 0x10 0x5 -p "Microsoft-Windows-Kernel-Image" 0xffffffffffffffff 0x5 -ets
Start-Sleep -Seconds 5
# ...run your lab sample here...
Start-Sleep -Seconds 5
logman stop $session -ets
wevtutil qe "Microsoft-Windows-Kernel-Process/Operational" /c:20 /rd:true /f:text
```

*Why:* ETW shows **effects** (image loads, process starts) even if user-mode hooks are unhooked or bypassed. A benign demo should show **no** suspicious process spawns—just your process calling `user32!MessageBeep`.

---

## Design patterns you will actually use

### PEB walk + export hashing (one-time resolver)

1. `ntdll` base via PEB → loader list.
2. Get `kernel32` or `kernelbase` base the same way.
3. Parse export directory to compute hash(name) == target hash for `LoadLibraryA/GetProcAddress`.
4. Resolve everything else by name (or continue hashing to stay string-free).

**Tips:**

* Keep the resolver **idempotent** (run once; cache pointers).
* Use **case-insensitive** hashing and avoid path separators (DLL base names only).
* Under **ACG**, you can still call into existing exports; it’s **creating new RX** that’s forbidden.

### Syscaller style (no Win32)

Skip `kernel32` entirely: resolve `ntdll` only and call `Nt*` you need. That reduces surface (and some hooks), but:

* You still must **marshal arguments** correctly and handle `OBJ_CASE_INSENSITIVE`, Unicode paths, etc.
* **WOW64** requires the 32-bit or 64-bit right stubs; do not mix.
* **Telemetry** still sees the **effects** (files/handles/threads) even if no Win32 wrapper runs.

### Stagers that behave

If staging, make stage 1 do **exactly** three things: resolve APIs, allocate a buffer, fetch stage 2, then **return**. Do not leave altered thread contexts, FPU state, or random handles open. Re-using the current thread is quieter than creating a new one; if you must, use `QueueUserAPC` into yourself rather than `CreateThread` from nowhere.

---

## Why this matters for exploitation / anti-exploit / malware analysis

Exploitation becomes “real” when control lands in **code you brought**. Shellcode is that code. On hardened Windows, shellcode that **obeys ABI and policy** is rare in commodity malware—making such discipline a differentiator in triage. For defenders, these routines leave **clear footprints**: permission flips, short bursts of API resolution, and sensitive syscalls without module loads. For exploit developers, knowing **where** shellcode fails (alignment, invalid entry, CET/CFG) saves days of “it works on my VM” confusion.

## APIs and functions

* `VirtualAlloc` / `VirtualProtect` — lab allocation/protection flips; in real incidents, correlate with private RX execution.
* `LoadLibraryA/W` / `GetProcAddress` — classic resolver targets after PEB/export walk.
* `NtProtectVirtualMemory` / `NtAllocateVirtualMemory` — syscall path for protection/alloc (fewer user-mode hooks).
* `QueueUserAPC` / `NtCreateThreadEx` — control transfer primitives; noisy in telemetry if misused.
* `IsProcessorFeaturePresent(PF_SHADOW_STACK | PF_IBT_SUPPORTED)` — discover CET at runtime; plan valid call entries accordingly.
* `RtlLookupFunctionEntry` / `RtlVirtualUnwind` — helpful when your shellcode must unwind safely (exception-prone hosts).
* `GetModuleHandleW` — fallback if you already *are* in a module-rich process (not pure shellcode, but pragmatically useful).

## Pitfalls, detection notes, and anti-analysis gotchas

* **Stack misalignment**: most mysterious crashes at API boundary are 16-byte misalignment or missing **shadow space**.
* **Invalid indirect entry**: **IBT** requires `ENDBR64`; jumping mid-function faults even if the address “works” on non-CET hosts.
* **CFG**: indirect calls to non-registered stubs are blocked; prefer returns into **real function prologues** or direct syscalls via valid thunks.
* **ACG walls**: creating/modifying RX is blocked; do not plan on RWX. Use syscalls and existing RX.
* **WOW64 mismatches**: 32-bit shellcode calling 64-bit stubs (or vice versa) yields confusing faults; keep the world consistent.
* **Resolver noise**: repeated export parsing every call is a tell; resolve **once**, cache, and continue.
* **Thread creation spam**: many small stages spawning threads raise obvious ETW flags; stay on the current thread when possible.
* **Decoder crashes**: self-modifying decoders collide with **CET** and **ACG**; keep decoders in RW, call out via valid entries, then jump into RX.

## Cross-references

* For getting control in the first place: **Buffer Overflows** and **Use-After-Free & Type Confusion**.
* For building the “permission flip” or syscall trampoline: **ROP & JOP** and **DEP / NX / W^X**.
* For why your indirect call dies on modern builds: **Compiler & Hardware CFI: CFG, CET (Shadow Stack/IBT)**.
* For how shellcode effects appear in logs: **Windows Eventing & ETW Playbook** and **Telemetry Tampering & Unhooking (ETW, Direct Syscalls)**.
* For loader semantics (what you don’t get in shellcode): **Windows Loader & Image Activation**.

## Glossary

* **Shellcode**: small, position-independent routine executed without a loader or imports.
* **PIC (Position-Independent Code)**: code that runs correctly regardless of its base address.
* **PEB walk**: locating module bases by traversing the Process Environment Block loader lists.
* **Export hashing**: resolving functions by hashing export names to avoid storing strings.
* **Shadow space**: 32 bytes the caller reserves on x64 Windows for callees.
* **ACG (Arbitrary Code Guard)**: policy restricting creation/modification of executable memory.
* **CET (IBT/Shadow Stack)**: hardware protections enforcing valid indirect entries and return integrity.
* **Stager**: initial small payload that fetches/installs a larger second stage.
* **WOW64**: subsystem that runs 32-bit code on 64-bit Windows.
* **Syscaller**: tiny routine invoking `Nt*` system calls directly from user mode.

## Key takeaways

* Modern shellcode is **ABI-disciplined, policy-aware PIC**: obey x64 calling rules, use valid call targets, and avoid creating RWX.
* Resolve **as few APIs as possible**, **once**, via PEB/export parsing or syscalls, then cache and reuse.
* Prefer **existing RX** and **syscall paths**; if you must flip protections, do so minimally and land in a stable continuation.
* Debug with **alignment and shadow space** front-of-mind; most “anti-debug” crashes are ABI mistakes.
* Defenders should anchor on **permission flips, private RX execution, and sensitive syscalls without new modules**—these expose shellcode even when strings and imports do not.
