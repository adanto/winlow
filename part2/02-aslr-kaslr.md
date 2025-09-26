# Part 2 – Exploitation Mitigations: ASLR / KASLR

**What this chapter covers**

* How Windows randomizes user-mode and kernel-mode address spaces (executables, DLLs, drivers)
* Entropy sources: bottom-up ASLR, image relocation, high-entropy VA, per-boot kernel slides
* Practical effects on exploitation and evasion, and how analysts verify ASLR posture
* Typical bypasses: info leaks, non-ASLR modules, JIT/loader side channels, memory reuse
* Minimal examples to read ASLR settings and observe randomized bases

## Core concepts

### What ASLR/KASLR actually randomize

**ASLR** randomizes where **images** (EXEs/DLLs) and heaps/stacks/allocations land in a process. The loader maps an image to a base that (usually) differs from its preferred base, then applies **relocations**; this spreads gadgets and makes hard-coded addresses unreliable. **KASLR** does the same for the **kernel image** and **drivers**: a **per-boot slide** picks new bases that hold until reboot. On 64-bit Windows, **HighEntropyVA** extends user-mode entropy beyond classic 8–12 bits.

Two practical constraints help performance and sharing:

* System DLLs often land at the **same base across processes** in a given boot so the RX pages can be shared; the base itself still changes across boots.
* The **kernel slide** is **system-wide per boot**; all drivers/ntoskrnl are consistently offset until reboot.

### Where the randomness comes from

* **Image relocation slide**: per mapping; bounded by alignment and loader policy.
* **Bottom-up ASLR**: randomized base for `VirtualAlloc` regions; complicates heap and shellcode placement.
* **High-entropy VA**: enables randomness across a much larger 64-bit range.
* **KASLR slide**: selected early in boot; applies to the kernel and loaded drivers.

```c
// Print base addresses of a few loaded modules to see ASLR at work (x64; error checks omitted)
#include <windows.h>
#include <psapi.h>
#include <stdio.h>

int main() {
    HMODULE mods[256]; DWORD needed=0;
    EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed);
    DWORD count = needed / sizeof(HMODULE);
    for (DWORD i=0; i<count && i<10; i++) {
        wchar_t name[MAX_PATH]; MODULEINFO mi={0};
        GetModuleFileNameExW(GetCurrentProcess(), mods[i], name, MAX_PATH);
        GetModuleInformation(GetCurrentProcess(), mods[i], &mi, sizeof(mi));
        wprintf(L"%p  %s\n", mi.lpBaseOfDll, name);
    }
    return 0;
}
```

**Analyst note:** run the snippet twice (or on different boots) to see base movement; DLL bases will typically be identical across processes within the same boot, but differ after a reboot.

### Image flags and process policy that affect layout

* **`DllCharacteristics.DynamicBase`**: allows relocation (ASLR).
* **`HighEntropyVA`**: enables wider 64-bit entropy.
* **Mitigation policy**: `ProcessDynamicCodePolicy` and related flags do not change ASLR directly but influence how/where executable memory can appear (important for spray/ROP staging).
* **/DYNAMICBASE** and **/HIGHENTROPYVA** (linker): compile-time switches you’ll audit in binaries.

```powershell
# Read a process's mitigation posture and quick-check HighEntropyVA support (PowerShell)
$pid = (Get-Process | ? {$_.MainWindowTitle} | Select -First 1).Id
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Mit {
 [StructLayout(LayoutKind.Sequential)] public struct PROCESS_MITIGATION_ASLR_POLICY { public uint Flags; }
 [DllImport("kernel32.dll")] public static extern bool GetProcessMitigationPolicy(IntPtr h, int pol, out PROCESS_MITIGATION_ASLR_POLICY p, int len);
}
"@
$h = (Get-Process -Id $pid).Handle
$p = New-Object Mit+PROCESS_MITIGATION_ASLR_POLICY
[void][Mit]::GetProcessMitigationPolicy($h, 3, [ref]$p, [System.Runtime.InteropServices.Marshal]::SizeOf($p))
"{0}: ASLR flags=0x{1:X}" -f $pid, $p.Flags
```

**Quick read:** the ASLR policy exposes bits like bottom-up randomization and high-entropy VA enablement from the OS point of view.

### Kernel layout: KASLR and drivers

The kernel’s **system-wide slide** randomizes `ntoskrnl.exe` and drivers. Drivers are relocated by the same slide (plus their own alignment), so gadget addresses from one box rarely transfer to another without an info leak. Within one boot, kernel addresses remain stable (useful for defenders correlating telemetry; problematic if an attacker finds any reliable leak).

**Practical implication:** kernel exploits nearly always begin with an **info leak**—a way to learn a kernel pointer (object address, function pointer, PTE address) and thus the slide.

### What ASLR does *not* protect

* **Logic bugs**: if you can call a dangerous function, ASLR doesn’t help.
* **Non-ASLR modules**: any image without `DynamicBase` defeats layout diversity for its code/data.
* **Disclosures**: once you leak one code pointer, the whole module layout (and often the process) becomes predictable.
* **JIT regions**: JITs emit code in RX regions whose addresses can be learned via side channels.

### Typical bypass strategies you’ll see

* **Info-leak first**: read an IAT pointer, vtable, or exception record to learn a module base, then compute gadget addresses.
* **“ASLR oracle”**: measure `LoadLibrary`/`GetProcAddress` behaviors or error messages to infer presence/absence and sometimes base of a module.
* **Aim for non-ASLR gadgets**: older plug-ins/third-party DLLs compiled without `/DYNAMICBASE` (rarer today, still worth checking).
* **Heap sprays + partial overwrites**: align payloads so that partial pointer control lands inside your sprayed region despite randomness.
* **In kernel**: disclose the slide with side channels (timing in GDI/handle tables, driver info queries), then ROP.

### What defenders verify

* **Every binary** in the estate built with `/DYNAMICBASE` and `/HIGHENTROPYVA` (for 64-bit).
* **No legacy non-ASLR modules** loaded into high-value processes (browsers, Office, script hosts).
* **ETW joins** of `ImageLoad` with compile flags and signer; isolate outliers.
* **Kernel**: ensure the OS is new enough to restrict unauthenticated kernel pointer disclosures, and watch for **user-mode leaks** (e.g., logs, crashes that include pointers).

```text
; WinDbg quick kernel/user checks
lm k               ; list kernel modules (observe randomized bases compared to symbol addresses)
!drvobj <name> 2   ; driver object layout (avoid printing raw pointers in screenshots/reports)
lm                 ; user modules with base addresses; compare across boots
```

**Hygiene tip:** never paste live kernel pointers into tickets; treat them as sensitive.

## Why this matters for exploitation / anti-exploit / malware analysis

ASLR/KASLR push attackers toward **info-leak + ROP/JOP** or toward **abusing JIT/loader behaviors**. That means **sequence** and **context** are king for detection: a suspicious **memory disclosure** followed by **image enumeration** followed by **indirect call chains** tells the story. Analysts who can **prove** that a non-ASLR module was present, or that a kernel pointer leaked, can explain why an exploit “suddenly became reliable.”

## APIs and functions

* `GetProcessMitigationPolicy` – read ASLR/high-entropy/bottom-up flags in a target process.
* `VirtualQueryEx` – enumerate regions; find image vs. private RX and spot predictable layouts.
* `GetModuleInformation` / `EnumProcessModules` – list modules and bases; confirm per-boot stability or drift.
* `NtQuerySystemInformation` (SystemModuleInformation) – enumerate kernel modules (privilege-sensitive; leaks restricted on modern builds).
* `GetProcessDEPPolicy` – not ASLR, but often audited alongside; confirms broader mitigation posture.
* `RtlPcToFileHeader` – compute containing module given a code pointer; useful in tooling for base derivation.
* `SetProcessMitigationPolicy` – enable ASLR-related process mitigations (where configurable).
* `LoadLibraryExW` – combine with `GetProcAddress` for controlled probes (and for tests of module presence).

## Pitfalls, detection notes, and anti-analysis gotchas

* **“ASLR is off” misreads:** a module with a **stable base** across processes in the same boot may still be ASLR-enabled; check the PE flags, not just the address.
* **Symbol leakage in logs/dumps:** user crash handlers and verbose logging that print `%p` undo your entropy; sanitize.
* **WOW64 skew:** 32-bit processes may have different entropy characteristics; match bitness when measuring.
* **JIT noise:** frequent RX allocations at fresh bases are normal for browsers/CLR—join with **unwind registration** and JIT DLLs to avoid false positives.
* **Kernel ETW limits:** some providers redact pointers; lack of pointers in telemetry is not proof that KASLR is intact—combine with memory forensics when needed.
* **Pinned images:** images loaded at preferred base (no relocation needed) are not “ASLR-off”; it’s just luck—validate `DynamicBase`.
* **Debugger side effects:** breakpoints and hot-patching can create RX stubs that look like manual maps; attribute to module owner before calling it a bypass.

## Cross-references

* DEP/NX and **W^X** constraints that pair with ASLR are in **Part 2 – Exploitation Mitigations: DEP / NX / W^X**.
* Provenance of RX memory (Image vs. Private) and VAD inspection live in **Memory & Virtual Address Space** (Part 1).
* Loader behavior (relocations, `DllCharacteristics`, KnownDLLs) is covered in **Windows Loader & Image Activation** (Part 1).
* ROP/JOP planning, info-leaks, and exploit chains appear in **ROP & JOP** and **Buffer Overflows** (Part 4).
* Kernel primitives, pointer protections, and KASLR interactions continue in **Kernel Exploitation Primer** (Part 4).
* Telemetry joins (ImageLoad, VirtualProtect, module flags) are described in **Windows Eventing & ETW Playbook** (Part 5).

## Glossary

* **ASLR**: Randomization of user-mode address layouts (images, heaps, stacks) to break hard-coded addresses.
* **KASLR**: Per-boot randomization of kernel and driver bases.
* **HighEntropyVA**: 64-bit enhancement expanding ASLR randomness range.
* **Bottom-up ASLR**: Randomized base for anonymous allocations (`VirtualAlloc`), complicating heap layouts.
* **DynamicBase**: PE flag indicating an image supports relocation for ASLR.
* **Relocation**: Fix-ups applied when an image cannot map at its preferred base.
* **Info leak**: Primitive that reveals pointers/addresses, collapsing ASLR.
* **Slide**: The offset applied to a module/kernel from its preferred base.
* **Oracle**: Side channel that reveals the presence/layout of modules without direct disclosure.
* **WOW64**: 32-bit-on-64-bit subsystem with distinct layout characteristics.

## Key takeaways

* Treat ASLR/KASLR as **entropy you must protect**: eliminate non-ASLR modules and pointer leaks first.
* Verify **flags, not folklore**: `DynamicBase`/`HighEntropyVA` and mitigation policy tell you the truth; a stable base within one boot doesn’t mean ASLR is off.
* Bypass patterns are **disclose → compute → ROP/JOP** or **abuse JIT/loader**; design detection around that sequence.
* For kernel work, **one leak = full predictability** until reboot—guard kernel pointers in telemetry and crash paths.
* Always analyze addresses with **provenance** (Image/Private, module signer) and **time** (per-process, per-boot) to keep signals clean.
