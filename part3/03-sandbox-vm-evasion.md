# Part 3 – Sandbox & VM Evasion

**What this chapter covers**

* The goals and economics of sandbox/VM evasion and what evasion *actually* proves
* Environment, capability, and timing checks that differentiate lab VMs from real endpoints
* Brokered-execution and “do work elsewhere” patterns that sidestep instrumentation
* Practical triage for defenders: join signals (policy, hardware, identity, timing) rather than chasing one-off tricks
* Minimal examples that show shape, not weaponization

## Core concepts

### Threat model: evade *who*, not just *where*

“Sandbox & VM evasion” tries to avoid controlled analysis environments: automated detonation sandboxes, analyst VMs, or tightly instrumented hosts. Evasion rarely proves a machine is “safe”—only that **a subset of tells are absent**. Mature malware layers **three classes** of checks:

* **Environment** (hardware/firmware): CPU features, memory/cores, device/BIOS strings, drivers, session type.
* **Capability** (policy/identity): token privileges, PPL/WDAC posture, AppContainer/IL, EDR user-mode modules.
* **Economics/time**: long sleeps, staged downloads, human-interaction gates (mouse entropy/clipboard use), randomized backoff.

Attackers then **gate payload delivery** (don’t run) or **offload work** (brokered execution, LOLBins). Defenders win by correlating **multiple weak signals** and focusing on **capability graphs** (who could do what), not single artifacts.

---

### Environment probes: hardware and firmware tells

Cheap signals often stack: a VM may expose fewer cores, specific device vendors, or hypervisor CPUID leaves.

```c
// Shape-only: basic VM-ish signals (no single item is decisive)
#include <windows.h>
#include <intrin.h>
#include <stdio.h>

int main() {
    SYSTEM_INFO si; GetSystemInfo(&si);
    printf("Logical processors: %lu\n", si.dwNumberOfProcessors);

    int regs[4]; __cpuid(regs, 0x40000000);  // hypervisor vendor leaf
    char hv[13]={0}; *(int*)&hv[0]=regs[1]; *(int*)&hv[4]=regs[2]; *(int*)&hv[8]=regs[3];
    printf("Hypervisor vendor (if any): %s\n", hv[0]?hv:"<none>");

    MEMORYSTATUSEX ms = { sizeof(ms) }; GlobalMemoryStatusEx(&ms);
    printf("RAM (GB): %.1f\n", ms.ullTotalPhys/ (1024.0*1024*1024));

    DWORD len=0; GetFirmwareEnvironmentVariableW(L"SecureBoot", L"{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}", NULL, 0);
    printf("SecureBoot var read status: %lu\n", GetLastError()); // presence/ACLs differ by estate
    return 0;
}
```

**How attackers use it:** “Proceed iff ≥ 4 cores, ≥ 8 GB RAM, no known hypervisor vendor string.”
**Defender stance:** every criterion has legitimate failures (VDI, laptops). Treat *combinations* as signal, not singletons.

---

### Capability probes: tokens, policies, sensors

Sandboxed processes often run with **constrained tokens** (low IL/AppContainer), and analysis VMs may run **test-signed** or **audit-only** policies.

* **Token/IL**: `OpenProcessToken` + `GetTokenInformation` (groups, privileges), `GetTokenInformation(TokenIntegrityLevel)`.
* **PPL/WDAC/VBS** posture: PPL targets present? WDAC enforced or audit? HVCI running? (See mitigations chapters.)
* **EDR presence**: module names in process, registered ETW sessions, loaded kernel callbacks (indirect signals via failures).

```powershell
# Shape-only: quick policy posture many sandboxes gloss over
Get-CimInstance Win32_DeviceGuard |
  Select SecurityServicesRunning, VirtualizationBasedSecurityStatus
Get-WinEvent -LogName "Microsoft-Windows-CodeIntegrity/Operational" -MaxEvents 5 |
  Select TimeCreated, Id
```

**Attacker read:** “If WDAC is Enforce + PPL-Lsa present, delay and offload credential work.”
**Defender read:** “A sample that *only* runs when WDAC is Audit is tuning for your lab—flip to Enforce in a canary ring.”

---

### Economics & timing: outwait and out-noise

Automated sandboxes value **speed**. Malware increases **time-to-signal**:

* **Sleep jitter**: randomized, exponential backoff, time dilation checks (QPC deltas deviating under single-step).
* **Human gates**: cursor entropy over minutes, clipboard/IME activity, file-open dialogs.
* **Staged triggers**: large downloads, multi-process orchestration, or requiring a reboot.

```c
// Timing dilation probe (benign): detect breakpoint/slow emulation
#include <windows.h>
#include <stdio.h>
int main(){
    LARGE_INTEGER a,b,f; QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&a);
    Sleep(200); // a sandbox or debugger can stretch this
    QueryPerformanceCounter(&b);
    double ms = (b.QuadPart-a.QuadPart)*1000.0/f.QuadPart;
    printf("Slept ~%.1f ms\n", ms);
}
```

**Analyst note:** debuggers alter timing; capture ETW alongside to avoid “proving” claims the sample manipulates.

---

### Brokered execution: move work to a cleaner lineage

Rather than executing sensitive actions directly, malware **asks** a **broker** (already-allowed process or system component) to do it, often via **IPC** (ALPC/RPC/COM/Named Pipes). This reduces telemetry in the original process and inherits **better tokens**.

* **Examples**: use a COM object for file writes outside sandbox profile; ask a service via named pipe to spawn a helper; drive a browser’s headless component to fetch payloads.
* **Tell**: low-priv proc creates a **client connection** to a high-priv service and immediately sensitive I/O occurs **from the service**, not the client.

**Defender play:** trace **endpoint → server process → effective token → action** (see IPC chapter). Evasion collapses if the broker enforces **capability allow-lists** (AppContainer caps, SDDL).

---

### Off-host and LOLBins: “someone else does the noisy part”

Detonations often confine outbound traffic and tools; malware uses **LOLbins** (signed utilities) or pushes work to **remote endpoints**:

* **`rundll32`, `mshta`, `powershell`, `wmi`**: execute inline logic; sandbox may allow them by design.
* **Dropper only**: the first-stage does nothing interesting without a second-stage from C2.
* **Cloud pivot**: abuse OneDrive/SharePoint/Teams API—as long as tokens exist—to pull payloads (labs rarely simulate).

**Analyst play:** if the sample “does nothing,” check **failed network** with realistic **auth context**; RATs park silently without valid tokens.

---

### Image/loader shyness: detect lab hooks, then manual-map

Analysis agents hook `kernel32/ntdll` to intercept. Evasive code inspects export addresses for **trampolines**, validates `ntdll` bytes, or calls **direct syscalls**. If hooks are present, it **manual-maps** its next stage to avoid import resolution audits.

* **Tell**: early `ReadProcessMemory`/checksum of `ntdll`, unusual **syscall** stubs, **RX Private** execution, no `PEB->Ldr` record.
* **Mitigations** bite: CFG/CET/WDAC turn sloppy manual maps into crashes or load failures (missing ENDBR/CT/unwind data).

---

### “Don’t look here”: tamper-with-telemetry

User-mode attempts (patching `EtwEventWrite`, AMSI bypass in script hosts) are common; they **do not** stop **kernel ETW** or **driver** telemetry.

* **Tell**: a process’s ETW goes quiet while it still creates threads, flips W→X, or opens handles.
* **Analyst play**: probe with **expected** noise (e.g., force file I/O) and see if it appears; if not, correlate with **recent memory writes** to ETW/AMSI stubs.

---

## Why this matters for exploitation / anti-exploit / malware analysis

Exploit payloads and loaders frequently add **evasion layers** to avoid detonating in analysis and to select **only** high-value hosts. As a defender, you must separate **capability** from **theater**: a dozen VM tells are meaningless if the sample then performs **no sensitive action**. For exploit reliability, sandbox artifacts (debuggers, slow timers, unusual scheduling) change the timing of **APCs**, **heap**, and **JIT**—understanding these lets you reproduce or neutralize “works only on bare metal” bugs.

## APIs and functions

* `GetSystemInfo` / `GlobalMemoryStatusEx` — coarse resource probes (cores/RAM) used for environment gating.
* `IsProcessorFeaturePresent` / `__cpuid` — CPU/hypervisor feature and vendor detection.
* `OpenProcessToken` / `GetTokenInformation` — token/IL/privilege checks to detect sandboxes and decide on capability use.
* `QueryPerformanceCounter` / `Sleep`/`WaitFor*` — timing gates and dilation checks.
* `NtQuerySystemInformation(SystemCodeIntegrityInformation)` — CI/WDAC posture hints (combined with event logs).
* `CreateFile`/`DeviceIoControl` on known devices — presence of virtual hardware (e.g., vendor PCI/ACPI IDs).
* `LdrLoadDll` / `GetProcAddress` (with hashing) — delayed import resolution after hook checks.
* `NtAllocateVirtualMemory` / `NtProtectVirtualMemory` — RW→RX transitions that follow packers/manual maps (pair with provenance).

## Pitfalls, detection notes, and anti-analysis gotchas

* **Single-signal traps:** one VM tell is not proof. Real endpoints (VDI, kiosks) also look “VM-like.” Stack diverse signals.
* **Debugger observer effect:** stepping and breakpoints stretch sleeps and reorder APC delivery; always capture **ETW** alongside.
* **Policy misreads:** WDAC/CI **Audit** is not Enforce; many “bypasses” are configuration artifacts in labs.
* **Hook tunnel vision:** direct syscalls still generate **kernel** telemetry; user-mode hooks are not your source of truth.
* **Manual-map fragility:** without **unwind/CFG/ENDBR**, evasive loaders crash on modern builds—don’t mistake this for “random instability.”
* **Token confusion:** PPL and AppContainer change who may perform actions; a low-priv process failing to read LSASS is expected, not evasion.
* **Network blinders:** detonation labs often block auth; payloads that “do nothing” may be waiting for real **tokens** and routes.

## Cross-references

* Timing and queued execution surfaces: **Scheduling, APCs & Callback Surfaces**.
* Loader behavior, manual mapping, and metadata: **Windows Loader & Image Activation**.
* Memory provenance and W→X detection: **Memory & Virtual Address Space** and **DEP / NX / W^X**.
* NT-layer truth and direct syscalls: **Syscalls & the NTAPI Boundary**.
* Telemetry tamper and ETW realities: **Telemetry Tampering & Unhooking (ETW, Direct Syscalls)**.
* Broker abuse and IPC security: **IPC (ALPC, RPC, COM, Pipes)**.
* Mitigations that break sloppy evasions (CFG/CET/WDAC/PPL): **Part 2** chapters.

## Glossary

* **VM tell**: Observable artifact that hints at virtualization (device IDs, CPUID vendor, low resources).
* **Capability gate**: Conditional that enables payload only when identity/policy meets thresholds.
* **Brokered execution**: Performing actions via higher-privileged services over IPC.
* **Manual mapping**: Loading code without the OS loader’s bookkeeping (no PEB/Ldr record).
* **W→X transition**: Changing memory from writable to executable—typical after unpacking/JIT.
* **Direct syscall**: Issuing `syscall` from custom stubs to bypass user-mode hooks.
* **PPL**: Protected Process Light—policy that restricts inter-process access independent of tokens.
* **Audit vs Enforce (WDAC)**: Logging-only vs deny-by-default policy decision modes.
* **Time dilation**: Breakpoints/emulation stretch measured execution time, revealing analysis.
* **LOLbins**: Signed Windows binaries repurposed to run attacker logic.

## Key takeaways

* Treat evasion as **risk scoring**, not truth: combine environment, capability, and timing before concluding “real host.”
* Anchor analysis in **capability graphs** (who did what, using which token/policy), not single VM artifacts.
* RW→RX plus **Private RX execution** is a stronger indicator than any number of API hashes.
* Kernel/ETW vantage outlives user-mode tampering and direct-syscall games—collect it by default.
* Most fragile evasions collapse under modern mitigations and proper policies; use those failures to your advantage in triage.
