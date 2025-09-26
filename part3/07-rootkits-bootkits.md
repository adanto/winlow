# Part 3 – Rootkits & Bootkits

**What this chapter covers**

* Threat models and goals of kernel-mode persistence (rootkits) and pre-OS compromise (bootkits)
* Where and how attackers interpose: callback tables, object/handle mediation, filter stacks, and page-fault/time-of-use surfaces
* Secure Boot → ELAM → Code Integrity → VBS/HVCI as the modern trust chain, and how BYOVD changes the game
* Practical triage: memory provenance, invariants (lists/trees), and “what changed” diffing with WinDbg and live telemetry
* Defensive engineering patterns that survive trick decay: least-privileged brokers, deny-by-default drivers, and measured boot signals

## Core concepts

### What rootkits and bootkits try to buy

Rootkits and bootkits are not “just” stealth. They try to change the **observability graph**:

* **Where code runs:** move below user-mode hooks and EDR into kernel drivers, or earlier than the OS in the boot chain.
* **Who enforces policy:** intercept kernel events before logging/enforcement, or replace policy with their own.
* **How state is viewed:** lie to inspection by **interposition** (hook/redirect), **forgery** (fake objects), or **deletion** (unlink/neutralize).

Modern Windows raises the bar with **Secure Boot**, **Code Integrity (CI)**, **WDAC**, **VBS/HVCI**, and **PatchGuard**. The result: most viable threats today abuse **signed but vulnerable drivers** (**BYOVD**) or do **pre-OS** tampering that survives into Windows.

---

### The boot chain in three checkpoints

Understanding bootkits requires the checkpoints where trust is established:

* **UEFI Secure Boot**: firmware validates the next stage (boot manager, then OS loader) using keys and revocations (`db`, `dbx`). If a stage is revoked or tampered, boot must fail or recover.
* **ELAM (Early Launch Anti-Malware)**: first Windows driver to load; classifies early drivers (good/bad/unknown) before they initialize device stacks.
* **Code Integrity (KMCI)**: from `winload` onward, kernel enforces driver signing. **VBS/HVCI** locks code pages with EPT permissions at runtime.

A bootkit must subvert one of these (e.g., pre-boot filesystem drivers, option ROMs, UEFI DXE drivers, BCD manipulation). Post-2016 realities: **boot sectors alone** are not enough — Secure Boot changed the economics. Attacks move to **UEFI/NVRAM** or to **hardware/firmware** vendors with vulnerable update flows.

---

### Kernel attack surfaces that survive 2025

In user mode we learned to ask **handle → memory → execution**. Kernel tradecraft echoes that, with different attachment points:

* **Registration callbacks**: `PsSetCreateProcessNotifyRoutineEx`, `PsSetCreateThreadNotifyRoutine`, `PsSetLoadImageNotifyRoutine`, `CmRegisterCallbackEx`, `ObRegisterCallbacks` (handle pre-/post-operation), `KeRegisterBugCheckReasonCallback`, `FltRegisterFilter` (filesystem). Legitimate security features use them; rootkits also insert or **edit** these vectors.
* **Filter and miniport stacks**: filesystem mini-filters (FltMgr), registry callbacks, NDIS filter drivers, storage miniports. Interception here is “by design,” so you hunt **who** sits in the chain and **what** they do.
* **Dispatch tables & thunks**: SSDT and device-object `MajorFunction[]` tables (IRP handlers). PatchGuard monitors popular invariants; BYOVD drivers sometimes provide “legal” IOCTLs that reach into protected structures instead.
* **Direct Kernel Object Manipulation (DKOM)**: unlinking or falsifying kernel lists (`EPROCESS` from `PsActiveProcessHead`, handles, tokens, driver objects). PatchGuard and list hardening make naive DKOM unreliable, but **partial** DKOM (e.g., privilege mask edits) appears via BYOVD IOCTLs.
* **Timing and page faults**: lazy mapping and demand-zero pages let kernel-mode code see **first-use** of resources (e.g., code pages) and race logging.

**Analyst lens:** PatchGuard and HVCI mean overt code patching tends to crash. That pushes adversaries to **policy-adjacent** or **metadata-only** changes (permissions, tokens, callout order, call target registration) and to **signed IOCTL gadgets** from vulnerable drivers.

---

### BYOVD is the rootkit of 2025

Where “ring-0 shellcode” used to be the story, current campaigns commonly:

1. Load a **signed but vulnerable driver** (attestation-signed, expired, or revoked yet still runnable on drifted hosts),
2. Use its **IOCTLs** to read/write physical memory, arbitrary process memory, or kernel virtual memory,
3. **Patch or map** what they want once, then unload the helper.

**Why it works:** many estates allow such drivers (no blocklist, WDAC audit mode). **Why it fails under pressure:** HVCI blocks runtime **code** tampering; PPL/CI/ETW still see **effects** (handle opens, thread creations), and driver-blocklists/Smart App Control increasingly deny known-bad hashes.

*Defensive pattern:* prefer **blocklists** (known-bad driver hashes and vendors), **attestation** check + **revocation update** hygiene, and minimal allowed-driver sets through **WDAC**. Treat driver load as a **big event**; it changes the reachable state space.

---

### Hiding vs. surviving: what “stealth” means now

Rootkits historically hid by **removing themselves** from lists (driver object lists, process lists, handle tables). Today, that collides with:

* **Kernel memory scanners** (Volatility, Redline class) diffing allocation pools/trees vs. lists.
* **PatchGuard** checking critical list integrity.
* **Kernel ETW** and **object callbacks** catching the operation instead of the view.

Modern stealth looks more like **selective blindness**: make sensitive events “never occur” by **short-circuiting** before logging, or force them to occur **elsewhere** (brokered system process, filter driver). That subtlety is why **timeline + memory provenance** beats “scan for hidden module” heuristics.

---

### Forensic invariants and what to diff

Rootkits try to desynchronize **derivable truths**. Your job is to pick invariants that attackers cannot easily repair:

* **Module view vs. VADs**: does a driver have an object and a live `Mm` mapping? Are there RX pages without a driver object?
* **Object directories vs. handles**: can a name be opened from `\Driver\…` and resolved to a live object that does not appear in enumeration?
* **Process list vs. handle tables**: an “invisible” process still appears as a handle target for something (token, section, thread).
* **Filter stacks**: FltMgr knows the registry of mini-filters; a driver handling IRP\_MJ\_CREATE should also be in the altitude chain. If not, someone patched a `MajorFunction`.
* **Callback tables**: expected security products will register callbacks. A new entry at odd altitudes or from an unknown signer is suspect.

```text
; WinDbg (kernel) quick recipes (read-only triage)
!drvobj <name> 7           ; dump driver object, device objects, major function table
!process 0 1               ; list processes, watch for missing/inconsistent links
!handle 0 0                ; system-wide handle table – cross-check targets that lack listings
!stacks 2                  ; kernel stacks; look for unknown driver frames in sensitive paths
!fltFilters                ; filesystem mini-filter registration, altitudes, instances
!obtrace                   ; if enabled, object operations being traced (lab-only)
```

---

### Example (safe): enumerate loaded drivers and basic provenance

The point is to anchor on **signer and load path**, not names.

```powershell
# Driver provenance snapshot (safe)
Get-CimInstance Win32_SystemDriver |
  Sort-Object State -Descending |
  Select-Object Name, State, PathName, StartMode |
  Format-Table -Auto

# Quick signing/glance: hash and catalog have to be verified with signtool off-box for certainty
Get-ChildItem "$env:windir\System32\drivers\*.sys" |
  Get-FileHash -Algorithm SHA256 |
  Select-Object Path, Hash |
  Out-File .\driver_hashes.txt
```

Use the hash list to compare against **known-bad** blocklists off-box. In incident response, record **when** a driver loaded (Kernel-Process/ImageLoad ETW) and **what** changed soon after (new callbacks, mini-filters, registry callbacks).

---

### Example (safe): detect private RX in kernel space (conceptual)

You cannot directly walk kernel VA safely from user mode. But in a lab with kernel debugging:

```text
; WinDbg: look for executable non-image memory in kernel address ranges (signals manual map/patch)
!address -summary
!pte <suspicious_address>
!poolfind -e <pooltag>    ; if you know a tag to chase; many drivers track allocations with tags
```

The goal is not to “find the rootkit by string,” but to **prove provenance**: executable memory with **no backing image** is rare in a clean kernel.

---

### Bootkits: from MBR/VBR to UEFI and back

Legacy bootkits patched the MBR/VBR to load their stub before Windows. With **GPT** disks and **Secure Boot**, that family largely died off unless Secure Boot is **off** or **dbx** revocations are stale. Modern bootkits surface in three broad ways:

* **UEFI DXE drivers**: persist by adding or modifying a DXE driver (in SPI flash/NVRAM). They then hook boot services or chainload a kernel-mode component.
* **Boot manager/loader tampering**: patch `bootmgfw.efi` or `winload.efi` (again blocked by Secure Boot if keys/revocations are healthy).
* **Early filesystem/boot driver insertion**: malicious driver that loads before ELAM and mediates disk or registry reads; harder against CI and ELAM if signing is enforced.

**Detection/practice:** use **measured boot** (TPM PCRs) to attest to boot components remotely; verify **Secure Boot** state and revocation list freshness; dump **NVRAM** variables in incident response to look for unusual UEFI drivers.

---

### How PatchGuard and HVCI changed rootkits

* **PatchGuard**: randomizes checks that critical code/data (SSDT, IDT/GDT, MSRs, callback lists) are unmodified; on tamper, it bugchecks. Rootkits that rely on direct patching trade stealth for **instability**.
* **HVCI**: turns kernel code pages into **execute-only**, blocking write-then-execute and prohibiting **RX** changes without the hypervisor’s consent. It also constrains what can run at all if it lacks valid signatures/metadata.

**Implication:** you mostly see (a) **BYOVD data-only** attacks (tokens, privileges, ACLs), and (b) **“legal” interposition** via filter stacks and callbacks. Good news: both leave **ledger entries** you can inspect and alert on.

---

### When userspace still matters

Many campaigns keep the kernel path for **hardening only** (anti-scan, anti-dump) while **capabilities** stay in user mode (injection, C2). That split produces crisp joins:

* **Kernel driver loads → seconds later, LSASS access fails for everything except a broker** (PPL present, yet a benign process suddenly reads memory: likely a signed driver proxy).
* **ETW noise drops in a process** while **kernel ETW** still shows net/file ops: user-mode unhooking only.
* **Private RX** in a process + **new driver** that exposes “memory write” IOCTLs: BYOVD in action.

Your job is to connect **kernel events** to **user-mode behavior** and ask “what got easier” after the driver arrived.

---

### Defend with structure, not signatures

Five practical patterns consistently work:

* **Block the enablers**: WDAC in **enforce**; driver blocklists (revoked, vulnerable vendors); Smart App Control where possible.
* **Treat driver load as critical**: alert on new drivers, especially **non-Microsoft** loading outside maintenance windows; always record **hash, signer, path, altitude** (if mini-filter).
* **Protect callback surfaces**: enumerate and whitelist expected callbacks (process/thread/image/registry/OB) from your own products; alert on newcomers.
* **Leverage measured boot**: tie PCR values to **allow** decisions (e.g., only allow domain join if PCRs match a healthy baseline).
* **Prefer brokers and least privilege**: your own security components should not run as **unconstrained** kernel modules; use brokers and strict SDDL on device objects to limit who can speak to your drivers.

## Why this matters for exploitation / anti-exploit / malware analysis

Rootkits and bootkits decide who tells the truth about the system. Exploit developers must understand **how mitigations constrain kernel payloads**; otherwise post-exploit reliability collapses under PatchGuard/HVCI. Defenders must anchor on **kernel-first telemetry** (ETW providers, mini-filter registry, callback enumerations) and **boot attestation**, and treat **driver load** as a high-signal pivot in timelines. Analysts who tie **trust chain → driver posture → callback/filter graph → user-mode effects** can explain incidents clearly and recommend durable controls.

## APIs and functions

* `NtLoadDriver` / `NtUnloadDriver` — load/unload kernel drivers via Service Control Manager paths; audit attempts and results.
* `ZwQuerySystemInformation(SystemModuleInformation)` — enumerate loaded kernel modules (used by tools; treat as triage input).
* `FltRegisterFilter` / `FltStartFiltering` — filesystem mini-filter registration; legitimate and malicious filters both use it.
* `CmRegisterCallbackEx` / `CmUnRegisterCallback` — registry operation callbacks; monitor for unexpected registrants.
* `PsSetCreateProcessNotifyRoutineEx` / `PsSetLoadImageNotifyRoutine` — process/image notifications; high-value surfaces to inventory.
* `ObRegisterCallbacks` / `ObUnRegisterCallbacks` — object access mediation (e.g., protect LSASS handles); frequent target for both defense and offense.
* `DeviceIoControl` (user-mode) / `IRP_MJ_DEVICE_CONTROL` (kernel) — IOCTL path used by BYOVD to expose arbitrary read/write; alert on suspicious IOCTLs for “helper” drivers.
* `GetFirmwareEnvironmentVariable` — UEFI variable access; useful for posture checks in incident response (not for modification).

## Pitfalls, detection notes, and anti-analysis gotchas

* **Assuming SSDT hooks**: modern threats rarely patch SSDT on HVCI/PatchGuard systems; look for **callback/filter** registration and **BYOVD IOCTLs** instead.
* **“Hidden = gone” fallacy**: unlinking objects rarely survives **cross-view** diffing (lists vs. pools vs. handles). Use invariants.
* **Driver trust = signer trust**: attestation-signed ≠ safe. Maintain **blocklists**; attestation says who, not how.
* **PPL misunderstanding**: PPL stops user-mode opens, not kernel IOCTLs that read memory on behalf of a low-priv client. Broker SDDL matters.
* **Crash misattribution**: PatchGuard or CET/CFG fail-fasts look like random BSODs; collect minidumps and symbolically inspect for violated invariants.
* **Lab drift**: Secure Boot off, WDAC audit, HVCI disabled leads to fake “bypass” conclusions. Confirm posture first.
* **WOW64 blind spots**: if triaging user-mode effects, remember that x86 processes on x64 use a separate `ntdll` and driver-facing thunks.
* **UEFI sprawl**: not all “UEFI drivers” are malicious; inventory against **OEM baseline** before declaring a bootkit.

## Cross-references

* Trust anchors and runtime policy live in **Trust & Integrity: Secure Boot, WDAC/App Control, Code Integrity, PatchGuard, VBS/HVCI, PPL**.
* Memory provenance, RX vs. image-backed, and permission flips are covered in **Memory & Virtual Address Space** and **DEP / NX / W^X**.
* Hooking and interposition mechanics (CFG/CET, ENDBR, unwind) appear in **Compiler & Hardware CFI: CFG, CET (Shadow Stack/IBT)** and **Compiler & EH Hardening (/GS, SafeSEH/SEHOP history, EHCONT)**.
* IPC and broker patterns relevant to “do it elsewhere” defenses are in **IPC (ALPC, RPC, COM, Pipes)**.
* Unhooking and ETW realities (what user-mode tamper can/cannot do) are in **Telemetry Tampering & Unhooking (ETW, Direct Syscalls)**.
* Bootloader and module metadata are introduced in **Windows Loader & Image Activation**.

## Glossary

* **Rootkit**: Malware that alters OS behavior or visibility at kernel level to hide or interpose on operations.
* **Bootkit**: Malware that executes before or during OS boot to control or tamper with the trust chain.
* **BYOVD**: Bring Your Own Vulnerable Driver; use of a signed driver’s IOCTLs to perform privileged actions.
* **PatchGuard**: Windows Kernel Patch Protection that detects and crashes on critical invariant tampering.
* **HVCI**: Hypervisor-enforced Code Integrity; prevents runtime kernel code modification and enforces execution permissions.
* **Mini-filter**: Filesystem filter driver registered with FltMgr that can interpose on file I/O at a defined altitude.
* **DKOM**: Direct Kernel Object Manipulation; altering kernel structures to hide or elevate.
* **ELAM**: Early Launch Anti-Malware; first driver loaded to classify other early drivers.
* **Measured Boot**: TPM-based recording of boot component hashes into PCRs for attestation.
* **PPL**: Protected Process Light; restricts inter-process access independent of token privileges.

## Key takeaways

* Treat **driver load** as a high-signal event; it changes what is possible. Record signer, hash, path, and immediate effects.
* Hunt **graphs and invariants**, not strings: callback/filter registries, handle/object cross-views, and RX provenance expose stealth.
* Expect **BYOVD** and **policy-adjacent** tricks, not naked SSDT hooks; blocklists and WDAC enforcement blunt these quickly.
* HVCI/PatchGuard turn sloppy rootkits into **crashes**; use fail-fasts and minidumps as detectors, not annoyances.
* Bootkits target the **trust chain**; respond with **Secure Boot hygiene**, **measured boot attestation**, and **revocation updates**.
* Prefer **brokers with strict SDDL** to “big kernel” security features in your own products; the smaller your kernel footprint, the less there is to subvert.
