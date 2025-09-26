# Part 2 – Exploitation Mitigations: Trust & Integrity: Secure Boot, WDAC/App Control, Code Integrity, PatchGuard, VBS/HVCI, PPL

**What this chapter covers**

* The trust chains that decide what code may run: UEFI Secure Boot → Code Integrity → WDAC/App Control
* Virtualization-Based Security (VBS) and Hypervisor-enforced Code Integrity (HVCI) as modern enforcement layers
* Protected Process Light (PPL) and why “signed” is not the same as “allowed to interact”
* PatchGuard’s role in keeping the kernel honest and the common anti-forensic failure modes
* Practical posture checks and the signals analysts use to separate configuration drift from compromise

## Core concepts

### Secure Boot: root of trust for early boot

**UEFI Secure Boot** verifies that each stage of the boot chain is signed by a trusted authority before it executes: firmware → boot manager → OS loader → kernel. Trust is expressed with UEFI variables (`db`, `dbx`), platform keys, and update revocation lists. If a stage is blocked (revoked or tampered), boot should fail—or fall back to recovery paths.

```powershell
# Quick posture: Secure Boot + Device Guard/WDAC/VBS summary
Confirm-SecureBootUEFI
Get-CimInstance -ClassName Win32_DeviceGuard |
  Select-Object -ExpandProperty SecurityServicesConfigured, SecurityServicesRunning, VirtualizationBasedSecurityStatus
```

**Practitioner note:** Secure Boot prevents unsigned bootkits but does **not** guarantee a hardened OS policy once booted. Runtime controls (CI, WDAC, VBS/HVCI) still decide what post-boot code may load.

### Code Integrity (CI): who may execute

**Code Integrity** enforces that only trusted, correctly signed code runs. In user mode, **UMCI** (User-Mode Code Integrity) backs **WDAC** decisions; in kernel mode, **KMCI** bans unsigned drivers and (optionally) third-party kernel Graphical Kernel Subsystem (GDI) font loading and other legacy vectors. CI recognizes different **signing levels** (e.g., Microsoft, WHQL, cross-signed, attestation-signed, test-signed); policies can allow or refuse each level.

```c
// Ask the kernel about Code Integrity status (simplified; error checks omitted)
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION {
  ULONG Length;
  ULONG CodeIntegrityOptions;
} SYSTEM_CODEINTEGRITY_INFORMATION;
typedef NTSTATUS (NTAPI *NtQuerySystemInformation_t)(ULONG,PVOID,ULONG,PULONG);
int main() {
  SYSTEM_CODEINTEGRITY_INFORMATION ci = { sizeof(ci), 0 };
  auto NtQSI = (NtQuerySystemInformation_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
  NtQSI(103 /*SystemCodeIntegrityInformation*/, &ci, sizeof(ci), NULL);
  printf("CI Options: 0x%08lx\n", ci.CodeIntegrityOptions);
  return 0;
}
```

**Analyst lens:** a box can be “Secure Boot ON” yet run with permissive CI (e.g., Test Signing), or a WDAC policy in **Audit** mode only. Join **policy + signing levels + event logs** before judging exposure.

### WDAC / App Control: allow-lists and reputation

**Windows Defender Application Control (WDAC)** (aka **App Control**) governs *which* signed code is **allowed**. Unlike classic AV deny-lists, WDAC is **default deny** when **Enforced**: only trusted signers/hashes/paths/attributes run. WDAC supports **Enterprise signing**, **Managed Installer**, **ISG (Intelligent Security Graph)**, and **supplemental policies**. Modes:

* **Audit**: logs what would have been blocked.
* **Enforce**: blocks unapproved code.
* **UMCI only** or **UMCI+KMCI** depending on policy.

```powershell
# See recent WDAC decisions
Get-WinEvent -LogName "Microsoft-Windows-CodeIntegrity/Operational" -MaxEvents 20 |
  Select-Object TimeCreated, Id, Message
```

**Threat model:** WDAC shrinks the attack surface for **initial execution** and for **side-loading**. Attackers pivot to **signed-but-vulnerable drivers**, **LOLbins** already allowed, or **memory-only** paths—your detection must cover those too.

### VBS/HVCI: the hypervisor holds the keys

**Virtualization-Based Security (VBS)** uses a hypervisor to carve out **Isolated Virtual Trust Levels (VTLs)**. **HVCI** (Hypervisor-enforced Code Integrity) keeps the kernel’s executable pages honest: even if a kernel bug is exploited, turning RW into RX or patching code is blocked by EPT permissions under hypervisor control. HVCI also protects **kernel key structures** (e.g., EPROCESS tokens, IDT/GDT) indirectly by denying code/data tampering primitives.

**Implication:** load-time trust (signatures) is necessary but insufficient; **runtime** writes to code are denied. Attackers escalate to **vulnerable drivers** with DMA or hypervisor escape attempts, or retreat to user-mode-only techniques.

### Protected Process Light (PPL): who may touch whom

**PPL** assigns **protection levels** to processes (e.g., `WinTcb`, `Lsa`, `Antimalware`, `Windows`, `ProtectedLight-Windows`). The kernel enforces interaction rules: only processes with **equal or higher** signer level and **compatible** protection type may **open**, **inject into**, or **debug** a PPL. PPL does not sandbox logic; it **raises the bar** for cross-process tampering. Examples: **LSASS** often runs as `PPL-Lsa`; **AV** runs as `PPL-Antimalware`.

```text
; WinDbg quick glance at PPL on a target
!process <pid> 1
  ...
  Protection: PsProtectedSignerLsa-Light
```

**Red-team reality:** “I have SeDebugPrivilege” is not enough to open LSASS if it is **PPL-Lsa**. You need an **equal/higher** signer (e.g., a co-signed security product process) or a kernel-mode primitive that violates the rule—typically a vulnerable driver.

### PatchGuard: the kernel’s self-defense

**PatchGuard** (Kernel Patch Protection) periodically checks kernel invariants (code segments, SSDT, IDT, GDT, critical lists, callback tables). If tampering is detected, it **bugchecks** instead of trying to recover. This blunts persistent rootkits that patch `ntoskrnl` or popular dispatch tables. It is not an access control policy; it is a **booby trap** for post-compromise stealth.

**Operational takeaway:** PatchGuard pushes attackers toward **data-only** kernel attacks (tokens, ACLs) and **bring-your-own-vulnerable-driver** (BYOVD) flows that perform allowed operations through a signed—but buggy—path.

### Posture is a chain, not a checkbox

A hardened environment ties these together:

* **Boot**: Secure Boot “on” and revocation list current.
* **Runtime**: WDAC enforced (UMCI + desired KMCI), VBS/HVCI running, PPL applied to sensitive services.
* **Observability**: CI/WDAC/Kernel logs integrated; vulnerable-driver allow-lists block BYOVD.

```powershell
# Minimal runtime check: VBS + HVCI + PPL target
Get-CimInstance -ClassName Win32_DeviceGuard |
  Select-Object -ExpandProperty SecurityServicesRunning
Get-Process -Name LSASS | % {
  $_.Path;  # presence only; use WinDbg or ETW for protection level classification
}
```

## Why this matters for exploitation / anti-exploit / malware analysis

Almost every persistent foothold ends up negotiating these gates. Exploits must either **live inside** allowed code paths (LOLbins, signed drivers), **bypass** them (BYOVD, test signing), or go **memory-only** while avoiding CI/CFI. Defenders who can read **policy → eventing → memory artifacts** spot when a box drifted into **Audit**, when HVCI is **off because of drivers**, or when LSASS is **not** PPL-protected. Analysts map **what executed** to **why it was allowed**, then decide **how to narrow it** without breaking the estate.

## APIs and functions

* `NtQuerySystemInformation(SystemCodeIntegrityInformation)` – query global CI options.
* `GetSystemFirmwareTable` – enumerate SMBIOS/ACPI data (context for Secure Boot state via higher-level cmdlets/tools).
* `GetProcessInformation(ProcessProtectionLevelInfo)` – read a process’s PPL metadata where available.
* `GetProcessMitigationPolicy` / `SetProcessMitigationPolicy` – inspect/tune per-process policies (pairs with CFI/DEP chapters; useful context for VBS-aware apps).
* `WinVerifyTrust` – verify a file’s signature and policy compliance (tooling step, not an enforcement path).
* `DeviceIoControl` – used by drivers; in BYOVD investigations you’ll map IOCTLs that subvert CI/PPL indirectly.
* `LsaRegisterLogonProcess` – reference point; shows why PPL-Lsa exists to constrain even privileged callers.
* `Event Tracing for Windows (ETW)` providers: CodeIntegrity, AppLocker/WDAC, Kernel-Process/ImageLoad – join policy decisions with execution.

## Pitfalls, detection notes, and anti-analysis gotchas

* **Audit ≠ Enforce:** WDAC in **Audit** only tells you what would have been blocked—threat actors rely on this misread.
* **Test signing/dev policies left on:** labs that forget to revert leak permissive settings into production gold images.
* **Driver compatibility flips HVCI off:** legacy drivers can silently **disable** HVCI/VBS at deploy time; confirm with **running** status, not install intent.
* **PPL misunderstandings:** PPL is a **who-may-touch-whom** rule, not a sandbox; a PPL service can still make dangerous calls.
* **Signed ≠ safe:** attestation-signed or WHQL drivers can be vulnerable; track and **blocklist** known-bad hashes and vendors.
* **BYOVD telemetry holes:** once a signed driver is loaded, many EDR hooks sit **above** it; prefer kernel ETW + blocklists.
* **PatchGuard crash misattribution:** instability after “legit” kernel instrumentation is often PatchGuard—don’t ignore minidumps.
* **Nested virtualization/Hyper-V conflicts:** security products or dev stacks that toggle hypervisors can turn off VBS; watch posture drift after updates.

## Cross-references

* Memory provenance, W→X, and call-target metadata intersect with **DEP / NX / W^X** and **Compiler & Hardware CFI: CFG, CET (Shadow Stack/IBT)** (Part 2).
* The **loader** and **object/handle** model provide the primitives that WDAC/CI constrain; see **Windows Loader & Image Activation** and **Object Manager & Handles** (Part 1).
* Syscall semantics and where to anchor telemetry are in **Syscalls & the NTAPI Boundary** (Part 1).
* Kernel tradecraft that collides with KASLR and PatchGuard continues in **Kernel Exploitation Primer** (Part 4).
* Event joins and hunting playbooks for CI/WDAC/ImageLoad are expanded in **Windows Eventing & ETW Playbook** and **Telemetry & Hunting** (Part 5).

## Glossary

* **Secure Boot**: UEFI verification that each boot stage is signed by trusted keys.
* **Code Integrity (CI)**: Kernel enforcement that only trusted (signed/allowed) code executes.
* **WDAC (App Control)**: Policy-based allow-listing for user-mode and (optionally) kernel-mode code.
* **VBS**: Hypervisor-backed isolation used to protect sensitive OS components and policies.
* **HVCI**: Hypervisor-enforced Code Integrity; blocks runtime code tampering in the kernel.
* **PPL (Protected Process Light)**: Kernel policy restricting which processes can open/inject/debug protected peers.
* **PatchGuard**: Kernel patch protection that bugchecks on detected tampering with critical structures.
* **Attestation Signing**: Microsoft-signing path for third-party drivers; not a quality guarantee.
* **BYOVD**: Bring Your Own Vulnerable Driver; signed driver used to subvert protections.
* **db/dbx**: UEFI allowed and revoked signature databases used by Secure Boot.

## Key takeaways

* Treat trust as a **chain**: Secure Boot sets the stage, but **CI/WDAC/VBS/PPL** decide runtime realities.
* Enforce **allow-lists** (WDAC) and confirm **HVCI/VBS running**, not just configured.
* PPL changes the **interaction graph**, not application behavior—assess access patterns, not just tokens.
* Expect attackers to lean on **signed-but-vulnerable** components (BYOVD) and **memory-only** payloads; tune detection beyond “unsigned = bad.”
* Read and join **policy + logs + memory artifacts**; many “bypasses” are really **misconfigurations** visible in telemetry.
