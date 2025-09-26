# Part 5 – Detection & Countermeasures: EDR & AV Evasion

**What this chapter covers**

* The common architectural layers of EDR/AV on Windows and where adversaries try to blind or bypass them
* High-signal indicators of evasion (unhooking, direct syscalls, AMSI tamper, PPL games) and how to hunt them
* Practical lab checks to verify sensor health and spot “quiet” compromises without product-specific features
* Hardening moves that raise the cost of evasion (WDAC, PPL boundaries, driver hygiene, cross-view validation)
* Operational pitfalls: event loss, noisy false positives, and brittle detections

## Core concepts

### EDR/AV on Windows: where the eyes are

At a high level, modern endpoint sensors see you from four places:

* **User mode**: DLL shims and API instrumentation (IAT/EAT hooks, trampoline patches) in common host processes; script hosts route content through **AMSI**.
* **Kernel mode**: process/thread/image callback registrations, minifilters, network stack indicators, and sometimes kernel ETW consumers.
* **ETW & Event Log**: providers (kernel + user) feeding a firehose; some product agents subscribe and persist curated events.
* **Cloud analytics**: upload of telemetry chunks and memory samples for retrospective detection.

Knowing this anatomy explains the **attack surface**: unhook user mode, avoid or confuse AMSI, use **direct syscalls** to sidestep shims, race or disable ETW sessions, or install a **signed driver** to hobble callbacks. Your counter-move is **redundancy** (multiple independent views) and **cross-checks**.

---

### How evasion attempts look in practice

Adversaries rarely “turn everything off.” They usually succeed **partially**—which is detectable:

* **Unhooking**: `EtwEventWrite` returns success without logging; `AmsiScanBuffer` patched to constant `AMSI_RESULT_CLEAN`.
* **Direct syscalls / syswhispers**: user-mode API calls disappear from stack traces; kernel still sees the effect (thread/process creation).
* **In-memory execution**: **private RX** regions and module loads without stable on-disk lineage.
* **Trust piggy-backing**: **sideloading** into signed processes to inherit opt-ins or PPL adjacency.
* **Driver abuse**: vulnerable/signed drivers to read/write kernel memory or unregister callbacks.

You’re looking for **discrepancies** between subsystems that should agree: kernel ETW vs. user logs, AMSI vs. ScriptBlockLogging, image loads vs. file lineage.

---

### Cross-view verification beats single-sensor faith

Pick at least **two independent sources** for each hypothesis:

* **Code ran** → Kernel Process/Image vs. Security 4688/Module logs.
* **Script executed** → PowerShell 4104 vs. AMSI Operational.
* **Injection happened** → Sysmon CreateRemoteThread/MapViewOfSection vs. Kernel Thread provider.
* **Network egress** → DNS-Client vs. WinHTTP/WinINet vs. firewall logs.

If one says “no” while the others say “obviously yes,” treat “no” as a **signal** of evasion.

---

### Harden the boundaries attackers lean on

You can’t eliminate evasion, but you can **shrink the safe runway**:

* **WDAC/App Control**: reduce unsigned and unapproved loaders; starves sideload chains.
* **PPL (Protected Process Light)** for security agents: increases difficulty of handle-based tamper and memory readers.
* **Driver allow-listing** and **revocation hygiene**: block known-bad/vulnerable drivers; monitor **driver loads** like you do user modules.
* **VBS/HVCI**: makes user-mode patching and kernel ROP materially harder; your detections live longer.
* **ETW session health monitoring**: buffer sizes, dropped events, and unexpected provider disablement.

---

## Example-first: quick integrity checks and discrepancy hunts

```powershell
# Check for suspicious silence: ScriptBlock logging active but AMSI quiet
$window = (Get-Date).AddMinutes(-30)
$sb = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" |
      Where-Object { $_.Id -eq 4104 -and $_.TimeCreated -gt $window }
$am = Get-WinEvent -LogName "Microsoft-Windows-Antimalware-Scan-Interface/Operational" |
      Where-Object { $_.TimeCreated -gt $window }

if ($sb.Count -gt 0 -and $am.Count -eq 0) {
  Write-Warning "PowerShell ScriptBlock activity present but AMSI is silent—possible tamper/unhook."
}
```

*What it catches:* in-process AMSI patching or provider disablement while PowerShell still runs.

---

```powershell
# ETW kernel process vs. Security 4688 discrepancy (time-boxed sample)
# Requires Security auditing of process creation
$since = (Get-Date).AddMinutes(-10)
$sec = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=$since}
$kproc = Get-WinEvent -LogName "Microsoft-Windows-Kernel-Process/Operational" |
         Where-Object { $_.TimeCreated -gt $since }

# naive join on ProcessName+Time window—refine with PID if you enrich events
$kNames = $kproc | ForEach-Object { $_.Properties[1].Value } # ImageName
$secNames = $sec | ForEach-Object { ($_ | Select-Object -ExpandProperty Properties)[5].Value } # NewProcessName
$miss = $kNames | Where-Object { $_ -notin $secNames } | Group-Object | Sort-Object Count -Descending
$miss | Select-Object -First 5
```

*What it catches:* processes visible to kernel ETW that never materialize in Security log—misconfig, pipeline loss, or deliberate blinding.

---

```powershell
# User-mode sanity check: is EtwEventWrite patched in a hot process?
# Non-invasive: compare export address with module .text range
$target = Get-Process -Name powershell, wscript, mshta -ErrorAction SilentlyContinue | Select-Object -First 1
if ($target) {
  $mod = $target.Modules | Where-Object { $_.ModuleName -eq "ntdll.dll" }
  $addr = (Get-ProcAddress $mod.FileName "EtwEventWrite") # requires helper, or use a debugger
  # Pseudo-check: in real use, ensure $addr lies within ntdll .text region and not a jump to heap
  "Check EtwEventWrite at 0x{0:X}" -f $addr.ToInt64()
}
```

*What it hints at:* crude detection of **unhooking** that redirects ETW writes to non-module memory. Use proper tooling (dbghelp/WinDbg) in the lab.

---

## Why this matters for exploitation / anti-exploit / malware analysis

Modern payloads assume your EDR is present and aim to **degrade** it—not necessarily to zero, but enough. If your workflows depend on any **single** layer (AMSI, user-mode hooks, one provider), you’ll **miss**. Analysts who institutionalize **cross-view** checks and basic **sensor health** monitoring keep visibility even when adversaries pivot to direct syscalls, in-memory execution, or signed-driver shenanigans. Exploit developers and red teams benefit from the same knowledge to test realism and to generate **evidence** defenders can key on.

## APIs and functions

* `EtwEventWrite` — user-mode ETW entry; common unhooking target; verify integrity in suspicious processes.
* `AmsiScanBuffer` / `AmsiScanString` — AMSI scanning entry points; patching or bypasses produce the AMSI–PowerShell discrepancy.
* `NtCreateThreadEx` — core remote-thread primitive; still visible to kernel even with direct syscalls.
* `PsSetCreateProcessNotifyRoutine(Ex)` — kernel callback for process events; ensure drivers aren’t removing coverage.
* `ObRegisterCallbacks` — kernel object callbacks (handle operations); tamper attempts to disable are serious.
* `MiniFilterRegisterFilter` — file system minifilter registration; watch for unexpected filters or unloads.
* `StartTrace/EnableTraceEx2/StopTrace` — ETW session control; use to verify provider state and buffer health.
* `WinVerifyTrust` — signer checks for loaded modules/drivers to support allow-listing and anomaly scoring.

## Pitfalls, detection notes, and anti-analysis gotchas

* **False “silence” from policy**: ScriptBlock logging or AMSI may be disabled by admin choice; verify **GPO** before calling tamper.
* **Event drops ≠ evasion**: saturated ETW buffers look like blinding; monitor **dropped events** counters and session buffers.
* **Parent spoofing**: `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` can forge lineage; add **start-time** sanity and rare-parent models.
* **Signed ≠ safe**: trusted updaters can be coerced to sideload; always carry **signer + path + parent** as a trio.
* **WOW64 confusion**: mixed-arch hooks and providers can appear uneven; normalize on architecture in your queries.
* **Driver revocation lag**: blocking vulnerable drivers requires current revocation lists and reboot cycles; treat **new driver loads** as high-signal events.
* **PPL expectations**: SYSTEM token alone cannot touch PPL processes; use PPL status as a **health probe** of real privilege.

## Cross-references

* **Windows Eventing & ETW Playbook** for enabling the kernel/user providers these discrepancy hunts rely on.
* **Telemetry & Hunting** for effect-based queries (private RX, parentage, file-to-module correlations) you’ll apply when evasion is suspected.
* **Telemetry Tampering & Unhooking (ETW, Direct Syscalls)** for attacker techniques behind the gaps you’ll detect here.
* **Trust & Integrity: Secure Boot, WDAC/App Control, Code Integrity, PatchGuard, VBS/HVCI, PPL** for the hardening levers that shrink the evasion surface.
* **Process Injection & Hooking** to understand the behaviors (remote thread, APC) that still surface in kernel telemetry even with user-mode bypasses.

## Glossary

* **Unhooking**: removing or bypassing user-mode API hooks to evade monitoring.
* **Direct syscalls**: invoking kernel services via `syscall` stubs, sidestepping user-mode shims.
* **PPL (Protected Process Light)**: protection class restricting who can open/manipulate critical processes.
* **Discrepancy signal**: detection based on disagreement between independent telemetry sources.
* **Private RX**: process-private executable memory; common artifact of in-memory loaders.
* **Callback surface**: kernel notification APIs (process/thread/image/handle) EDRs register to gain visibility.
* **Driver abuse**: using (often signed) drivers to tamper with the kernel or sensors.
* **AMSI**: content scanning broker for script engines and other providers.
* **ETW session health**: buffer and drop metrics indicating whether telemetry is trustworthy.
* **Sideloading**: abusing DLL search order to load attacker-controlled modules under a signed process.

## Key takeaways

* Build detections around **effects** and **cross-views**; treat mismatches as first-class signals of evasion.
* Assume partial success for attackers: AMSI may be blind while kernel ETW still shows execution—**verify both**.
* Raise the bar with **WDAC**, **PPL**, **driver allow-listing**, and **VBS/HVCI**; your signals last longer.
* Monitor **ETW session health** and **driver loads**; drops and new filters are as informative as alerts.
* Keep examples and checks **product-agnostic** so your playbooks work even when an EDR is degraded.
