# Part 5 – Detection & Countermeasures: Telemetry & Hunting

**What this chapter covers**

* How to turn raw Windows telemetry into attacker-centric hunting hypotheses
* Minimal, portable signal sets that survive unhooking, in-memory execution, and LOLBins
* Practical queries and workflows for process trees, module loads, memory permissions, tokens, and persistence
* How to detect telemetry tampering and data gaps and what to pivot to when they occur
* Triage patterns that connect low-level events to high-confidence stories

## Core concepts

### Hunt from effects, not strings

String- and tool-name–based detections age poorly. Windows gives you **effects**: a process starts, a module maps, a thread begins, a token changes, a registry value flips, a pipe is opened. Build hunts around **irreducible intent**:

* **Code execution**: look for process creation with **unexpected parents** and **private RX** regions that go executable.
* **Privilege movement**: token duplication/handle grants, `SeDebugPrivilege` enablement, PPL interactions.
* **Lateral prep**: service installs, scheduled tasks, WMI permanent consumers, admin-share access.
* **Egress**: DNS patterns, WinHTTP/WinINet calls, certificate anomalies.

Effects resist *direct syscall*, *AMSI busting*, and *module unhooking* because they live below those layers or in orthogonal subsystems.

---

### A tiny but durable signal set

You do not need the whole firehose. In almost every investigation, these suffice:

* **Process start & stop** (with command line, parent PID, SID, integrity level).
* **Image load** (full path, signature info, memory-mapped vs. file-backed).
* **Thread start** (source & destination PIDs to spot remote thread creation and APC-heavy loaders).
* **File write → module load coincidence** (same process writes DLL/EXE then loads it).
* **Registry Autoruns** (Run keys, AppCertDLLs, IFEO).
* **Network** (DNS queries by process; WinINet/WinHTTP).
* **AMSI & ScriptBlock** (ground truth of PowerShell/JScript content, when available).

Collect these consistently; enrich with signer info and parent chain.

---

### Baseline before you hunt

Hunting succeeds when **outliers** are visible. Spend a week cataloging:

* Which management tools run where (RMM agents, EDR daemons).
* Legitimate **sideloading** behaviors (line-of-business apps).
* Normal admin utilities and their parents (PSRemoting, SCCM, Intune).
* Common *signed* helper binaries used by apps (packaged VC runtimes, browser updaters).

Then your rules can say “**not in allow-list + suspicious relationship**” instead of “this looks bad.”

---

### Parent–child relationships build stories

An unknown binary spawned by `services.exe` after a **service creation** event is more interesting than a one-off hash. Likewise, `rundll32.exe` launched by `winword.exe` with an HTTP parameter is higher fidelity than flagging `rundll32.exe` everywhere. Always join **parent→child**, and carry **command line**, **creation time**, **integrity**, and **token owner** forward.

---

### Telemetry resilience mindset

Attackers aim to **reduce** what you see (unhook, turn off providers, patch `EtwEventWrite`, neuter AMSI). You counter by:

* **Cross-view checks**: kernel process/image vs. user-mode PowerShell/AMSI; if one goes silent, the other should still move.
* **Time-boxed ETW sessions** for triage; **persisted logs** (Security, Sysmon) for narrative.
* **Active integrity checks**: status of critical providers, ETW session buffer health, API integrity of `EtwEventWrite` in suspicious processes, and anomalous log volume drops.

If two independent views disagree, the disagreement itself is a signal.

---

## Example-first: compact, actionable hunts

```powershell
# Process tree outliers: suspicious parents, LOLBins with strange args
# Lab-friendly: filter on-the-fly, no EDR dependency
$targets = @('rundll32.exe','regsvr32.exe','mshta.exe','powershell.exe','wscript.exe','cscript.exe','installutil.exe')
Get-CimInstance Win32_Process |
  Where-Object { $targets -contains $_.Name.ToLower() } |
  ForEach-Object {
    $parent = (Get-CimInstance Win32_Process -Filter "ProcessId=$($_.ParentProcessId)" -ErrorAction SilentlyContinue)
    [pscustomobject]@{
      Time         = $_.CreationDate
      Child        = $_.Name
      CommandLine  = $_.CommandLine
      Parent       = $parent.Name
      ParentCmd    = $parent.CommandLine
      ParentPid    = $_.ParentProcessId
      Integrity    = $_.ExecutablePath -and (Get-Item $_.ExecutablePath).Attributes
    }
  } | Sort-Object Time | Format-Table -Auto
```

*Why it works:* focuses on **LOLBin abuse** via unusual **parents/arguments**. Even if the payload is in memory and AMSI is muted, parentage and command line reveal intent.

---

```powershell
# File write → module load correlation (same process)
# Good for catching unpack->load and sideload dropper patterns
$recentWrites = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
  Where-Object {$_.Id -in 11, 1} | # 11=FileCreate, 1=ProcessCreate (adjust to your stack)
  Select-Object TimeCreated,Id,ProcessId,MachineName,
    @{n='Target';e={$_.Properties[-1].Value}}, @{n='Image';e={$_.Properties[0].Value}}

$recentLoads = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
  Where-Object {$_.Id -eq 7} | # ImageLoad
  Select-Object TimeCreated,ProcessId, @{n='Loaded';e={$_.Properties[1].Value}}

$join = $recentWrites | Join-Object -On ProcessId -Right $recentLoads
$join | Where-Object { $_.Target -and $_.Loaded -and ($_.Loaded -like "*\Temp\*" -or $_.Loaded -like "*\AppData\*") } |
  Sort-Object TimeCreated | Format-Table TimeCreated, ProcessId, Image, Target, Loaded -Auto
```

*Why it works:* many loaders **drop** a DLL then immediately **map** it. Correlating file create and module load by **process** collapses a lot of noise into a tight story.

---

```powershell
# Detect ETW/AMSI silencing by discrepancy: script evidence with missing AMSI
# If ScriptBlock logs exist but AMSI is silent for the same timeframe/process, investigate
$psBlocks = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" | Where-Object {$_.Id -eq 4104}
$amsiOps  = Get-WinEvent -LogName "Microsoft-Windows-Antimalware-Scan-Interface/Operational"
$last = (Get-Date).AddMinutes(-30)

$psRecent = $psBlocks | Where-Object {$_.TimeCreated -gt $last}
$amsiRecent = $amsiOps  | Where-Object {$_.TimeCreated -gt $last}

if ($psRecent.Count -gt 0 -and $amsiRecent.Count -eq 0) {
  Write-Warning "PowerShell ScriptBlock activity present but AMSI is silent in the last 30 minutes."
}
```

*Why it works:* **cross-view** sanity check. Unhookers often patch AMSI but forget PowerShell operational logging—or vice versa.

---

## Why this matters for exploitation / anti-exploit / malware analysis

Attackers target **weak links**—turning off AMSI, using **direct syscalls**, living inside signed binaries. A defender who hunts **effects**—process ancestry, image maps, thread starts, file-to-module correlations—detects **behavior**, not brands. Analysts need portable, low-assumption playbooks that they can run even when an EDR is down or degraded. This chapter gives you small, robust hunts that map directly to the techniques described throughout the exploitation and evasion parts of the book.

## APIs and functions

* `EvtSubscribe` / `EvtQuery` — programmatically consume Windows Event Log channels for on-host hunts.
* `StartTrace` / `EnableTraceEx2` / `StopTrace` — control ETW sessions for time-boxed hunting bursts.
* `OpenProcess` / `OpenProcessToken` — verify token-based hypotheses (e.g., did a user suddenly gain debug privileges?).
* `GetModuleHandleEx` / `GetMappedFileName` — map module handles to backing files; handy when correlating memory maps with image loads.
* `NtQuerySystemInformation` — enumerate processes/modules in constrained environments.
* `CryptQueryObject` / `WinVerifyTrust` — validate signer metadata at hunt time.
* `GetFileInformationByHandleEx` — fetch file birth/change times to support “wrote then loaded” correlations.

## Pitfalls, detection notes, and anti-analysis gotchas

* **Volume ≠ fidelity**: enabling every provider at Verbose creates drop risk; prefer **tight sessions** and **controller-side filters**.
* **Gaps hide in success**: a sudden **silence** in AMSI or PowerShell logs during otherwise busy process activity is suspicious; don’t ignore “nothing.”
* **Parent spoofing**: some loaders repair parentage by `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`; counter by validating **start time deltas** and improbable lineage (e.g., `lsass.exe` parenting `cmd.exe`).
* **Signed does not mean safe**: treat **unsigned-signed transitions** (dropper writes unsigned, then sideloads signed DLL) as high-risk.
* **Time skew**: ETW and WEL flush at different cadences; use **UTC** and carry **PID** + **StartTime** for joins.
* **WOW64 differences**: x86 processes on x64 hosts may load alternate DLL paths; maintain architecture awareness in rules.
* **Sysmon dependence**: if your hunts assume Sysmon IDs, keep an **ETW fallback** or Security log equivalent; plan for the product to be absent or neutered.

## Cross-references

* **Windows Eventing & ETW Playbook** shows how to enable and collect the signals we hunt here.
* **Telemetry Tampering & Unhooking (ETW, Direct Syscalls)** explains the attacker techniques these discrepancy checks catch.
* **Process Injection & Hooking** provides the behaviors (remote threads, APCs, image maps) your thread/image hunts surface.
* **AMSI & Script Host Internals** contextualizes ScriptBlock and AMSI events used above.
* **Object Manager & Handles** and **Trust & Integrity** chapters give the background for token, handle, and signer-based pivots.

## Glossary

* **Effect-based detection**: focusing on persistent system outcomes (process, image, token) rather than strings/names.
* **Cross-view**: correlating independent telemetry sources to detect tampering (e.g., kernel ETW vs. user logs).
* **Parent spoofing**: forging process ancestry using attribute inheritance to evade basic lineage checks.
* **Autoruns**: registry and filesystem locations that launch code on boot/logon.
* **PPL (Protected Process Light)**: protection level for critical processes; useful test of real privilege.
* **Private RX**: process-private executable memory; strong signal for in-memory loaders.
* **Time-boxed session**: short-lived ETW collection with tight filters to reduce noise and loss.
* **Discrepancy signal**: a detection triggered by disagreement between telemetry sources.

## Key takeaways

* Hunt from **effects** (process, image, thread, token, autoruns) and relationships, not product strings.
* Keep a **minimal signal set** you can collect anywhere; add DNS/WinHTTP when egress is suspected.
* Use **cross-view discrepancies** to catch AMSI/ETW tampering and direct-syscall bypass attempts.
* Correlate **file writes to module loads** and **parent–child chains** to collapse noise into narratives.
* Treat **silence** and **sudden volume drops** as first-class signals; gaps are often the point.
