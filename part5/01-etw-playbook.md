# Part 5 – Detection & Countermeasures: Windows Eventing & ETW Playbook

**What this chapter covers**

* How Windows Event Tracing (ETW) and classic event logs fit together and what each actually sees
* The providers that matter for malware triage (kernel process/image, PowerShell, AMSI, DNS, network) and how to enable them
* A practical playbook: minimal triage sessions, collection filters, and queries that surface real attacks without drowning you in noise
* Event loss, tampering, and anti-telemetry tactics—and how to detect or degrade them
* Building durable detections that survive EDR evasion, unhooking, and direct-syscall tricks

## Core concepts

### ETW in one screenful

Event Tracing for Windows (ETW) is a **high-throughput, low-overhead** pub/sub pipeline. **Providers** (kernel or user mode) produce events; **controllers** start a **session** and enable those providers with a **Level** and **Keyword mask**; **consumers** subscribe and decode payloads. ETW is not “the Event Log”—it is the *firehose* behind it. The Windows Event Log (WEL) consumes some ETW channels and writes friendly, persisted events; many high-value security facts exist **only** in ETW and never hit the WEL unless you collect them.

Basic shape you need to remember:

* **Providers** (e.g., `Microsoft-Windows-Kernel-Process`, `Microsoft-Windows-PowerShell`).
* **Sessions** (e.g., `NT Kernel Logger`, your own named session).
* **Levels/Keywords** (coarse + fine filtering).
* **Manifests/WPP** (how fields are named and decoded).

#### Example: spin up a short kernel triage

```powershell
# Lab-only: 30-second kernel process/image trace, then summarize
$session = 'TriKern'
logman start $session -p "Microsoft-Windows-Kernel-Process" 0x10 0x5 `
                      -p "Microsoft-Windows-Kernel-Image"   0xffffffffffffffff 0x5 -ets
Start-Sleep -Seconds 30
logman stop $session -ets
wevtutil qe "Microsoft-Windows-Kernel-Process/Operational" /c:20 /rd:true /f:text
```

*What it does:* starts a **real** ETW session (not just reading the log), enables the **process** and **image load** providers, runs for 30 seconds, then shows the last 20 process events. Use this to **prove** an injection or loader did what you think it did.

---

### ETW vs. Event Log vs. Sysmon (and why you want all three)

* **Windows Event Log (WEL)**: persisted, schema-stable, but sparser. Security 4688/4689 process events, 4624 logons, 4697 service installs, etc.
* **ETW providers (direct)**: richer context, transient by default unless your session writes to disk. You choose what to enable.
* **Sysmon**: a driver + service that **subscribes to ETW + native callbacks**, enriches, and **persists** concise events (ProcCreate, ImageLoad, CreateRemoteThread, DNS, etc.). Treat it as a curated “security lens” over ETW.

Use WEL for *policy* controls and durable audit, ETW for **ad hoc triage** and **high-fidelity hunting**, Sysmon for **normalized, long-lived signals** with your own config.

---

### The providers that consistently pay off

* **Microsoft-Windows-Kernel-Process** (`ProcessStart/Stop`, handle duplication patterns).
* **Microsoft-Windows-Kernel-Image** (module loads: unpackers, reflectively loaded DLLs that still map a file later).
* **Microsoft-Windows-Kernel-Thread** (remote threads, APC-heavy behavior).
* **Microsoft-Windows-PowerShell** (`400/403/4103/4104`: engine start, module logging, script block).
* **Microsoft-Windows-Antimalware-Scan-Interface/Operational** (AMSI scan results; blocked vs. allowed content).
* **Microsoft-Windows-DNS-Client** (beaconing, DGA hints).
* **Microsoft-Windows-WinINet/WinHTTP** (living-off-the-land downloaders).
* **Microsoft-Windows-Threat-Intelligence** (block reasons on code integrity and trust decisions when App Control is in play).

You do not need “everything.” Start with **process + image + PowerShell + AMSI**, then add **DNS** and **network stacks** if your case smells like C2.

---

### Levels and Keywords: don’t drown

Providers define **Level** (verbosity) and **Keyword** masks (bitfields for categories). Controllers pick both. For kernel providers:

* `Level` **5** (verbose) is common for triage.
* `Keyword` **0x10** for process usually captures starts/stops and command lines; `0xFFFFFFFFFFFFFFFF` for image is acceptable in lab windows.

Filtering at the **controller** is cheaper than post-hoc query filtering—critical on busy servers.

---

### WPP vs. Manifest providers

Most modern providers are **manifest-based** (self-describing, with stable fields). Many drivers still use **WPP** (tracefmt-style), where field names are not visible without the provider’s TMF files. In practice: stick to **well-known manifest** providers for security hunting; treat WPP-only trails as **supplemental** clues.

---

### ETW and mitigations

ETW sits **below** user-mode hooking games. If malware unhooks `kernel32` but still calls `NtCreateThreadEx`, you can still see **thread creation** in kernel ETW. Direct syscalls bypass **user** hooks, not **kernel** provenance. Conversely, ETW can be **tampered** with (e.g., patching `EtwEventWrite` in-process, disabling providers, or clogging the session). Your playbook must include **integrity checks** and **redundancy** (e.g., compare kernel ETW against Security 4688).

---

## Example-first: focused triage recipes

### Process & Image: the “is this thing launching and mapping?” pass

```powershell
# Minimal, time-boxed triage with process + image load
$S='TriProcImage'
logman start $S `
  -p "Microsoft-Windows-Kernel-Process" 0x10 0x5 `
  -p "Microsoft-Windows-Kernel-Image"   0xffffffffffffffff 0x5 `
  -ets
Start-Sleep 15
logman stop $S -ets

# Quick peek at the live channels (no persistent trace file needed for basics)
Get-WinEvent -LogName "Microsoft-Windows-Kernel-Process/Operational" |
  Select-Object -First 10 |
  Format-List TimeCreated,Id,Message
```

*Use it when:* analyzing a suspected **reflective loader**, **DLL sideload**, or **process hollowing** claim. Image loads reveal unexpected **signed-but-odd** DLLs and temporary file-backed modules.

---

### PowerShell + AMSI: script truth vs. console noise

```powershell
# Enable (if policy allows) and harvest key PowerShell logs
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /e:true
wevtutil sl "Microsoft-Windows-PowerShell/Analytic"   /e:true
# AMSI operational channel
wevtutil sl "Microsoft-Windows-Antimalware-Scan-Interface/Operational" /e:true

# Pull recent script block logs (4104) with command lines for the parent 4688
$ps = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" |
      Where-Object {$_.Id -eq 4104} |
      Select-Object TimeCreated, @{n='Script';e={$_.Properties[-1].Value}}
$ps | Select -First 5 | Format-List
```

*Why:* **4104** gives you the **actual code** even if malware hid it behind base64/obfuscation. Pair with **AMSI Operational** to see “Blocked” vs “Allowed.”

---

### DNS + WinINet: quick C2 sniff

```powershell
# Time-boxed network triage
$S='TriNet'
logman start $S `
  -p "Microsoft-Windows-DNS-Client" 0xffffffffffffffff 0x5 `
  -p "Microsoft-Windows-WinINet"    0xffffffffffffffff 0x5 `
  -ets
Start-Sleep 20
logman stop $S -ets

Get-WinEvent -LogName "Microsoft-Windows-DNS-Client/Operational" |
  Select-Object -First 10 TimeCreated,Id,Message
```

*Use it when:* beaconing or one-shot download/execute is suspected. Correlate **process ID** (from Kernel-Process) to see *who* issued the DNS query.

---

### Persisting a session to disk (when you must)

```powershell
# Capture to file for offline decode (etl)
$S='DeepTrace'
logman create trace $S -o "$env:TEMP\deeptrace.etl" -ow -nb 128 640 -bs 1024 -mode Circular
logman update $S -p "Microsoft-Windows-Kernel-Process" 0x10 0x5
logman update $S -p "Microsoft-Windows-Kernel-Image"   0xffffffffffffffff 0x5
logman start  $S
Start-Sleep 60
logman stop   $S
```

*Notes:* **Circular** buffer + **binary** file avoids log bloat and drops. Decode later with `tracerpt`, `xperf`, or an ETW-aware parser in your pipeline.

---

## Why this matters for exploitation / anti-exploit / malware analysis

Post-exploitation on Windows tries to **minimize artifacts**—direct syscalls, in-memory execution, and LOLBins. ETW gives defenders **ground truth** close to the kernel and closer to **intent** (process creation, image mapping, thread start) than any user-mode hook. Analysts need a repeatable, **time-boxed** way to light up the handful of providers that answer, “Did code run? From where? What did it talk to?” This chapter provides those switches and the checks that catch **tampering** when attackers attempt to blind the host.

## APIs and functions

* `StartTrace` / `ControlTrace` / `StopTrace` — controller APIs that create and manage ETW sessions.
* `EnableTraceEx2` — enables a provider for a session with Level/Keyword masks.
* `OpenTrace` / `ProcessTrace` — consumer APIs to read ETW events from a live session or .etl file.
* `TdhOpenDecodingHandle` / `TdhGetEventInformation` — decode manifest-based events into named fields.
* `EvtSubscribe` (WEvtApi) — subscribe to Windows Event Log channels (useful when bridging WEL to ETW-style pipelines).
* `EtwEventWrite` (provider-side) — user-mode export typically targeted by **unhookers**; watch its integrity.
* `EventRegister` / `EventWrite` — provider registration and emission for manifest-based events.
* `AmsiScanString` / `AmsiScanBuffer` — not ETW, but tie directly into **AMSI** events; invoked by PowerShell/JScript hosts.

## Pitfalls, detection notes, and anti-analysis gotchas

* **Session backpressure → event loss**: busy boxes drop events silently if buffers are small. Use adequate **`-nb`** (number/size) and prefer **circular** mode for triage.
* **Provider disabled by Group Policy/EDR conflict**: your start succeeds but yields no data. Verify with **`logman query -ets`** and check **`Enabled`** counters.
* **EtwEventWrite patching**: common evasion is to hotpatch `EtwEventWrite` to return `STATUS_SUCCESS` without logging. Detect via **module hash**/Export address table scan and by comparing **kernel ETW** (still shows behavior) vs. **user channels** (suspiciously quiet).
* **AMSI opt-out**: AMSI can be disabled per-process or bypassed; correlate **PowerShell 4104** presence with **AMSI Operational**—if script blocks exist but AMSI is silent, investigate hooking/tampering.
* **ScriptBlockLogging disabled**: organizations sometimes turn it off due to volume; compensate with **AMSI** and **module logging 4103** plus ETW **WinINet**.
* **Timestamp skew**: mixing WEL and ETW can produce ordering confusion (buffer flush latencies). Normalize on **kernel provider times** when correlating.
* **Sysmon-only blinders**: great normalization, but if it’s uninstalled or misconfigured, you miss native ETW-only facts; always keep a **minimal ETW plan** ready.
* **WOW64 confusion**: 32-bit hosts on x64 generate different module names and sometimes field layouts; ensure your decoders and queries handle both.

## Cross-references

* **Telemetry Tampering & Unhooking (ETW, Direct Syscalls)** explains the unhooking and direct-NT path attackers use; this chapter shows how to *detect* those behaviors by cross-checking kernel ETW against quiet user channels.
* **AMSI & Script Host Internals** provides the exact call paths that lead to **AMSI** and **PowerShell** events referenced here.
* **Process Injection & Hooking** describes the behaviors (remote thread, APC, image mapping) whose footprints you hunt with **Kernel-Process/Thread/Image** providers.
* **DEP / NX / W^X** and **Memory & Virtual Address Space** give the context for W→X transitions that you often pair with **image load** events to confirm in-memory execution.
* **Windows Loader & Image Activation** explains why some reflective loaders still produce **legit image loads**, helpful when interpreting Kernel-Image traces.

## Glossary

* **ETW (Event Tracing for Windows)**: high-throughput event pipeline with providers, sessions, and consumers.
* **Provider**: component that emits events (kernel or user mode).
* **Session**: controller-managed trace that enables providers and collects their events.
* **Level/Keywords**: verbosity and category masks used to filter events at the source.
* **WEL (Windows Event Log)**: persisted channels that may be fed by ETW; not all ETW events are persisted.
* **Sysmon**: Microsoft tool that consumes ETW/native signals, enriches, and writes normalized security events.
* **AMSI**: Anti-Malware Scan Interface; scanning broker used by script hosts and AV to inspect content.
* **WPP**: trace formatting system used by many drivers; requires extra metadata (TMF) for friendly decoding.
* **Backpressure**: condition where ETW buffers fill and events get dropped.
* **Unhooking**: attacker technique to bypass user-mode hooks; ETW kernel data often survives it.

## Key takeaways

* You do not need the whole firehose—**kernel Process/Image**, **PowerShell**, and **AMSI** cover most triage questions fast; add **DNS/WinINet** for C2-suspect cases.
* Prefer **controller-side filtering** (Levels/Keywords) and **time-boxed** sessions to avoid loss and noise.
* Cross-validate: if **user channels** go silent but **kernel ETW** still shows effects, suspect **tampering** or **direct syscalls**.
* Keep a **portable triage kit** (a few `logman` one-liners + `Get-WinEvent` snippets) and a **circular ETL recipe** for offline decode.
* ETW is about **intent**: process starts, image maps, and thread creation are harder to fake than strings or API hooks—anchor detections there.
