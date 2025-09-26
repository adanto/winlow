# Part 3 – AMSI & Script Host Internals

**What this chapter covers**

* How the Antimalware Scan Interface (AMSI) plugs into Windows script hosts (PowerShell, WSH/JScript/VBScript, MSHTA, Office/VBA)
* The AMSI request/response model (sessions, buffers, result codes) and how hosts choose to block
* What gets scanned (raw text vs. post-deobfuscation) and where ETW/script logging complements AMSI
* Common failure modes, bypass myths vs. current realities, and what defenders should hunt
* Minimal, safe examples to exercise AMSI and to baseline provider posture

## Core concepts

### AMSI in one page

**AMSI (Antimalware Scan Interface)** is a stable user-mode API that lets an **application** (the “host”) submit arbitrary content—often scripts or command fragments—to a **registered antimalware provider**. The contract is simple:

1. The host calls `AmsiInitialize(appName, &context)`.
2. For each unit of content (buffer or string), it calls `AmsiOpenSession`, then `AmsiScanBuffer`/`AmsiScanString`.
3. The provider returns an **AMSI\_RESULT**: a severity from “clean” to “malicious”.
4. The **host** decides what to do (block, warn, log) based on its own policy.

This means **AMSI is advisory**; hard blocking is implemented by the **host**, not the API. Modern hosts (PowerShell 5+, Office macros in newer channels, MSHTA, WSH) wire AMSI into their execution pipelines so **what executes** is usually **what was scanned**.

```c
// Minimal AMSI exercise (safe): scan a literal string and print the verdict
// cl /W4 /EHsc amsi_demo.c /link amsi.lib
#include <windows.h>
#include <amsi.h>
#include <stdio.h>

int wmain() {
    HAMSICONTEXT ctx = NULL; HAMSISESSION ses = NULL;
    if (AmsiInitialize(L"Book.AMSI.Demo", &ctx) != S_OK) return 1;
    AmsiOpenSession(ctx, &ses);

    const wchar_t *payload = L"Write-Host 'hello, AMSI'"; // benign text
    AMSI_RESULT res = AMSI_RESULT_CLEAN;
    if (AmsiScanString(ctx, payload, L"powershell", ses, &res) == S_OK) {
        wprintf(L"AMSI result: 0x%x  (>= AMSI_RESULT_DETECTED means suspicious)\n", res);
    }
    AmsiCloseSession(ctx, ses);
    AmsiUninitialize(ctx);
    return 0;
}
```

*What to notice:* AMSI sees **text**, not just files. The `contentName` (“powershell”) gives the provider context. Providers can score patterns; hosts often block when `AMSI_RESULT` is **≥ `AMSI_RESULT_DETECTED`** (the exact cutoff is host-defined).

---

### Who calls AMSI, and when

AMSI is **opt-in** per host. Relevant Windows script hosts integrate at different spots in their pipelines:

* **PowerShell (v5+)**: submits **post-expansion script blocks** (often after tokenization/partial deobfuscation) and dynamic fragments (e.g., `Invoke-Expression`, `Add-Type`, Base64 `-EncodedCommand`). It pairs with **Script Block Logging** and **Module Logging** (ETW) so analysts see both the **text** scanned and the **execution** that followed.
* **WSH (`wscript.exe`/`cscript.exe`)**: JScript/VBScript content is scanned before interpretation.
* **MSHTA**: HTML+script payloads are scanned as blocks before dispatch to the engine.
* **Office/VBA**: recent builds submit macro text and some DCOM invocation surfaces. Policy (e.g., Mark-of-the-Web, enterprise macro settings) influences whether AMSI ever runs.
* **Browsers/runtime engines** (legacy EdgeHTML/Chakra, IE): specific script bridges used AMSI historically; modern Chromium-based Edge has different security plumbing—treat AMSI as a **host-by-host** feature.

**Key point:** AMSI sees **what the host submits**. If a loader never goes through a script host (e.g., pure native shellcode), AMSI may not be involved. That’s why joining AMSI with **ETW** and **image/memory provenance** matters.

---

### What exactly is returned

`AMSI_RESULT` is an enum that encodes a **confidence/severity** gradient. Providers convert signatures and heuristics into those levels. Hosts typically treat:

* `< AMSI_RESULT_DETECTED` → allow (perhaps log)
* `≥ AMSI_RESULT_DETECTED` → **block** (PowerShell) or **prompt** (some hosts), sometimes with **admins-overrides**.

There are special results (e.g., **blocked-by-admin** policies) that instruct hosts to deny regardless of content. The API call itself returns `HRESULT`; a **failed call** is not a verdict and should be treated conservatively by the host (e.g., block/high-friction paths).

---

### What AMSI sees vs. what ETW sees

* **AMSI**: the **text or bytes** submitted by the host at the moment of execution, often **after** some level of expansion.
* **PowerShell ETW**: **script blocks** with GUIDs, invocation details, module load events—this is your *timeline*.
* **File/Process/ImageLoad ETW**: ties the script host to file provenance and child processes created by the script.

Joining **AMSI results → ETW script blocks → follow-on process/handle activity** lets analysts distinguish harmless admin scripts from staged loader behavior.

---

### AMSI providers and registration

Providers are COM-like components registered under machine policy. Only **one** active provider typically services a request on the box (the installed AV/EDR). If no provider exists, `amsi.dll` still loads and the API works, but verdicts default to **“no detection”**. Enterprise controls (tamper protection, WDAC) decide whether providers can be disabled.

```powershell
# Safe: observe provider registrations and recent AMSI events (when available)
$reg = 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers'
if (Test-Path $reg) { Get-ChildItem $reg | Select PSChildName,Property }
Get-WinEvent -LogName 'Microsoft-Windows-Antimalware-Scan-Interface/Operational' -MaxEvents 10 |
  Select TimeCreated, Id, LevelDisplayName, Message
```

*Analyst tip:* if AMSI looks **silent** during obvious script activity, confirm a provider exists and is running, and check whether **policy** placed the host in an **allow** or **audit** posture.

---

### Deobfuscation boundaries

PowerShell specifically scans after parsing/tokenization—so constructs like `("I"+"Ex") + " " + ("calc")` are typically **flattened** before scanning. However, **runtime-generated text** (downloaded blobs, reflection strings) must be **submitted** by the host to be scanned. Some hosts miss secondary dynamic layers; AMSI is not a full-sandbox—just a **scan hook**.

---

### Bypass myths vs. current reality

* **Patching amsi.dll exports**: trivial **user-mode patching** of `AmsiScanBuffer` in-process has been widely publicized. On current estates with **code integrity**, **signature verification**, **CET**, and **antitamper**, this is brittle and is detected/crashes often.
* **Setting “am­siInitFailed” in PowerShell**: historical, version-bound; repeatedly closed by updates and watched in telemetry.
* **Encoding-only evasion**: pure Base64/Compress wrappers that hosts decode **before** scanning no longer help.
* **No provider installed**: a real risk on stripped lab VMs; do not mistake “no detections” for a bypass. Confirm provider presence.

Defenders should avoid cat-and-mouse with specific patch signatures; instead, watch **sequence**: a process loads `amsi.dll`, writes to its code pages, then issues script-laden calls or goes quiet—this is crisp, technology-agnostic signal.

---

### Complementary controls

* **WDAC/App Control**: keeps untrusted script hosts and LOLBins from launching in the first place.
* **PPL**: protects security-critical processes from in-process tampering.
* **CFI/CET**: punishes sloppy inline patches and trampoline detours inside protected hosts.
* **Script Block Logging**: reconstructs intent even when AMSI is tampered (host logs the block it *meant* to run).

### Minimal analyst playbook

1. **Verify** there is an AMSI provider and that the script host actually calls AMSI on your box build.
2. **Correlate** AMSI verdicts with **script block ETW** and **child-process tree** (e.g., PowerShell → `rundll32` spawns).
3. **Hunt** for in-process writes to `amsi.dll` or `clr.dll/jscript9.dll` around the time scanning should occur.
4. **Escalate** only when AMSI **should** have triggered but did not, and policy and providers are intact.

## Why this matters for exploitation / anti-exploit / malware analysis

Scripted first stages dominate real intrusions. AMSI gives defenders **content visibility at execution time**, even when payloads never touch disk. Attackers therefore try to **avoid** AMSI (alternate hosts, native-only paths), **starve** it (no provider), or **tamper** with it. Analysts who understand **where AMSI sits** in each host and can join **AMSI → ETW → process/memory** can tell a **benign admin script** from a **stager** in minutes and can explain why a supposed “bypass” was actually **policy drift**.

## APIs and functions

* `AmsiInitialize` – create an application context for scanning.
* `AmsiOpenSession` / `AmsiCloseSession` – scope related scans (correlates content from one logical action).
* `AmsiScanBuffer` / `AmsiScanString` – submit bytes/text to the active provider and receive an `AMSI_RESULT`.
* `AmsiUninitialize` – tear down the application context.
* `CoCreateInstance` – provider instantiation occurs under the hood; useful when exploring custom providers.
* `Add-Type` / `System.Management.Automation` (PowerShell) – not AMSI itself, but where dynamic compilation invokes scanning paths.
* `EtwEventWrite` (host logging) – AMSI verdicts and script blocks often surface via ETW providers alongside the scan.

## Pitfalls, detection notes, and anti-analysis gotchas

* **“AMSI off” on labs:** no provider present or policy in **Audit** mode looks like a bypass—verify posture before judging.
* **Bitness mismatch:** x86 host loads x86 `amsi.dll`; monitor both platforms on x64 systems.
* **Blocking is host policy:** an `AMSI_RESULT_DETECTED` does nothing if the host does not honor it (legacy or misconfigured hosts).
* **Silence ≠ stealth:** user-mode patches to `amsi.dll` don’t mute **kernel ETW** or **process/memory** telemetry—correlate.
* **Over-reliance on strings:** API hashing and obfuscation do not hide **scanned content** in AMSI; focus on **what was submitted**.
* **Provider crashes:** a failing provider returning errors is not a clean verdict—good hosts fail-safe (block); validate behavior on yours.
* **Script host diversity:** not all hosts are equal; Office/VBA behaves differently from PowerShell in timing and scope.

## Cross-references

* Execution provenance and W→X transitions are covered in **Memory & Virtual Address Space** and **DEP / NX / W^X**.
* PowerShell’s CFG/CET interactions and runtime stubs tie back to **Compiler & Hardware CFI: CFG, CET (Shadow Stack/IBT)**.
* Telemetry joins (ETW providers, process/image events) are in **Windows Eventing & ETW Playbook**.
* Loader behavior and host module provenance appear in **Windows Loader & Image Activation**.
* Evasion context and tamper attempts continue in **Telemetry Tampering & Unhooking (ETW, Direct Syscalls)**.

## Glossary

* **AMSI**: Antimalware Scan Interface; API for hosts to submit content to an AV provider.
* **Host**: Application integrating AMSI (e.g., PowerShell, WSH, MSHTA, Office/VBA).
* **Provider**: Antimalware engine implementing the AMSI callback contract.
* **AMSI\_RESULT**: Provider’s severity/confidence code used by the host to decide allow/block.
* **Script Block Logging**: PowerShell ETW that records parsed blocks with GUIDs.
* **Content name**: String passed to AMSI to describe the context (e.g., “powershell”).
* **Mark-of-the-Web (MotW)**: Zone identifier influencing macro/script policy before AMSI.
* **Tamper protection**: Vendor controls preventing provider disable/patch.
* **Deobfuscation boundary**: Stage in the host pipeline at which content is normalized before scanning.
* **Audit vs. Enforce**: Policy modes that determine whether detections block or only log.

## Key takeaways

* AMSI is a **host-mediated** scan hook: it sees **what the host submits** and blocks only if the **host** enforces.
* PowerShell v5+ scans **post-expansion** text and pairs with ETW, giving high-fidelity content plus timeline—use both.
* Most “bypasses” are brittle or configuration artifacts; prefer hunting **sequence** (patch/write → suspicious execute) over signatures.
* Confirm **provider presence** and **policy mode** before concluding evasion; labs often mislead here.
* AMSI complements—not replaces—**ETW, WDAC, PPL, CFI/CET**; together they turn sloppy tamper into detection.
