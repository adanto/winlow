# Windows Internals & Exploitation

A concise, practical reference that connects Windows internals to real-world exploitation and detection: fundamentals, modern mitigations, evasion techniques, hands-on exploit development, and detection/playbooks. It’s example-driven and written for experienced analysts, reverse engineers, and anti-exploit engineers who want a focused, usable reference.

> **Authorship & process:** The content is authored and maintained by the repository maintainer. To help explain difficult concepts and speed drafting, AI tools were used to produce initial drafts and examples; the author manually reviewed, corrected, and verified all content. This project is a learning effort and will be refined over time.

> **Work in progress:** this is the first public version and will be actively maintained — expect updates, improvements, and new chapters over time.

---

## How to Use This Repository

* **Part 1 – Fundamentals** builds the mental model (processes, memory, loader, NT boundary, APC/callbacks, IPC).
* **Part 2 – Exploitation Mitigations** explains modern defenses and trust controls that shape tradecraft.
* **Part 3 – Anti-Reversing & Evasion** catalogs techniques to resist analysis and bypass sensors.
* **Part 4 – Practical Exploitation** applies fundamentals in hands-on exploitation (userland plus kernel primer).
* **Part 5 – Detection & Countermeasures** provides playbooks, hunting workflows, and case studies.

Each chapter is concise, cross-referenced, and includes realistic code snippets plus a short **“Why this matters”** section.

---

## Responsible Use & Safety

This repository is an educational reference for defensive research and learning. Do **not** run examples on production systems or public networks. Use isolated VMs with snapshots and no network egress when experimenting. Runnable payloads, raw shellcode blobs, operational C2 artifacts, and ready-to-execute exploit chains have been redacted or replaced with annotated pseudo-code. Do not upload compiled malware, weaponized binaries, or operational infrastructure.

---

## Objectives

* Build a Windows-centric exploitation mindset (user↔kernel boundaries, object model, loader, memory).
* Understand mitigation interactions (DEP/ASLR/CFG/CET, WDAC/CI/VBS/PPL, PatchGuard) and bypass surfaces.
* Master evasion tradecraft (anti-debug/anti-disassembly, sandbox/VM checks, unhooking, AMSI/ETW tampering).
* Execute reliable exploits (buffer overflows, UAF, ROP/JOP, shellcode) and structure fuzzing/exploit-dev workflows.
* Operationalize detection (ETW playbooks, YARA/CAPA/Sigma triage, case-driven analysis).

---

## Index

### Part 1 – Fundamentals

* [Introduction](part1/01-introduction.md)
* [Processes & Threads](part1/02-processes-threads.md)
* [Windows Loader & Image Activation](part1/03-loader-image-activation.md)
* [Memory & Virtual Address Space](part1/04-memory-vas.md)
* [Object Manager & Handles](part1/05-object-manager-handles.md)
* [Syscalls & the NTAPI Boundary](part1/06-syscalls-ntapi.md)
* [Scheduling, APCs & Callback Surfaces](part1/07-apcs-callbacks.md)
* [IPC (ALPC, RPC, COM, Pipes)](part1/08-ipc.md)

### Part 2 – Exploitation Mitigations

* [DEP / NX / W^X](part2/01-dep-nx-wx.md)
* [ASLR / KASLR](part2/02-aslr-kaslr.md)
* [Compiler & Hardware CFI: CFG, CET (Shadow Stack/IBT)](part2/03-cfg-cet.md)
* [Trust & Integrity: Secure Boot, WDAC, Code Integrity, PatchGuard, VBS/HVCI, PPL](part2/04-trust-integrity-stack.md)
* [Compiler & EH Hardening (/GS, SafeSEH/SEHOP, EHCONT)](part2/05-compiler-eh-hardening.md)

### Part 3 – Anti-Reversing & Evasion

* [Anti-Debugging](part3/01-anti-debugging.md)
* [Anti-Disassembly](part3/02-anti-disassembly.md)
* [Sandbox & VM Evasion](part3/03-sandbox-vm-evasion.md)
* [Process Injection & Hooking](part3/04-injection-hooking.md)
* [AMSI & Script Host Internals](part3/05-amsi-script-host.md)
* [Telemetry Tampering & Unhooking (ETW, Direct Syscalls)](part3/06-telemetry-tampering.md)
* [Rootkits & Bootkits](part3/07-rootkits-bootkits.md)

### Part 4 – Practical Exploitation

* [Buffer Overflows](part4/01-buffer-overflows.md)
* [Use-After-Free & Type Confusion](part4/02-uaf-type-confusion.md)
* [ROP & JOP](part4/03-rop-jop.md)
* [Shellcoding](part4/04-shellcoding.md)
* [Fuzzing & Exploit Development](part4/05-fuzzing-exploit-dev.md)
* [Kernel Exploitation Primer](part4/06-kernel-exploitation-primer.md)

### Part 5 – Detection & Countermeasures

* [Windows Eventing & ETW Playbook](part5/01-etw-playbook.md)
* [Telemetry & Hunting](part5/02-telemetry-hunting.md)
* [EDR & AV Evasion](part5/03-edr-av-evasion.md)

---

## Core References

* *Evasive Malware: A Field Guide to Detecting, Analyzing, and Defeating Advanced Threats* — Kyle Cucci
* *Rootkits and Bootkits: Reversing Modern Malware and Next-Generation Threats* — Matrosov, Rodionov, Bratus
* *Penetration Testing: A Hands-On Introduction to Hacking* — Georgia Weidman
* [*MITRE ATT&CK*](https://attack.mitre.org/matrices/) — the standard knowledge base for adversary tactics & techniques; useful to map detection strategies and hunting playbooks. 
* [*Microsoft Docs*](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa) — Windows driver & developer docs (official reference for APIs, WDK, driver samples and platform-specific behavior).
* [*Sysinternals (Microsoft)*](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer ) — Process Explorer, Procmon, Autoruns and other runtime triage tools and writeups used daily by defenders and reversers. 
