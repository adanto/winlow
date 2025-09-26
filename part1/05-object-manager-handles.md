# Part 1 – Fundamentals: Object Manager & Handles

**What this chapter covers**

* The Windows Object Manager: namespaces, types, security descriptors, and lifetime
* Handles as capabilities: desired access, handle tables, inheritance/duplication, and auditing
* Name resolution and namespaces (`\GLOBAL??`, `\BaseNamedObjects`, `\Device`, `\KnownDlls`)
* How tokens, SACLs, and integrity levels gate handle creation and use
* Practical triage: listing, tracing, and reasoning about suspicious handles

## Core concepts

### Objects, types, and the namespace

Windows treats most resources as **objects** with a **type** (Process, Thread, File, Key, Event, Section, SymbolicLink, etc.), a **name** (optional), and a **security descriptor** (owner, DACL, SACL). The **Object Manager** maintains a hierarchical **namespace** (rooted at `\`) and per-type semantics. You interact with objects through **handles** stored in a process’s **handle table**.

Common roots you will meet:

* `\Device` for device objects and file system stacks
* `\BaseNamedObjects` for user-mode named objects (events, mutexes, sections)
* `\GLOBAL??` for DOS drive letter links (e.g., `C:`)
* `\KnownDlls` for system image sections published by the kernel

**Why it matters:** many “priv-esc without a bug” chains abuse names and links (symbolic links/object directories) to redirect opens, or they steal useful handles already present.

```c
// Open a process with least privilege, then duplicate its token handle (error checks omitted)
#include <windows.h>

int main() {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 4); // PID 4 is System (example only)
    HANDLE hTok = NULL;
    if (hProc && OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_QUERY, &hTok)) {
        HANDLE hDup = NULL;
        DuplicateTokenEx(hTok, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &hDup);
        // Use hDup with ImpersonateLoggedOnUser(...) as appropriate
        CloseHandle(hDup);
        CloseHandle(hTok);
    }
    CloseHandle(hProc);
    return 0;
}
```

**Analyst note:** the *rights* you request define what you can do later; defenders monitor handle creations with excessive access to sensitive objects (processes, tokens, LSASS, SCM, registry hives).

### Handles are capabilities

A **handle** encapsulates: the target object, a **granted access mask**, and optional **audit** state. It lives only inside the process that holds it (unless duplicated). Two things decide what you receive on open:

1. Your **effective token** (primary or impersonation), and
2. The target object’s **DACL** and **integrity policy**.

**Desired vs. granted access:** requesting `PROCESS_ALL_ACCESS` invites failure and telemetry. Request the **narrowest access** that supports your goal (e.g., `PROCESS_VM_OPERATION | PROCESS_VM_WRITE` when you only need to write memory).

**Inheritance and duplication:**

* **Inheritance**: child processes can inherit selected handles at creation.
* **Duplication**: `DuplicateHandle` copies a handle into the same or another process, potentially reducing or expanding the access mask (but never beyond what the source process had on the object).

### Names, links, and where confusion comes from

Object names live in the kernel namespace, but **user-mode APIs** often resolve DOS-style paths. Translation goes through `\GLOBAL??` and symbolic links. Attackers use **TOCTOU** and **link races** (reparse points, directory junctions, `\RPC Control` symlinks) to redirect privileged opens. Understanding what the kernel finally opens (the **resolved NT path**) is key to triage.

### Security descriptors, integrity, and SACLs

A **security descriptor** holds:

* **Owner** and **Group** (mostly relevant for DACL editing)
* **DACL** (who may do what)
* **SACL** (what access attempts are audited)

**Integrity levels** (Low/Medium/High/System) add a **mandatory label** gate: low-integrity callers cannot write to high-integrity objects even if the DACL says otherwise. In practice, this blocks Low IL sandbox escapes that rely purely on handle opens.

### Lifetime and reference counts

Objects survive as long as they have references. A handle increments the object’s reference count; closing it decrements the count. Kernel components may hold references too. Memory exhaustion and denial-of-service tricks often abuse **leaked handles** or **excess reference counts**.

```text
; WinDbg quick handle inspection
!handle -a <handle>    ; show object type, granted access, name, and security
!process 0 1           ; list processes, then switch (~) and run !handle 0 3 for scoped dumps
!object \BaseNamedObjects ; enumerate named objects
```

**Analyst tip:** prefer **scoped** handle enumeration (specific PIDs, specific types) to avoid drowning in noise.

### Sections, tokens, and other high-value types

* **Section** objects back shared memory and images; a handle to a section with `SECTION_MAP_EXECUTE` is a strong signal in loaders.
* **Token** objects represent identity; `TOKEN_DUPLICATE`, `TOKEN_ASSIGN_PRIMARY`, and `TOKEN_ADJUST_PRIVILEGES` are the classic triad for lateral move/local priv-esc.
* **Process/Thread** objects gate injection (`VM_OPERATION/WRITE`, `CREATE_THREAD`) and hijack (`SUSPEND_RESUME`, `SET_CONTEXT`) actions.
* **Key** (registry) and **File** objects expose configuration and persistence; write access into sensitive paths is high-risk.

### Object directories and isolation

Objects live under **directories** with their own security. Brokered designs (AppContainer, PPL companions) place named IPC objects in guarded directories where untrusted callers can signal but not seize control. Malware often abuses world-writable directories to inject semantics (swap the target of a link; claim a name first).

### Auditing and telemetry

If SACLs request it (or when ETW providers are enabled), the kernel emits **audit events** for handle opens/closures with specific rights. EDRs fuse these with **ImageLoad** and **ProcessStart** to catch tell-tale sequences: “open LSASS with `VM_READ` → map section → read credentials”.

## Why this matters for exploitation / anti-exploit / malware analysis

Exploitation without a usable **handle** rarely goes far: you need a process handle to inject, a token handle to escalate, or a section handle to map code. Defenders who watch **handle creation** at the NT layer (object type + rights + caller identity) catch attacks before payload execution. Analysts use handle provenance to explain *how* an action was possible and to reconstruct chains (inheritance, duplication, parent spoofing).

## APIs and functions

* `NtOpenProcess` / `OpenProcess` – obtain a process handle with precise rights; foundation for injection/hijack.
* `NtOpenThread` / `OpenThread` – thread-level control (suspend, context, impersonation).
* `DuplicateHandle` – copy a handle across processes; used to launder or constrain access.
* `NtQuerySystemInformation` (SystemExtendedHandleInformation) – enumerate system-wide handles for hunting tools.
* `NtOpenFile` / `NtCreateFile` – open/create files by NT path; separates DOS path confusion from reality.
* `NtOpenKeyEx` / `RegOpenKeyExW` – open registry keys with explicit view and rights.
* `OpenProcessToken` / `DuplicateTokenEx` – obtain and clone tokens for impersonation/priv-esc.
* `NtCreateSection` / `NtMapViewOfSection` – create/map sections; strong indicator when combined with execute rights.

## Pitfalls, detection notes, and anti-analysis gotchas

* **Over-asking for rights:** `*_ALL_ACCESS` fails more, creates noise, and trips alerts. Ask for **exact** bits.
* **Handle inheritance leaks:** forgetting to clear inheritance on creation or to pass `bInheritHandles=FALSE` lets children keep powerful handles.
* **Parent spoofing ≠ lineage:** a forged parent process can mislead naive “inheritance” assumptions; confirm with ETW and token lineage.
* **Cross-session surprises:** named objects may resolve to per-session directories; the “same name” can point to a different object.
* **WOW64 confusion:** 32-bit tools may miss 64-bit handles in a 64-bit process; match bitness.
* **Symbolic link races:** DOS paths (`CreateFileW`) can be redirected via reparse points; prefer NT paths (`\??\C:\...`) when validating behavior.
* **SACL blind spots:** no audit = no event; rely on ETW **and** SACLs, not either alone.
* **Stale handle triage:** a process may hold a powerful handle that is no longer legitimate in policy terms—**the handle still works** until closed.

## Cross-references

* We assume the execution scaffolding from **Processes & Threads** and loader state from **Windows Loader & Image Activation** (Part 1).
* Memory provenance of **Section** mappings vs. private allocations is covered in **Memory & Virtual Address Space** (Part 1).
* System call mechanics and direct-syscall evasions appear in **Syscalls & the NTAPI Boundary** (Part 1).
* Integrity and code-trust policy interactions (PPL, WDAC, Code Integrity) belong to **Trust & Integrity: Secure Boot, WDAC/App Control, Code Integrity, PatchGuard, VBS/HVCI, PPL** (Part 2).
* Offensive uses (token theft, section-based injection) continue in **Process Injection & Hooking** (Part 3).

## Glossary

* **Object**: Kernel-managed entity with a type, optional name, and security descriptor.
* **Handle**: Per-process reference to an object, carrying a granted access mask.
* **Object Namespace**: Hierarchical tree of directories containing named objects (rooted at `\`).
* **Security Descriptor (SD)**: Owner, DACL, and SACL controlling access and auditing.
* **DACL/SACL**: Access control and audit lists; SACL emits audit events on specified access.
* **Integrity Level**: Mandatory label controlling writes/reads across trust boundaries.
* **Section**: Backing store for shared memory and images; map into one or more processes.
* **Token**: Identity and privileges context used in access checks (primary/impersonation).
* **Handle Table**: Per-process structure storing active handles and metadata.
* **Symbolic Link**: Namespace indirection object; commonly used to bridge DOS and NT paths.

## Key takeaways

* A **handle is a capability**: least-privilege rights and provenance matter more than the API you called.
* Name resolution occurs in the **kernel namespace**; validate the final NT path to avoid link tricks.
* Watch **handle creation** to sensitive objects/types with unusual rights—ahead of payload execution.
* **Inheritance and duplication** are common blind spots; scrub at creation and monitor cross-process duplicates.
* For reliable triage, correlate **object type + rights + caller token + namespace path** at the **NT** layer, not just Win32 wrappers.
