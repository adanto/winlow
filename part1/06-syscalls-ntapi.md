# Part 1 – Fundamentals: Syscalls & the NTAPI Boundary

**What this chapter covers**

* What the NTAPI boundary is, how `ntdll` marshals calls into the kernel, and how WoW64 changes the path
* `Nt*`/`Zw*` semantics, system call numbers, SSDT dispatch, and return paths
* Practical parameter marshalling (`OBJECT_ATTRIBUTES`, `UNICODE_STRING`, `IO_STATUS_BLOCK`) and common call patterns
* Direct-syscall and hook-evasion considerations (benefits, fragility, detection)
* How to observe and reason about syscalls in debuggers and telemetry

## Core concepts

### The NTAPI boundary in one sentence

User mode crosses into kernel mode through **system calls** exposed by **`ntdll.dll`** as the **NTAPI** (functions like `NtOpenProcess`, `NtCreateFile`). These stubs validate/pack parameters, load a **system service number**, execute the `syscall/sysenter` instruction, and return with a **`NTSTATUS`**. Anything above (`kernel32`, `advapi32`) is a convenience veneer.

```c
// Call the NT layer directly (x64; minimal checks). Shows OBJECT_ATTRIBUTES packing.
#include <windows.h>
#include <winternl.h>

typedef NTSTATUS (NTAPI *PFN_NtCreateFile)(
  PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
  PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);

int main() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    PFN_NtCreateFile NtCreateFile =
        (PFN_NtCreateFile)GetProcAddress(ntdll, "NtCreateFile");

    UNICODE_STRING us; RtlInitUnicodeString(&us, L"\\??\\C:\\Windows\\Temp\\ntapi_test.txt");
    OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &us, OBJ_CASE_INSENSITIVE };
    IO_STATUS_BLOCK iosb = {0};
    HANDLE h = NULL;

    NTSTATUS s = NtCreateFile(&h, FILE_GENERIC_WRITE, &oa, &iosb, NULL,
                              FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
                              FILE_OPEN_IF, FILE_NON_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT,
                              NULL, 0);
    if (NT_SUCCESS(s)) CloseHandle(h);
    return (int)s;
}
```

**Key ideas:**

* **Marshalling:** The NT layer expects **native structs** (`UNICODE_STRING`, `OBJECT_ATTRIBUTES`), not Win32 strings.
* **Status-first:** NT calls return `NTSTATUS`, not `BOOL/GetLastError`. Map failures correctly.
* **Provenance:** Defenders prefer the NT layer because shims/hooks above it are easier to bypass.

### `Nt*` vs. `Zw*` and why you rarely care in user mode

Most NTAPI functions exist as both **`Nt*`** and **`Zw*`** exports. In **user mode** they are the same stubs. The semantic distinction matters **inside the kernel** (effect on `PreviousMode`/parameter probing). For user-mode callers choosing between `NtOpenProcess` and `ZwOpenProcess` is cosmetic.

### How a stub works (x64, native)

An `ntdll` stub loads a **service number** into a register, places a pointer to the argument list, and executes `syscall`. The CPU switches to kernel mode, `ntoskrnl` dispatches via the **System Service Descriptor Table (SSDT)** to the target kernel routine (e.g., `NtOpenProcess` in kernel), which returns an `NTSTATUS`. On return, the stub sets `LastError` from the status if a high-level wrapper asked for it.

```text
; WinDbg peek at a stub (illustrative)
uf ntdll!NtOpenProcess
; You'll see: mov r10, rcx  | mov eax, <ServiceNumber> | syscall | ret
```

**Service numbers are build-specific.** Hardcoding them is fragile across Windows updates; robust “direct syscall” approaches resolve the number **at runtime** by parsing `ntdll` stubs (or regenerating per build).

### WoW64: two thunks and an extra hop

In a 32-bit process on x64 Windows (**WoW64**), a call to `ntdll!Nt*` first thunks through **`wow64.dll/wow64win.dll/wow64cpu.dll`**, then enters the 64-bit kernel path. Tools and hooks that watch only the 64-bit `ntdll` miss 32-bit callers. Cross-bitness injection or tracing must match the target’s bitness.

### Parameter contracts and common gotchas

The NT layer takes **explicit desired access masks**, **NT paths** (e.g., `\??\C:\...`), and structured attributes. A few high-frequency patterns:

* **Object opens**: `UNICODE_STRING` + `OBJECT_ATTRIBUTES` + desired access → handle.
* **Memory ops**: base address **by reference**, region size **by value**, protection/state as flags; the kernel may adjust alignment.
* **I/O**: `IO_STATUS_BLOCK` carries result codes/bytes transferred; synchronous vs. alertable I/O matters.
* **Process/thread:** rights drive feasibility; `PROCESS_VM_WRITE | PROCESS_VM_OPERATION` for writing, `CREATE_THREAD` for remote thread creation.

```c
// Minimal direct allocation + protection flip via NT calls
typedef NTSTATUS (NTAPI *PFN_NtAllocateVirtualMemory)(HANDLE,PVOID*,ULONG_PTR,PSIZE_T,ULONG,ULONG);
typedef NTSTATUS (NTAPI *PFN_NtProtectVirtualMemory)(HANDLE,PVOID*,PSIZE_T,ULONG,PULONG);

PFN_NtAllocateVirtualMemory NtAlloc = (PFN_NtAllocateVirtualMemory)
    GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtAllocateVirtualMemory");
PFN_NtProtectVirtualMemory NtProt = (PFN_NtProtectVirtualMemory)
    GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtProtectVirtualMemory");

PVOID base = NULL; SIZE_T sz = 0x2000; ULONG oldProt = 0;
NtAlloc(GetCurrentProcess(), &base, 0, &sz, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
// ... write payload ...
NtProt(GetCurrentProcess(), &base, &sz, PAGE_EXECUTE_READ, &oldProt);
FlushInstructionCache(GetCurrentProcess(), base, sz);
```

**Analyst note:** the NT path is where **dynamic code** shows up first; defenders join `NtProtectVirtualMemory` with **VAD provenance** (Image/Mapped/Private) to separate benign from malicious.

### Direct syscalls and hook evasion

“Direct syscall” means **calling the `syscall` instruction yourself** (bypassing hooked `kernel32`/`ntdll` prologues) but still using the **OS’s numbers and contracts**. Pro: evades naive user-mode hooks. Cons:

* **Fragility:** service numbers change across builds; stub layouts change.
* **Coverage gaps:** ETW and kernel sensors still see the call; only user-mode shims are skipped.
* **Suspicion:** unusual stub addresses or short trampolines are good hunting indicators.

Practical approaches:

* Resolve numbers at runtime by reading `ntdll` (don’t hardcode).
* Keep a vetted syscall set; avoid rarely used services that fingerprint your tool.

### Observability: call stacks, ETW, and triage

* **ETW/ImageLoad/Process/Thread + Nt* providers*\* give high-fidelity join points: “who”, “what object”, “with which rights”.
* **Stack provenance:** if `NtOpenProcess` is reached via a tiny unmanaged stub in **private RX**, that is different from a normal `kernel32→ntdll` path.
* **Return codes:** `STATUS_ACCESS_DENIED` during repeated `NtOpenProcess` to LSASS followed by success → token change or privilege escalation.

```text
; WinDbg commands to anchor investigations
!process 0 1                  ; find target PID
.kframes 2                    ; show user-mode frames
kb                             ; check stub callers (kernel32/ntdll vs. custom region)
!handle 0 3                   ; joins with NtOpen*/NtCreate* outcomes
```

## Why this matters for exploitation / anti-exploit / malware analysis

Attackers operate where **policy** and **capability** meet: the NT boundary. Anti-exploit stacks that only hook Win32 miss direct NT and WoW64 paths; analysts who reason in **NT terms** explain outcomes precisely (which access bits failed, which object path resolved). Defenders that join **NT calls + object types + tokens + memory provenance** catch attacks *before* payload logic succeeds.

## APIs and functions

* `NtOpenProcess` / `NtOpenThread` – obtain handles with precise rights; gateway to injection/hijack.
* `NtAllocateVirtualMemory` / `NtProtectVirtualMemory` – carve and transition memory; watch W→X and provenance.
* `NtCreateFile` / `NtOpenFile` – open/create by NT path; eliminates DOS-path ambiguity.
* `NtMapViewOfSection` – map image/data sections; common in manual mapping and shared memory.
* `NtCreateUserProcess` – native process creation with attribute blocks; parent spoofing/mitigations live here.
* `NtQuerySystemInformation` – enumerate processes/handles/modules via native views.
* `NtSetInformationThread` – hide-from-debugger flags, affinity, impersonation adjuncts.
* `RtlInitUnicodeString` / `InitializeObjectAttributes` – helpers for clean parameter packing.

## Pitfalls, detection notes, and anti-analysis gotchas

* **Return code confusion:** `NTSTATUS` is not `GetLastError`; always use `NT_SUCCESS(s)` and map status via `RtlNtStatusToDosError` if needed.
* **Service-number brittleness:** build updates break hardcoded syscall numbers; resolve them dynamically or call the export by name.
* **WoW64 blinders:** x64 hooks miss x86 callers; attach the right debugger and symbol set.
* **Path translation traps:** `CreateFileW` DOS paths may resolve through reparse points; validate the final **NT path** seen by `Nt*`.
* **“Direct syscall” ≠ stealth:** kernel ETW still records the operation; only superficial hooks are skipped.
* **Struct layout drift:** avoid hand-rolled `OBJECT_ATTRIBUTES` with wrong `Length`; use `InitializeObjectAttributes`.
* **Guarded returns:** some sandboxes instrument `syscall` entry/exit; timing or unusual stubs may raise flags.
* **Page provenance matters:** `NtProtectVirtualMemory` to RX on **Private** memory is far more suspicious than on **Image** memory.

## Cross-references

* Handle semantics and object paths are detailed in **Object Manager & Handles** (Part 1).
* Memory provenance and W→X implications appear in **Memory & Virtual Address Space** (Part 1).
* Loader visibility vs. manual maps and section mapping mechanics are in **Windows Loader & Image Activation** (Part 1).
* Mitigation interactions (DEP/NX, CFG/CET) that can block or redirect control flow are in **DEP / NX / W^X** and **Compiler & Hardware CFI: CFG, CET (Shadow Stack/IBT)** (Part 2).
* Evasion strategies that lean on this boundary (unhooking, direct syscalls) continue in **Telemetry Tampering & Unhooking (ETW, Direct Syscalls)** (Part 3).

## Glossary

* **NTAPI**: Native API exported by `ntdll` that marshals user-mode calls into kernel syscalls.
* **SSDT**: System Service Descriptor Table mapping service numbers to kernel routine addresses.
* **WoW64**: Thunking layer for 32-bit processes on 64-bit Windows; inserts extra user-mode hops.
* **`NTSTATUS`**: Status code type returned by NT routines; use `NT_SUCCESS` to test.
* **Service Number**: Build-specific index selecting a kernel service from the SSDT.
* **`OBJECT_ATTRIBUTES`**: Structure describing name, root directory, attributes for object opens.
* **`UNICODE_STRING`**: Length-prefixed UTF-16 string used by NT routines.
* **Direct Syscall**: Issuing `syscall` directly (custom stub) rather than calling `ntdll` exports.
* **Provenance (VAD Type)**: Whether memory is Image/Mapped/Private; crucial to evaluate `NtProtect*` activity.
* **ETW**: Event Tracing for Windows; records process, image, and native operation telemetry.

## Key takeaways

* The **NT boundary** is the ground truth for access and policy; learn to speak in `Nt*` calls, **NTSTATUS**, and **NT paths**.
* **Direct syscalls** only dodge superficial hooks; kernel telemetry still tells the story.
* Service numbers are **per-build**; prefer resolving from `ntdll` at runtime or calling by name.
* Always pair a syscall with **object/type + rights + provenance** to judge intent, not just API names.
* WoW64 adds an extra thunk; match bitness in tooling, hooks, and analysis.

