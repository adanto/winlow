# Part 3 – Process Injection & Hooking

**What this chapter covers**

* The main injection families (CreateRemoteThread, APC, image mapping, handle duplication, COM/CLR) and what they buy
* Hooking primitives (IAT/EAT, inline/trampoline, VEH/SEH, user-mode callbacks) and their modern constraints (CFG/CET/ACG)
* Memory provenance and policy interactions (W→X flips, Private RX vs. Image RX, PPL/WDAC/VBS)
* Triage and hunting: what to log, where to look, and how to separate benign shims from covert loaders

## Core concepts

### Injection = identity + memory + execution

All Windows injection collapses to three steps:

1. **Gain a handle** to a target (identity): `OpenProcess`, duplicated handle, broker.
2. **Place bytes** in target memory (content): `WriteProcessMemory`, section map, image load, JIT.
3. **Transfer control** (execution): remote thread, APC, queue/timer/callback, hijacked thread.

The **how** varies, but the **graph** (caller → target → code provenance → resulting token) is what analysts track.

---

### Remote thread injection (classic, noisy, durable)

Create a region in the remote, write code/parameters, start a thread at your chosen PC.

```c
// Shape-only, with error-checking omitted: classic CreateRemoteThread pattern (no shellcode)
#include <windows.h>
int inject(HANDLE hp, const wchar_t* dllPath) {
    SIZE_T len = (wcslen(dllPath)+1)*sizeof(wchar_t);
    void* rbuf = VirtualAllocEx(hp, NULL, len, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(hp, rbuf, dllPath, len, NULL);
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC load = GetProcAddress(k32, "LoadLibraryW");
    HANDLE ht = CreateRemoteThread(hp, NULL, 0, (LPTHREAD_START_ROUTINE)load, rbuf, 0, NULL);
    WaitForSingleObject(ht, INFINITE);
    return 0;
}
```

**Reality:** easy to spot in ETW (new thread start at `kernel32!LoadLibraryW`), often blocked by **PPL**, **AppContainer** boundaries, or **WDAC** (if the DLL is unapproved). With **ACG**/dynamic code policy, even allocating RX is constrained.

---

### APC/Early-bird: thread hijack without new threads

Queue an **APC** to a target thread in an **alertable** state; the thread runs your routine on return from a wait. “Early-bird” queues before the main thread calls `ResumeThread`, so the APC runs early in process startup.

```c
// Shape-only: APC queuing for benign LoadLibraryW
void apc_inject(HANDLE hProc, HANDLE hThread, const wchar_t* dll){
    LPVOID r = VirtualAllocEx(hProc, NULL, 4096, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(hProc, r, dll, (wcslen(dll)+1)*sizeof(wchar_t), NULL);
    PTHREAD_START_ROUTINE load = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"kernel32"), "LoadLibraryW");
    QueueUserAPC((PAPCFUNC)load, hThread, (ULONG_PTR)r); // requires alertable waits
}
```

**Why attackers like it:** no new thread creation. **Tell:** `QueueUserAPC` + an RX/parameter region and a later `NtTestAlert`/alertable wait. CFG/CET do not forbid LoadLibrary; policy and provenance still expose it.

---

### Section mapping / “Process hollowing”

Instead of writing bytes directly, create a **section** (file-backed or pagefile-backed), map it into the remote, then set the thread context to your entry. For “hollowing,” create a suspended process, unmap its image, map your own, fix PEB and context, resume.

**Why it works:** avoids `WriteProcessMemory` and looks more like a loader. **Tell:** `NtCreateSection`/`NtMapViewOfSection` across processes, `ZwUnmapViewOfSection` of the original image, thread context changes. Missing **unwind/CFG** metadata often betrays crude mappers.

---

### Image load without the loader (manual mapping)

Copy PE sections to the target, apply relocations/imports yourself, register **unwind** and **CFG** call targets, then start. Modern Windows adds friction:

* **CFG** requires indirect-call targets to be registered if you use them;
* **CET-IBT** wants **ENDBR64** at indirect-entry stubs;
* **EH** requires **RtlAddFunctionTable** for exceptions.

Manual maps that skip this **crash under pressure**—good detection anchors.

---

### Handle-before-content: token & PPL boundaries matter

If the target is **PPL** or runs under a stronger signer, `OpenProcess` will fail even with `SeDebugPrivilege`. EDR/user-mode sensors may run PPL-*Antimalware*. **AppContainer**, **IL**, and **capabilities** further limit cross-process actions. Analysts should always record **why a handle succeeded** (privileges, identity) before judging content.

---

### Hooking ≠ injection, but often co-travelers

Hooking replaces or interposes control flow locally (same process) to:

* Redirect execution (inline/trampoline hooks)
* Rewrite import targets (IAT/EAT hooks)
* Use exception machinery (VEH/SEH) to detour on faults
* Install global GUI hooks (`SetWindowsHookEx`) for user sessions

#### IAT hook (surgical and stable if done right)

```c
// Shape-only: patch IAT entry for MessageBoxW to a local stub
#include <windows.h>
typedef int (WINAPI *PFN_MBW)(HWND,LPCWSTR,LPCWSTR,UINT);
int WINAPI MyMsgBox(HWND a,LPCWSTR t,LPCWSTR c,UINT f){ return 0; }

void hook_iat(HMODULE mod){
    ULONG size=0; PIMAGE_IMPORT_DESCRIPTOR imp = (PIMAGE_IMPORT_DESCRIPTOR)
        ImageDirectoryEntryToData(mod, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size);
    for (; imp->Name; ++imp){
        LPCSTR dll = (LPCSTR)((BYTE*)mod + imp->Name);
        if (_stricmp(dll, "user32.dll")) continue;
        PIMAGE_THUNK_DATA orig = (PIMAGE_THUNK_DATA)((BYTE*)mod + imp->OriginalFirstThunk);
        PIMAGE_THUNK_DATA iat  = (PIMAGE_THUNK_DATA)((BYTE*)mod + imp->FirstThunk);
        for (; orig->u1.AddressOfData; ++orig, ++iat){
            PIMAGE_IMPORT_BY_NAME nm = (PIMAGE_IMPORT_BY_NAME)((BYTE*)mod + orig->u1.AddressOfData);
            if (!strcmp((char*)nm->Name, "MessageBoxW")){
                DWORD old; VirtualProtect(&iat->u1.Function, sizeof(void*), PAGE_READWRITE, &old);
                iat->u1.Function = (ULONGLONG)MyMsgBox;
                VirtualProtect(&iat->u1.Function, sizeof(void*), old, &old);
                return;
            }
        }
    }
}
```

**Modern friction:** **CFG** may guard **indirect** calls, but IAT is usually **direct-called**. **CET-IBT** is not triggered if the callsite is direct. Defenders focus on **unexpected IAT writes** and module provenance.

#### Inline/trampoline hooks (fragile under CET)

Overwrite a function prologue with a jump to your stub, optionally preserving original bytes as a **trampoline**. On CET-IBT systems, indirect entries require **ENDBR64**; prologue mangling can break landing pads and CFG thunks. Hotpatching should preserve **unwind** and any **CFI** metadata.

---

### CLR/COM-assisted “legit” injection

Use the **CLR hosting** APIs to execute managed code inside another process or instantiate **auto-elevating COM** classes to perform work elsewhere. These paths look “approved” and can inherit **better telemetry lineage**. Defenders should attribute the **server** (CLR/COM host) performing the action, not the small stub that initiated it.

---

### Why this matters for exploitation / anti-exploit / malware analysis

Injection and hooking are how payloads gain **persistence**, **context**, and **stealth** after initial code execution. Attackers choose the primitive that fits **policy** (PPL/WDAC), **mitigations** (CFG/CET/ACG), and **telemetry** (which path is least noisy). Defenders who join **handle acquisition → memory provenance → control transfer** can explain nearly all families—no matter the obfuscation.

## APIs and functions

* `OpenProcess` / `DuplicateHandle` — acquire cross-process handles (gates by IL/PPL/token).
* `VirtualAllocEx` / `WriteProcessMemory` — stage content in a remote process.
* `CreateRemoteThread` / `NtCreateThreadEx` — start remote execution (noisy but reliable).
* `QueueUserAPC` / `SetThreadContext` / `ResumeThread` — hijack existing threads; “early-bird” flow.
* `NtCreateSection` / `NtMapViewOfSection` — map code/data into a remote; hollowing, section-based injection.
* `RtlAddFunctionTable` / `SetProcessValidCallTargets` — required plumbing for manual maps under unwind/CFG.
* `SetWindowsHookEx` — user-session hooks; abuse for code loading in GUI processes.
* `LdrLoadDll` / `GetProcAddress` — delayed resolution inside the target; common in lightweight stagers.

## Pitfalls, detection notes, and anti-analysis gotchas

* **Private RX ≠ evil by itself:** JITs and profilers also create Private RX; join with **who** wrote it and **what** executed next.
* **ACG/Dynamic Code Policy:** blocks creating/altering RX in many estates; failed `VirtualProtect`/`WriteProcessMemory` to RX is a strong signal.
* **PPL surprises:** `SeDebugPrivilege` does not pierce **PPL**; failed `OpenProcess` on LSASS is normal on hardened hosts.
* **CET/CFG collisions:** missing **ENDBR** or unregistered call targets in manual maps cause fail-fast; don’t mislabel as “random crash.”
* **WOW64 confusion:** cross-bitness injection needs the right `ntdll`/thunks; an x86 injector can’t call x64 `LoadLibraryW`.
* **IAT races:** patching while another thread executes the callsite yields heisenbugs; suspend or patch atomically.
* **Telemetry tunnel vision:** user-mode hook evasion (direct syscalls) still triggers **kernel** events; prefer NT-layer telemetry for truth.
* **Handle reuse:** duplicated handles from a brokered process alter lineage; record **source process** for the handle.

## Cross-references

* Memory permission flips and provenance are discussed in **DEP / NX / W^X** and **Memory & Virtual Address Space**.
* CFG/CET constraints on trampolines and indirect calls: **Compiler & Hardware CFI: CFG, CET (Shadow Stack/IBT)**.
* Loader behavior and image mapping, including manual maps: **Windows Loader & Image Activation**.
* Token boundaries, PPL, and trust enforcement: **Trust & Integrity: Secure Boot, WDAC/App Control, Code Integrity, PatchGuard, VBS/HVCI, PPL**.
* APC timing and scheduler surfaces: **Scheduling, APCs & Callback Surfaces**.
* Evasion context (hook detection, user-mode unhooking): **Anti-Reversing & Evasion** and **Telemetry Tampering & Unhooking (ETW, Direct Syscalls)**.

## Glossary

* **Process injection**: Introducing code into another process and executing it to gain its context/identity.
* **Hollowing**: Replacing a suspended process’s image with another, then resuming.
* **APC injection**: Executing a function in a target thread by queuing an APC that runs during alertable waits.
* **Manual mapping**: Loading a PE into memory without the loader’s bookkeeping.
* **IAT/EAT hook**: Rewriting import/export tables to redirect calls.
* **Inline hook**: Overwriting function prologue with a jump to a trampoline/stub.
* **Private RX**: Executable, anonymous memory region not backed by an image.
* **CFI metadata**: Data (CFG call targets, ENDBR, unwind info) required for stable execution under modern mitigations.
* **PPL**: Protected Process Light; restricts who may open/inject/debug a process.
* **ACG**: Dynamic Code policy that restricts creating or modifying executable memory.

## Key takeaways

* Model every case as **handle → memory → execution** and record **identity** at each hop; obfuscation cannot hide that graph.
* Prefer **provenance** and **sequence** over strings: W→X, section map, thread start/APC are your high-signal joins.
* Modern mitigations (ACG/CFG/CET/PPL/WDAC) don’t forbid injection outright, but they make **sloppy** techniques fail fast—use those crashes as detectors.
* Differentiate **legitimate shims/JITs** from covert loaders with metadata: unwind tables, call-target registration, signer/policy context.
* In labs, test both **x86/WOW64** and **x64** paths and collect **ETW at the NT layer** to survive user-mode hook games.
