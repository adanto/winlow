# Part 1 – Fundamentals: IPC (ALPC, RPC, COM, Pipes)

**What this chapter covers**

* The main Windows IPC families—**ALPC, RPC, COM, and Named Pipes**—and how they relate
* Security boundaries: object namespaces, SDDL/DACLs, impersonation levels, and capability-based brokering
* Practical attacker/defender patterns: client spoofing, potato-style relays, side-loading via brokers
* Fast triage: where to look (namespace paths, endpoints, ETW) and which fields matter (SIDs, ILs, rights)
* Minimal examples to anchor terms (pipe server/client, COM activation)

## Core concepts

### IPC is capability transfer, not “just messages”

All IPC winds up as **object + identity + method**: a client asks a **server** (often a service) to do work through an endpoint object. The **Object Manager** hosts many of these endpoints under `\BaseNamedObjects`, `\RPC Control`, and device stacks. Access checks use your **token** (integrity, groups, privileges) against the endpoint’s **security descriptor**; some systems (COM/RPC) then **impersonate** or **broker** the operation.

**Mental model:** think “who am I?” (token), “what object did I reach?” (endpoint name, DACL), and “what exactly will run?” (server identity, thread/token after impersonation).

---

### ALPC: the OS’s fast local mailbox

**ALPC (Advanced Local Procedure Call)** is the kernel’s high-performance local IPC. User-mode code seldom calls ALPC directly; **RPC** and **COM** frequently ride on top of ALPC for in-box services. ALPC endpoints live as objects in `\RPC Control\…` (via RPC runtime) or as raw ALPC ports. Messages carry small payloads and handles; security is enforced by the port’s **SDDL** and per-message impersonation decisions.

**Analyst tip:** enumerate `\RPC Control` for active RPC/ALPC-backed endpoints; unexpected world-writable ports are red flags.

```text
; WinDbg snapshot of namespace surfaces you’ll inspect
!object \BaseNamedObjects
!object \RPC Control
!handle 0 3 type Event | type Section | type ALPC Port   ; scope per PID for signal/transfer primitives
```

---

### RPC: IDL contracts, endpoints, and impersonation levels

**Microsoft RPC** exposes **procedures** defined in IDL and served at **endpoints** (ALPC, named pipe, TCP). Calls serialize parameters (NDR), reach a server stub, and (optionally) **impersonate** the client on the server thread. Impersonation levels matter:

* **Anonymous / Identify / Impersonate / Delegate**: only **Impersonate** gives the server the client’s access on local resources; **Delegate** allows constrained delegation to remote hops.
* Endpoint security is separate from object security—**binding** might succeed, but the server may reject or impersonate at a lower level.

```c
// Minimal RPC client skeleton (local ALPC/NP binding from a string; error checks omitted)
#include <Rpc.h>
#pragma comment(lib, "Rpcrt4.lib")
int main() {
    RPC_WSTR s = (RPC_WSTR)L"ncalrpc:[My.Alpc.Endpoint]"; // or "ncacn_np:127.0.0.1[\\pipe\\MyPipe]"
    RPC_BINDING_HANDLE h = NULL;
    RpcBindingFromStringBindingW(s, &h);
    // …call generated stub: MyInterface_MyOp(h, …) …
    RpcBindingFree(&h);
    return 0;
}
```

**Security note:** “potato”-style local privilege escalations exploit misconfigured servers that accept low-privilege clients and then perform privileged file/service actions while **impersonating SYSTEM** (or by triggering **NTLM relay** to a higher-privilege identity). Correct **SDDL** and strict impersonation levels choke these off.

---

### COM: activation + marshaling + security descriptors

**COM** builds on RPC (DCOM for remote) and adds **activation** (create an object by CLSID), **marshaling**, and **security policy** (launch/access permissions, **AppID**-scoped SDDL). Servers can run **in-proc** (DLL), **local server** (EXE), or **service**. COM security has two orthogonal knobs:

* **Launch/Activation permissions**: who may start a server (DACL on AppID).
* **Access permissions**: who may call into existing objects (DACL on AppID or per-object).
* **Impersonation**: set via `CoInitializeSecurity`/proxies; typical is **Impersonate**.

```powershell
# Quick COM activation check (PowerShell)
$sh = New-Object -ComObject "Shell.Application"
$sh.NameSpace("$env:WINDIR").Self.Name  # simple method call
```

**Abuse themes:** launch a **high-IL** COM server from **medium-IL** and convince it to perform privileged filesystem/registry operations, or locate an **auto-elevating** COM class (under UAC) that lacks capability checks. WDAC/AppContainer reduce the blast radius by restricting activation and token capabilities.

---

### Named Pipes: versatile, visible, and easy to get wrong

**Named Pipes** live under the **NPFS** filesystem (`\\.\pipe\Name`). They support **message** or **byte** modes, multiple instances, and optional **server impersonation** of the client.

```c
// Tiny Named Pipe server + client in one process (demo only; error checks omitted)
#include <windows.h>
int main() {
    HANDLE srv = CreateNamedPipeW(L"\\\\.\\pipe\\DemoPipe",
        PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1, 4096, 4096, 0, NULL);
    ConnectNamedPipe(srv, NULL); // blocks until a client connects (in real code, run client in another process)
    ImpersonateNamedPipeClient(srv);  // server now runs with client’s token (if allowed)
    // …do work, then…
    RevertToSelf(); DisconnectNamedPipe(srv); CloseHandle(srv);
    return 0;
}
```

**Hard rules for pipes:**

* The **server** must call `ImpersonateNamedPipeClient` before performing privileged filesystem/registry work “for” the client.
* Lock down the **pipe SDDL** so untrusted callers cannot connect; default everyone-writable pipes invite trouble.
* Defenders watch `\\.\pipe\` names (heuristics for LOLBins and common malware kits), **server impersonation calls**, and **token transitions** around pipe transactions.

---

### Brokering: least privilege via helper processes

Modern apps/services split privileges: a **broker** (High IL or SYSTEM) receives requests from a **low-IL** client via ALPC/RPC/COM/pipes and enforces a **capability contract** (“open file under Downloads only, read-only”). This is how **Edge/Chromium**, **AppContainer** apps, and EDRs work. Correct brokering validates **call origin** (PID/SID/IL), **arguments**, and forces **allow-lists** of file/registry destinations.

**Hunting idea:** requests that escape the expected sandbox (e.g., broker writing outside profile paths) usually show up as **mismatched SIDs/ILs** joined to the IPC transaction.

---

### Quick posture triage

* **Endpoint name and path** (`\RPC Control\…`, `\\.\pipe\…`, CLSID/AppID): does it exist? who owns it? SDDL?
* **Impersonation level**: Identify vs. Impersonate vs. Delegate—too permissive?
* **Server identity**: which service/process actually handles the call? (ETW: RPC/ALPC/DCOM providers)
* **Client token**: what IL/groups/privileges did the server run under while handling the call?
* **Argument allow-lists**: volumes/keys/verbs outside the contract are suspicious.

## Why this matters for exploitation / anti-exploit / malware analysis

Most local privilege escalations, sandbox escapes, and stealthy lateral moves ride IPC. Attackers seek **high-privilege brokers** with weak SDDL or sloppy impersonation. Defenders that join **endpoint → server process → client token → performed action** cut through noise quickly. Analysts who can map **namespace paths** and **security descriptors** to actual **code paths** resolve whether an observed call is expected brokering or an exploit chain.

## APIs and functions

* `RpcBindingFromStringBinding` / `RpcBindingFree` – create/destroy client bindings to RPC endpoints.
* `CoCreateInstance` / `CoGetClassObject` – COM activation (in-proc/local/server).
* `CoInitializeSecurity` – set COM process-wide security (authentication, impersonation level).
* `CreateNamedPipeW` / `ConnectNamedPipe` – create and accept clients on NPFS endpoints.
* `ImpersonateNamedPipeClient` / `RevertToSelf` – assume/release client identity on server threads.
* `NtAlpcConnectPort` / `NtAlpcSendWaitReceivePort` – native ALPC connect and message round-trips.
* `SetSecurityInfo` / `ConvertStringSecurityDescriptorToSecurityDescriptor` – assign/read SDDL on objects.
* `LdrRegisterDllNotification` – image notifications usable for lazy binding to IPC loads (analysis hook).

## Pitfalls, detection notes, and anti-analysis gotchas

* **World-writable endpoints:** `D:(A;;GA;;;WD)` on a pipe or ALPC port invites low-IL code to reach a high-privilege broker.
* **No impersonation in server:** doing privileged I/O without `Impersonate*` executes as SYSTEM—clients can steer writes/links (classic potato class).
* **RPC/COM misleveling:** allowing **Delegate** when not needed lets identities hop farther than intended.
* **Namespace confusion:** `CreateFileW` DOS paths can traverse reparse points—servers must canonicalize to **NT paths** and validate against allow-lists.
* **ETW blind spots:** some sandboxes disable providers; build your own sampling (client + server logs) when testing.
* **Cross-session endpoints:** names can be per-session; the same pipe name may resolve differently—verify session IDs.
* **WOW64 marshaling bugs:** 32/64-bit callers marshal different struct sizes; mismatches cause silent truncation or overreads.
* **Message pump reentrancy:** COM STA and GUI hooks run *inside* message loops; long operations deadlock UIs and skew timing.

## Cross-references

* Handle semantics and namespace resolution are explained in **Object Manager & Handles** (Part 1).
* Creating suspended processes and queuing APCs to service threads intersects with **Scheduling, APCs & Callback Surfaces** (Part 1).
* NT marshalling, direct syscalls, and ALPC primitives are in **Syscalls & the NTAPI Boundary** (Part 1).
* Memory provenance for injected IPC stubs (private RX vs. image) ties to **Memory & Virtual Address Space** (Part 1).
* Trust boundaries (WDAC, PPL, AppContainer, HVCI) that constrain brokers are detailed in **Trust & Integrity: Secure Boot, WDAC/App Control, Code Integrity, PatchGuard, VBS/HVCI, PPL** (Part 2).
* Offensive uses (RPC/COM abuse, pipe impersonation, ALPC gadgets) continue in **Process Injection & Hooking** and **Telemetry Tampering & Unhooking (ETW, Direct Syscalls)** (Part 3).

## Glossary

* **ALPC**: Kernel-local message-passing IPC used by OS components and runtimes (fast, handle-passing).
* **RPC**: IDL-based remote procedure call framework; endpoints over ALPC, NPFS, TCP; supports impersonation.
* **COM**: Component Object Model; activation and marshaling atop RPC; governed by AppID security.
* **Named Pipe (NPFS)**: Filesystem-backed duplex channels under `\\.\pipe\…`.
* **Endpoint**: Named IPC listening point (port/pipe/CLSID) that accepts client bindings.
* **Impersonation Level**: Degree to which a server may act as the client (Identify/Impersonate/Delegate).
* **Broker**: Higher-privilege process that performs restricted work for a low-privilege client under policy.
* **SDDL**: String form of a security descriptor; used to define DACL/SACL on endpoints.
* **AppContainer**: Sandbox model with capability SIDs limiting IPC scope and resource access.
* **NDR**: Network Data Representation; RPC’s parameter encoding format.

## Key takeaways

* Treat IPC as **capability transfer**: endpoint security + impersonation level decide impact.
* Map calls from **endpoint name → server process → effective token → performed action** to separate benign brokering from abuse.
* Lock down **SDDL** and demand **Impersonate** only when necessary; avoid **Delegate** unless absolutely required.
* For hunting, join **endpoint creation**, **client connect**, **impersonation**, and **privileged I/O** in ETW.
* In PoCs, keep server callbacks minimal and validate **canonical NT paths** against allow-lists to avoid self-owning bugs.
