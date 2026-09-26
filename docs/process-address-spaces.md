# Process attachment and cross-process memory

This pass separates thread ownership from the process whose address space the
thread is currently using. Merely changing KAPC_STATE.Process is insufficient:
guest instructions, host API adapters, scheduler resume, and fault handling must
all select the same address space.

## Contract and acceptance criteria

Each KeStackAttachProcess call, including a same-process call, has a matching
KeUnstackDetachProcess. Nested calls restore in reverse order using the exact
caller-supplied KAPC_STATE. The host retains authoritative attachment records and
strong references to the relevant process/address-space objects. Guest memory
does not supply a trusted host process pointer. Invalid targets, state reuse,
unmatched/out-of-order detach, invalid IRQL, and termination while attached must
fail explicitly rather than leave mismatched APC and page-table state.

Both APIs require IRQL below DISPATCH_LEVEL. Attachment does not change thread
ownership: PsGetCurrentProcessId and PsGetThreadProcess continue identifying the
creator/owner, while PsGetCurrentProcess and IoGetCurrentProcess identify the
effective attached process. IRQL and APC-disable counters are preserved.

The backend switches actual guest page tables and invalidates translations.
Scheduler resume must retain the attachment. Shared kernel mappings keep kernel
code and stacks available while the user half changes. SMAP remains enabled;
kernel code performing direct user-memory accesses must use the architecture's
normal access mechanism rather than relying on a global protection bypass.

Callbacks must return with their incoming attachment state intact. An unbalanced
return stops emulation. Failure cleanup restores the incoming address space and
APC state, including callbacks originating from user syscalls.

## Copy boundary

MmCopyVirtualMemory uses seven native arguments and a required byte-count output.
Nt/ZwReadVirtualMemory and Nt/ZwWriteVirtualMemory use five arguments and an
optional count output. The native handle model requires PROCESS_VM_READ (0x10)
or PROCESS_VM_WRITE (0x20), respectively. This follows the referenced ReactOS
native implementation; it is not the distinct Win32 WriteProcessMemory wrapper's
documented VM_WRITE plus VM_OPERATION requirement.
User callers cannot use OBJ_KERNEL_HANDLE process handles for either transfer.

Source and destination are resolved independently. User ranges require readable
source and writable destination metadata plus actual mapped backing. Kernel-mode
kernel buffers require mapped backing; the current MMU host-access abstraction
does not expose a complete kernel permission probe. UserMode requests must not
access kernel addresses. Output counts belong to the initiating caller's address
space and must be validated before payload mutation.

The intended bounded-copy model transfers page-bounded chunks and reports the
valid prefix: complete transfer is success, a fault after progress is
STATUS_PARTIAL_COPY, and a zero-progress inaccessible transfer is an access
violation. Overflow and user-range limits are checked before copying. This is
an explicit emulator contract, not a claim of exact undocumented Windows
validation order. A multi-page copy is not an atomic snapshot.

Nt calls use the thread's PreviousMode, including kernel callbacks originating
from user calls. A distinct kernel Zw entry forces KernelMode; an ntdll alias
called from user mode does not. The pinned kernel does not export the four
Nt/Zw read/write entry points, so the conformance subjects exercise their real
ntdll syscall stubs instead of introducing synthetic kernel exports.

Nt/ZwOpenProcess now supports live process IDs with the existing object-handle
callback path. It captures and probes input structures, rejects unsupported
named/thread-ID forms and user requests for kernel handles, and rechecks output
permissions when publishing after callbacks. This preserves callback access
reductions and closes a newly created handle if output publication fails. It
does not implement token-based process access checks or security descriptors.

## Current limits

The attachment model requires empty APC queues and shared backing for the kernel
continuation and saved state. It rejects unsupported cases before switching.
It does not add general propagation of newly allocated kernel root-table slots.
Cross-process copy rejects copy-on-write destinations instead of materializing
private pages, and rejects guarded pages without consuming the guard. Ordered
VM metadata locks stabilize permission checks during transfer, but do not make
the copied contents an atomic snapshot. Process handles still use the existing
global handle table. Multi-vCPU behavior and ARM64 execution are not validated
by the x64 Hyper-V fixtures.

The Hyper-V instruction-hook implementation can expose its internal TF bit to
guest PUSHFQ. The fixture masks TF when enabling/restoring AC around direct
user-memory accesses, so it does not replay the backend's single-step flag.
This is a fixture accommodation, not a fix for general guest flag transparency.

## Verification design

The positive guest fixture uses two processes with different values at the same
virtual address. It checks actual guest reads/writes through nested attachments,
same-process nesting, restoration, identity, and a scheduler yield while attached.
It also exercises explicit cross-process copies, process-handle access rights,
protected/inaccessible pages, partial byte counts, and native ring-3 completion.
Negative fixtures cover invalid detach order, reused state, invalid IRQL/target,
callback imbalance/failure, and termination while attached. ExNotifyCallback
also has dedicated cases for an attachment leak and an attempt to detach an
attachment owned by its caller. Guest-call boundaries apply a shared checkpoint
adapter so comparator, exception, I/O, timer, and generic callbacks cannot leave
host attachment records inconsistent with the restored address space.

All drivers and native user programs run only as inputs to kernemul. They are
never installed as host drivers or launched as native host executables.

## Validation record

The initial positive fixture on the prior executable failed effective-process
identity and target allocation (`attach-20260926-141432-641.json`). On the new
Release executable, after the TF fixture correction, all kernel assertions
passed (`attach-20260926-142422-777.json`); native subjects exposed the missing
NtOpenProcess handler. After implementing and validating that handler, the
complete fixture passed (`attach-20260926-143142-116.json`): 65 kernel PASS
assertions, both native subjects exited with 0xA11C, and no unexpected runtime
faults or missing syscalls. All ten attachment negative cases passed
(`attach-negative-20260926-143150-973-*`), including ExNotifyCallback imbalance
and caller-frame protection. Callback imbalance/failure records confirm rollback.

The 11 host model tests passed (`attach-model-tests.log`). Existing guest
regressions passed: process notification (`process-notify-20260926-142206-226`),
all eight process negative cases (`process-negative-20260926-142214-384-*`),
OB user callbacks (`ob-user-20260926-142223-213`), registry notification and
boundaries (`registry_notify_conformance-20260926-142236-222`,
`registry_notify_boundaries-20260926-142240-896`), and image notification and
boundaries (`image_notify_conformance-20260926-142246-070`,
`image_notify_boundaries-20260926-142250-859`). Logs and JSON manifests reside
under `build-conformance/`.

After extending guest-call checkpoints, callback, timer, thread-notification,
thread-owner, and CI conformance passed (`*-20260926-143210` through
`*-20260926-143215` manifests). All 22 generic negative cases passed
(`negative-*-20260926-143221` through `*-20260926-143230`). Independent review
identified and drove fixes for the generic callback boundary and user access
through kernel-only handles.

The final kernel-handle regression also passed (`attach-20260926-143551-123.json`):
69 kernel PASS assertions and both native exits 0xA11C. The final generic
Release executable is preserved in
`build-conformance/process-address-spaces-generic-20260926/kernemul.exe`, SHA256
`362BCCBCEB88D2B3E78FB0AF70BF85843FD91230C36B628825E2C00A85F2DDAC`.
Independent review reported no outstanding material findings after both fixes.

## Sources

- [KeStackAttachProcess](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-kestackattachprocess)
- [KeUnstackDetachProcess](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-keunstackdetachprocess)
- [Owner PID versus attached process](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psgetcurrentprocessid)
- [Process identity](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psgetprocessid)
- [Memory protections](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [ReactOS native memory interfaces and copy implementation](https://doxygen.reactos.org/d2/dfa/ntoskrnl_2mm_2ARM3_2virtual_8c.html)
- [Process access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
