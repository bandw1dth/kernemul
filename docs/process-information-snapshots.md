# Coherent process and thread system-information snapshots

This pass replaces the fabricated class-5 `SystemProcessInformation` handle
counts and single-thread records with the emulator's process, handle-table, and
thread lifecycle state. The preceding
[fifteen-minute kernel capture](vgk-kernel-15-minute-analysis.md) exercised this
query repeatedly and established the inconsistency: the query reported 32 handles
and thread ID `PID + 4` independently of the actual objects.

## Scope and acceptance

- Published processes are reported in active-process-list order. Incomplete or
  unpublished host identities must not become fabricated process records.
- Handle counts come from each process's actual table, including System's
  marked kernel handles. Opening, duplicating, and closing handles change the
  corresponding owner's count.
- Each process is followed by its modeled owned threads. Attachment changes
  execution address space, not the thread's owning process or client ID.
  Seeded processes with no modeled threads report zero threads.
- Thread identities, start addresses, creation times, priorities, and available
  scheduler fields come from modeled thread objects. Unimplemented accounting
  is not replaced with invented activity.
- Process creation time and parent ID reflect the EPROCESS fields maintained
  by the existing user-process creation transaction.
- Snapshot membership is copied under the model's structural locks. No such
  lock spans caller-buffer serialization or guest callback execution. The
  result is a stable value snapshot, not a promise that all runtime counters
  across CPUs were sampled at one instant.
- Variable-length thread arrays and UTF-16 names determine required length and
  eight-byte-aligned next-entry offsets. The final offset is zero. The name's
  advertised `MaximumLength` must fit inside its record, including its terminator.
- Invalid caller buffers produce controlled status failures. Short buffers
  report the current required length without partially emitting records.
  A later query may need more space after a lifecycle change.

## API contract and native boundary observations

The native 64-bit wire format uses a 0x100-byte process header and 0x50-byte
thread records. `Threads[1]` in common header declarations is a variable-array
convenience; its enclosing `sizeof` is not the fixed process-header size.
`UNICODE_STRING` lengths count bytes and its buffer is a guest pointer into the
caller's output allocation. See the Microsoft
[query documentation](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation)
and [UNICODE_STRING definition](https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_unicode_string).

The implementation must preserve
[Nt/Zw caller-mode rules](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-nt-and-zw-versions-of-the-native-system-services-routines).
A real user-mode system call cannot bypass user-buffer checks by using the Zw
name; a kernel Zw thunk supplies KernelMode temporarily.

A read-only native host probe on kernel 10.0.26100.9457 observed the following
class-5 user-mode behavior. This is a nearby build, not the pinned guest kernel
10.0.26100.9444, and does not establish every fault-ordering detail for that guest.
Local evidence is in `build-conformance/system-process-native-probe.json` and
`system-process-native-alignment.json`.

| Inputs | Observed status and writes |
| --- | --- |
| Null output, zero length | INFO_LENGTH_MISMATCH, required length supplied |
| Null output, nonzero length | ACCESS_VIOLATION, ReturnLength unchanged |
| Valid aligned short output | INFO_LENGTH_MISMATCH, output unchanged |
| Output offset 1 or 2, nonzero length | DATATYPE_MISALIGNMENT |
| Output offset 4, nonzero length | Alignment accepted |
| Misaligned output, zero length | Output pointer not probed |
| Invalid non-null ReturnLength | ACCESS_VIOLATION |
| Valid unaligned ReturnLength | Accepted |

Microsoft does not specify all class-5 partial-write, alignment, and competing
fault precedence details. The bounded implementation and fixtures should describe
their behavior without claiming byte-for-byte equivalence across Windows builds.

## Implementation and limits

`win_kernel_state::snapshot_processes()` copies values while holding the process
registry read lock, then the process/thread list lock. It intersects active-list
entries with published host identities, copies each owner's ETHREAD list, and
samples its locked handle-table count. Cycle and size checks bound list traversal.
The resulting records retain no guest views or host lifetime references.

The query then builds a separate zero-initialized byte buffer and releases the
model locks before accessing caller outputs. A non-null ReturnLength and any
nonempty output range are validated before writes. User-mode checks include VM
metadata and page-table permissions; low-address supervisor mappings are not
accepted merely because their addresses lie in the user range. Nt/Zw routing uses
the existing caller-mode handling. Memory/protection failures return status values
instead of escaping as fatal emulator hook exceptions.

Names retain the existing EPROCESS image-name representation, including its
15-byte limit. Process CPU-time, memory, I/O, and other accounting fields are not
implemented by this pass and remain zero. Thread scheduler fields are copied
from the guest-visible model as maintained by existing scheduling code; this
pass does not establish complete Windows scheduler accounting or wait semantics.

The snapshot's membership and output layout are stable, but per-table counts and
mutable scheduler fields are sampled sequentially. Concurrent guest mapping or
permission changes after validation can still cause a later copy failure or
partial output. Arbitrary guest edits to private process/thread lists are not a
supported lifecycle interface. Native WOW64 layouts and ARM64 runtime behavior
are outside the x64 validation scope.

## Validation

The x64 WHP Release build succeeds. The verified generic executable has SHA-256
`A51DD8FDE7D8D887F39D490C673BBE571FD51ECAD5DC6A4A138ADA4F2B16AC76`.

Six existing regressions passed, with 1,447 successful assertions in total:

| Regression | Assertions | Manifest under `build-conformance/` |
| --- | ---: | --- |
| Process-local handle tables | 951 | `handle-tables-20260927-130902-148.json` |
| Process attachment | 69 | `attach-20260927-130913-276.json` |
| Process notifications | 95 | `process-notify-20260927-130917-592.json` |
| Thread notifications | 29 | `thread_notify_conformance-20260927-130934-135.json` |
| Thread ownership | 15 | `thread_owner_conformance-20260927-131100-020.json` |
| Storage | 288 | `storage_conformance-20260927-131101-046.json` |

Artifacts remained unchanged during each run and stderr was empty. The pinned
kernel's three previously known missing optional hook aliases (`KeRaiseIrql`,
`KfLowerIrql`, and `KeRaiseIrqlToSynchLevel`) were excluded from the diagnostic
failure gate. Existing native loader probes of unsupported classes 192 and 197
remain outside this class-5 pass.

The dedicated snapshot run passed: all 27 kernel checks were observed (66
successful assertion occurrences), and the native fixture reached its single
success-only `0x5150` termination after all 24 source checks. Runner and emulator
both exited zero without timeout. Forbidden runtime diagnostics and unsupported
syscalls were zero; stderr was empty and all hashes stayed stable. Evidence:
`build-conformance/process-snapshots-20260927-132146-542.json` and the matching
`.stdout.log`. These fixtures do not exercise `vgc.exe` startup.

The first focused run exposed a fixture reporting defect: native `DbgPrint`
called the unimplemented `NtQueryDebugFilterState` syscall (0x142), suppressing
all native assertion messages despite reaching the success exit status. That
run (`process-snapshots-20260927-131648-683.json`) is retained as failed evidence.
The corrected native fixture uses an exact success-only termination status and
encodes the failing source line in failure statuses, matching existing native
fixtures. It does not need a new debugger syscall implementation.

Build and run the focused fixtures from the repository root in PowerShell:

```powershell
tests/scripts/build-drivers.ps1 -Driver process_snapshot_conformance
tests/scripts/build-process-snapshot-user.ps1
tests/scripts/run-process-snapshots.ps1
```

The runner executes both images only inside the emulator, records hashes and
diagnostics, and rejects deadline expiry or missing completion evidence. Do not
load the fixture driver or run the native executable on the host.

The focused kernel fixture checks layout, Registry's zero-thread record, local
and cross-process handle-count changes, attached-thread ownership, and the
appearance/removal of a held system thread. The native fixture checks its actual
PID/TID, process creation time and parent, buffer alignment, and invalid,
read-only, unmapped, supervisor-address, and overflowing output ranges.
Full process create/exit publication is covered by existing lifecycle regressions,
but a simultaneous class-5 process-creation/deletion stress test and preservation
of a real supervisor-page sentinel are not covered by these focused fixtures.
No new VGK capture was used as the acceptance test for this pass.

Independent production and completed-fixture reviews found no material issues.
The final whitespace/error check passed, and no emulator process remained after
validation. The generic executable contains no local VGK compatibility patch.
