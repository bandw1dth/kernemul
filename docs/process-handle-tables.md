# Process-local handles and ObjectTable

Ordinary object handles now resolve in the effective process context, including
an attached process. Equal numeric handles in different processes can name
different objects. User process console handles are allocated in their owner's
table. Kernel handles use a marked value and resolve in System's table;
user-mode lookups cannot use them. Kernel Zw entry points temporarily supply
KernelMode and restore PreviousMode on return.

The API modules use shared routing helpers for creation, lookup, close, waits,
I/O, registry operations, sections, process/thread operations, and duplication.
`NtDuplicateObject` resolves source and destination process handles in the
caller, checks `PROCESS_DUP_HANDLE`, and then operates on the explicitly selected
tables. Duplicate notifications carry those source and destination process
objects. Handle protection and the granted-access ceiling are retained.

Each published process has distinct guest-visible `_HANDLE_TABLE` storage,
including seeded process identities. `EPROCESS.ObjectTable` points to that
storage. This is a bounded representation using the repository's pinned private
types, not a portable Windows ABI:

- A level-one `TableCode` points to a root page containing up to 512 leaf pointers.
- Each leaf holds 256 16-byte entries; slot zero in every leaf is reserved.
- Leaves are allocated as needed. Handles increase by four, skipping reserved
  slots, with a maximum of 130,560 allocations per table and no handle reuse.
- Entries expose the compressed object-header address, attributes, and granted
  access. Closing a handle clears its entry and updates table/object counts.
- Table metadata identifies its process, allocated range, and current handle count.

The object allocator also uses `offsetof(_OBJECT_HEADER, Body)` (`0x30`) for the
body location. Previously it used the full header size (`0x38`), so a native
consumer decoding an entry and adding the body offset would reach the wrong
address. Count updates now write only their respective header fields.
Process identities, including System and seeded processes, are allocated through
the object manager before their bodies are linked into the active-process list.
Their handle entries therefore refer to real headers with live handle and pointer
counts, just as thread and event entries do.

`ObReferenceProcessHandleTable` validates the process identity and acquires its
guest `EPROCESS.RundownProtect` reference before returning `ObjectTable`.
A missing table releases the acquired reference. On the pinned x64 kernel,
`ObDereferenceProcessHandleTable` and `PsReleaseProcessExitSynchronization` are
the same function; both release that process rundown reference. The existing
process API handler owns both release names.
`ExEnumHandleTable` visits a snapshot of live entries without holding a host
table lock across guest code. On the tested x64 kernel its callback is
`callback(table, entry, handle, context)`. The callback must unlock the entry
without changing its metadata. A true result stops the walk and supplies the
matched handle; a false result leaves the output untouched. Entry state and
critical-region state are restored on callback failure.

The callback ABI and level-one lookup arithmetic were checked against the exact
guest `ntoskrnl.exe` version 10.0.26100.9444, SHA-256
`75665496A75FC020A0573523F3F77D7C719479ACEB5806A98D82FF2D1B5314A1`.
`ExEnumHandleTable` is at RVA `0x8a5500`; its lookup helper is at `0x872460`.
The private table-reference routine is at `0x8a77a0`; its folded release routine
is at `0x9fe3e0`. PDB records and local disassembly confirm the acquisition at
`EPROCESS+0x1e8` and subsequent table read at `EPROCESS+0x300`. The fixture gates
its private-RVA checks on the exact kernel hash before launching the emulator.
Local disassembly evidence is in `build-conformance/handle-table-native-abi.txt`
and `build-conformance/handle-table-native-layout.txt`; rundown evidence is in
`build-conformance/handle-table-rundown-native-abi.txt`.

## Lifecycle and limits

Process unpublication clears `EPROCESS.ObjectTable`, removes its local handles,
clears their entries, and releases their object handle counts. Other processes'
duplicates and System-owned kernel handles remain independent. Exposed table
storage and referenced owners are retained, so stale guest pointers do not
become pointers into reused allocations.

This does not implement Windows' complete handle-table allocator, lock/refcount
cache protocol, or blocking rundown. Process rundown references are represented
in guest memory; retained storage keeps exposed pointers valid, but references
do not yet delay process exit. Process-exit rundown does not yet dispatch
device cleanup/close IRPs. Explicit last-handle closes do. Object reclamation,
handle inheritance, arbitrary guest edits to handle entries, and complete
object-security policy remain outside this pass. Private layout and callback
behavior on ARM64 are not established by the x64 validation.

Hook-level rundown operations share a per-emulator serialized service. Beginning
rundown preserves outstanding references and rejects new acquisitions; later
releases drain the count. This does not provide atomic interoperability with
arbitrary guest instructions that directly modify a rundown word, nor implement
Windows' blocking rundown wait protocol.

Object type indices and other private object-manager metadata remain subject to
the existing synthetic object model. Header/body addresses and counts being
coherent does not make every private header field a native Windows implementation.

## Integration corrections

The x64 address-space allocator serializes cursor reservation through mapping,
so different process tables cannot race while allocating leaves in the shared
kernel address space. The standalone allocator test uses the production MMU
with a memory-only physical backend; it does not establish full multi-vCPU guest
execution conformance.

Raw read/write entry points check a UserMode status-block destination before
handle rejection can write to it. The storage fixture uses a local handle for
pointer checks and separately covers rejected kernel and invalid handles.
`ZwFlushKey` uses the same temporary KernelMode handling as other Zw operations.
Failed ALPC handle publication rolls back only its own namespace entry, using
atomic name insertion and conditional removal. Device opens that accepted CREATE
but failed handle publication send CLEANUP and CLOSE before freeing their file
object.

The custom-device fixture also exposed a prior IRP-dispatch bug: dispatch always
returned the CPU to user mode, even for a kernel caller. The dispatch boundary now
captures and restores the exact incoming CS/SS (x64) or PSTATE (ARM64), including
exception unwinding. The x64 fixture verifies normal open, duplication, and
cleanup/close only on the final handle.

The failed-publication fixture also checks that an unexpected host exception at
an exported API cannot resume ordinary guest execution. Export-hook failures
preserve checked-call/DPC failure propagation and stop the scheduler for an
unchecked caller. The negative runner requires cleanup/close before the fault,
then termination with no guest continuation; exit status alone is insufficient.

## Reproduction

```powershell
tests/scripts/build-drivers.ps1 -Driver handle_table_conformance
tests/scripts/build-handle-user.ps1
tests/scripts/run-handle-tables.ps1
tests/scripts/build-x86-allocator-tests.ps1 -Run
tests/scripts/build-rundown-tests.ps1 -Run
tests/scripts/build-drivers.ps1 -Driver storage_conformance
tests/scripts/run-conformance.ps1 -Driver storage_conformance
tests/scripts/build-drivers.ps1 -Driver handle_migration_conformance
tests/scripts/run-conformance.ps1 -Driver handle_migration_conformance
tests/scripts/build-drivers.ps1 -Driver device_handle_rollback
tests/scripts/build-drivers.ps1 -Driver device_handle_rollback_negative
tests/scripts/run-conformance.ps1 -Driver device_handle_rollback
tests/scripts/run-device-handle-rollback-negative.ps1
```

The driver and native-user fixtures run inside the emulator. They are not installed
or executed as host drivers/programs. The allocator unit test runs on the host
with an in-memory physical backend. The guest runner records executable and fixture
hashes and requires the complete assertion set, both native process exits, and
zero runtime failures.

## Validation (2026-09-27, x64 WHP)

The Release build passed. The validated generic executable is retained locally
at `build-conformance/handle-tables-rundown-validated-20260927/kernemul.exe`, SHA-256
`453AF5D8C0F1F68E773B4710B3761A1F01E86C8D6E914B165A90527B958AE4B6`.

- Handle tables: 81 required assertion labels, 951 passing assertions, both guest
  processes exited, all fixture/executable hashes stable. Manifest:
  `build-conformance/handle-tables-20260927-014803-318.json`.
- Attach/address spaces: 41 required labels and 69 passing assertions.
  Manifest: `build-conformance/attach-20260927-014813-636.json`.
- Custom device: 15 passing assertions. Failed publication separately produced
  exactly one CREATE, CLEANUP, and CLOSE in order, then one fatal hook diagnostic
  and exit 1 with no guest continuation. Manifests:
  `device_handle_rollback-20260927-014828-887.json` and
  `device-handle-rollback-negative-20260927-014823-715.json` under
  `build-conformance/`.
- Storage, CI verification, exception delivery, migration, timers, executive
  callbacks, registration, registry notification, firmware, physical resources,
  thread/image/OB notifications, and IRQL conformance passed. Paired storage,
  firmware, process-notification, and OB user fixtures passed.
- Four checked-callback/DPC negative cases passed: callback wait, OB API failure,
  thread-notification API failure, and unsupported DPC API. These ran on the
  preceding generic executable, SHA-256
  `4E12C3CBED44DE74A0B425970AC61D1408466654B10E53A006A6FAB86AB06723`,
  before the rundown correction; they were not repeated on the final executable.
- The production x64 allocator test passed serialization, 2,048 concurrent
  allocations, translations/data integrity, and mapping-failure recovery. Removing
  the allocation locks made its negative control fail.
- The production rundown service passed concurrent exact-count acquisition and
  release, active-state draining/refusal, overflow/underflow, initialization, and
  guest-memory-authority tests. Removing its lock reproduced lost increments.

Independent focused testing and static review were used. The migration fixture
tests exported Zw operations; it explicitly skips direct NtFlushKey/NtAlpcCreatePort
UserMode-denial checks because those Nt names are not exported by the pinned
kernel. Other native/kernel-handle rejection paths are covered by the main fixture.
These results do not establish untested private Windows behavior or ARM64 runtime
conformance.

## Target capture and final analysis

The completed repeat capture is retained locally at
`build-conformance/kernel-20260927-121310-132/`. It ran for 210.042 seconds on
WHP and was deliberately stopped at the time limit (exit -1), rather than
exiting naturally. The earlier repeat at `kernel-20260927-014952-765` was
interrupted after approximately 46 seconds and is not completion evidence.

The repeat used generic commit `4008b0c` plus the author-provided, in-memory
DEBUGCTL compatibility stub on local-only lab commit `6c919b4`. Its frozen
executable SHA-256 is
`990DEC649896CE06C0061F1C14A71CA8CB27D4972B528D64F05736461D5C39FD`.
That stub and the lab branches are excluded from the published generic branch.
The guest arguments were `vgk.sys process_notify_user.exe`; no `vgc.exe` was
launched. The driver file remained unchanged, with SHA-256
`3CB2F36CF9F3B66BF63561D24649422D852229F2C788A7AAA783752DCE4AB39F`
before and after the run. The pinned guest kernel was 10.0.26100.9444.

- DriverEntry returned STATUS_SUCCESS at 12:13:21.441.
- There were 249 attaches and 249 matching detaches, four process-notification
  deliveries, and 245 process-rundown releases with zero unmatched-release
  diagnostics. The first completed capture before the rundown correction
  (`kernel-20260927-013133-830`) had 246 unmatched-release diagnostics.
- The three-minute timer was observed signaled 18 times, first at 12:16:14.517.
- There were 142 handled exceptions, zero unhandled exceptions, zero API/callback
  faults, zero executed unimplemented-function diagnostics, and empty stderr.
  Handled exceptions remain part of the observed behavior; these results do not
  establish that debugger-sensitive paths reproduce real hardware.
- The only three error-level lines were the existing optional hook-symbol misses
  for KeRaiseIrql, KfLowerIrql, and KeRaiseIrqlToSynchLevel.
- CI produced eight verdicts: two trusted SHA-256 signatures and six digest or
  algorithm mismatches. Trust used the host chain policy with offline revocation
  unchecked. BootCurrent and Boot0000 queries succeeded, and the physical-memory
  resource-map key opened successfully.
- Storage dispatched three requests to the modeled disk: 0x4D02C returned
  STATUS_BUFFER_TOO_SMALL, while two 0x2D1400 descriptor requests succeeded.
  Eight opens for unmodeled PhysicalDrive1 through PhysicalDrive4 remained absent;
  there were no former "not a device" dispatch failures.

The target now exercises substantially more process attachment activity than the
pre-pass capture (four attaches), while the rundown correction removes the
specific reference-pairing failure exposed by the first new capture. This is
evidence for the bounded handle-table/process-rundown model, not full Windows
Object Manager equivalence. The retained-storage, allocator, security, blocking
rundown, process-exit cleanup, and ARM64 limits described above still apply.
User-mode fidelity and software LBR/BTF modeling remain outside this pass.

The subsequent [fifteen-minute kernel capture](vgk-kernel-15-minute-analysis.md)
records longer post-expiry behavior, allocation trends, observability limits,
and the recommended process/thread snapshot coherence pass.

## References

- [Microsoft: object handles](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/object-handles)
- [Microsoft: PreviousMode](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/previousmode)
- [Microsoft: ObReferenceObjectByHandle](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obreferenceobjectbyhandle)
- [Microsoft: ZwDuplicateObject](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwduplicateobject)
- [Microsoft: opaque EPROCESS](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/eprocess)
