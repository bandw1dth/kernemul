# Process lifecycle and notifications

CLI user images are launched by emulated system threads after every requested
driver has returned successfully from DriverEntry. This makes registrations in
DriverEntry observable by subsequent process creation. Boot-seeded processes
remain snapshots: their historical creation and exit events are not replayed.

## Creation transaction

The emulator constructs the address space, executable and ntdll mappings, PEB,
process parameters, backed image FILE_OBJECT, and suspended initial thread before
delivering process notifications. PID lookup and the initial ETHREAD are already
available to callbacks, but user code cannot run yet.

Extended callbacks receive the 72-byte native 64-bit PS_CREATE_NOTIFY_INFO,
including parent PID, actual creator PID/TID, image file object, image name, and
command line. For the current CLI interface the command line is the image path.
Strings and the information structure are callback-scoped. Only CreationStatus
is mutable; other metadata modifications stop emulation. FileOpenNameAvailable
is clear because guest path resolution does not establish a canonical NT name.

The following are explicit emulator conventions, not claims about undocumented
Windows ordering:

- Extended callbacks run before classic creation callbacks.
- The first failed CreationStatus is retained across later extended callbacks.
- A veto removes the uncommitted process and initial thread from discovery,
  closes its owned console handle, and emits neither classic creation nor a
  synthetic process-exit notification.
- Accepted creation is followed by initial-thread creation and EXE/ntdll image
  notifications, then the initial thread becomes runnable.

## Exit and callback execution

The last live user thread delivers its thread-exit notification followed by
extended process exit (CreateInfo NULL) and classic process exit. Delivery is
claimed once under the process lifecycle lock. Process exit records status and
time, signals the process dispatcher object, wakes waiters, and removes PID and
active-list visibility after callbacks. Kernel/system snapshot processes do not
undergo this user-process transaction.

The shared lifecycle bridge enters kernel mode on a supervisor stack, establishes
the required IRQL/APC context, and restores the incoming registers, mode, PCR,
IRQL, and APC counters on return or failure. Process callbacks run at PASSIVE_LEVEL
with normal kernel APCs disabled and special kernel APCs enabled. Blocking,
termination, reentrant process/thread creation, callback removal, and unbalanced
context inside callbacks stop execution rather than silently continuing.

The registry is per emulator, distinguishes classic from extended registrations,
and drains in-flight callbacks on removal outside callbacks. A shared 64-entry
quota and duplicate-address rejection across both kinds are modeling choices.
Extended registration requires the containing mapped PE's FORCE_INTEGRITY
characteristic. That check is not Authenticode verification.

## Boundaries

This pass does not implement NtCreateUserProcess, Ex2/non-Win32 notifications,
arbitrary remote termination, a general multi-thread process kill transaction,
or reclamation of retained guest object bodies. The object manager still retains
those bodies under its existing ownership model. Unsupported callback paths
remain explicit failures; registry and object notification execution retain their
separate bridges. A driver admission veto is an individual launch outcome;
emulator failure or failed driver initialization produces a nonzero host exit.
Ordinary executable setup failures also fail the host run; the admission-veto
outcome is recorded separately. Thread completion uses release/acquire publication
so a launcher that observes completed DriverEntry also observes its exit status.

## Verification

The process registry host model covers quota, type identity, duplicate rejection,
stale snapshots, removal rundown, callback deadlock prevention, and isolation.
The guest fixture registers both callback types and checks accepted creation,
sticky rejection, payload/context, initial thread and image ordering, ring-3 user
execution, last-thread exit, callback removal, and eventual PID disappearance.
The accepted and rejected executable files have identical bytes, making an
accidental rejected launch observable as a second user termination.

Separate guest fixtures exercise FORCE_INTEGRITY rejection and fail-stop paths
for waits, self-removal, a failing API, immutable metadata changes, and a wait in
the ring-3-origin process-exit callback. All guest artifacts execute only inside
the emulator.
Staging checks cover a DriverEntry that yields before failing, a missing CLI
image, and a malformed executable, none of which may run user code.

Build and run with `build-drivers.ps1 -Driver 'process_notify_*'`,
`build-process-user.ps1`, `run-process-notify.ps1`,
`run-conformance.ps1 -Driver process_notify_integrity`, and
`run-process-negative.ps1` under `tests/scripts`.

### Validation on 2026-09-26

The WHP Release build succeeded. All 11 standalone host model programs passed.
The process positive fixture passed on the final generic executable
`3D2974AD0381C5EADB36F9F518943AC326A644DA57809453C99D39D76695A6A3`:
`build-conformance/process-notify-20260926-134242-709.json` records all 14
expected markers exactly once, one user termination with status `0x1234`, stable
artifact hashes, no exception dispatch, and no callback failures. The guest
also verified the retained process object's signaled state after PID removal.
The OB user/kernel pairing passed on the same executable.

Thread, thread-ownership, image, object, registry, executive callback, and CI
positive regressions passed during integration, as did all 22 existing negative
cases. The fail-stop runner now requires host exit one. Runtime verification
uses WHP with one vCPU; it does not establish concurrent multi-vCPU correctness
or ARM64 execution coverage. Completion publication was additionally reviewed
for the identified cross-vCPU race.

All eight new negative/staging cases passed on that final generic executable:
`build-conformance/process-negative-20260926-134816-343-*.json`. Every run exited
one without timeout, retained stable artifact hashes, and reached its specific
expected failure. Creation failures never published/runs a user process; the exit
failure reached user termination once and stopped before successful exit cleanup.

## Contract sources

- [Classic registration](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutine)
- [Extended registration and callback execution context](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex)
- [PS_CREATE_NOTIFY_INFO fields and admission status](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_ps_create_notify_info)
- [Extended callback creation and exit contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nc-ntddk-pcreate_process_notify_routine_ex)
