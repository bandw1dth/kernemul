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
separate bridges. Registry delivery also saves the actual caller context and uses
kernel mode, KPCR, and a supervisor stack when invoked from a user syscall.
A driver admission veto is an individual launch outcome;
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
The initial process positive fixture passed on the generic executable
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
expected failure. Creation failures never published or ran a user process; the exit
failure reached user termination once and stopped before successful exit cleanup.

### Target-driven registry bridge regression

The first process-aware VGK capture (`kernel-20260926-134921-445`, local lab
commit `e07fd2f`) delivered Ex and classic process creation successfully, then
stopped after 10.005 seconds in a user-loader registry query. The old registry
bridge attempted to execute a supervisor callback with the user's ring-3
registers, TEB context, and stack. The fault occurred at callback entry, before
any registry payload dereference. The reported zero fault address is not proof
of a null dereference: this WHP diagnostic reads CR2 without forwarding the raw
exception parameter/error bits.

Adding a registry observer to the process conformance driver reproduced the
failure independently (`process-notify-20260926-135120-686`). The regression
checks the callback's subject PID/TID through kernel PCR access, requires actual
user-loader registry delivery, and reaches a user program that checks ring-3
execution after those callbacks. The registry bridge fix preserves the existing
registry IRQL/APC behavior and callback result while restoring the exact incoming
architectural context on both return and failure.

After the fix, `process-notify-20260926-135435-685.json` passed with all 14
lifecycle markers and successful user-loader registry observations. The final
generic executable hash is
`7C800BA9C2E4483A8E4BA856BFDED8643C3EA756545D4DB517A7EE23FEE51D7B`.
Registry conformance and all four registry failure cases also passed on this
build (`135449` through `135452` manifests).

### Completed process-aware target capture

`build-conformance/kernel-20260926-135545-142` ran for **210.032 seconds** and
was stopped at the requested limit (host exit `-1` from that deliberate stop).
The manifest and `analysis.json` pin the local lab commit `054bff5`, executable,
driver, user image, kernel, and CI DLL. The user-provided DEBUGCTL compatibility
patch remains confined to guest memory on the local lab branch. The target driver
and test executable hashes remained unchanged; no `vgc.exe` service was launched.

- At 13:55:51.989–51.996, VGK's Ex (`vgk+0xF4A0`) and classic (`vgk+0xF3E0`)
  creation callbacks completed for PID 196, created by PID 4/TID 172. Both
  retained successful admission status.
- At 13:55:53.280 the native guest program terminated with `0x1234`, after its
  ring-3/TEB checks. Ex and classic exit callbacks completed in PID 196/TID 200;
  the lifecycle then unpublished PID 196 at 13:55:53.284.
- All four callback BEGIN records have matching END records. There were zero
  callback failures, faulted hooks, missing runtime exports, or unhandled
  exceptions; stderr was empty. There were 147 handled exceptions and three
  known optional IRQL hook-symbol setup diagnostics.
- All eight CI signed-file calls returned without hook faults. The three-minute
  timer expired and subsequent reads returned true 19 times.

This validates observable process creation and exit, not every Windows process
subsystem. Four `KeStackAttachProcess` calls still warned that attachment only
updates APC state, without switching the address space. Real attach/detach and
cross-process memory access are a concrete next fidelity priority. CI certificate
verification, firmware/storage backing, exception routing for genuine faults in
kernel callbacks owned by user threads, and the other stated limits remain.

The generic branch and final generic executable were restored after the capture;
the lab patch was not included in the published branch. Independent review found
no remaining material findings in either the lifecycle change or registry fix.

## Contract sources

- [Classic registration](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutine)
- [Extended registration and callback execution context](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex)
- [PS_CREATE_NOTIFY_INFO fields and admission status](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_ps_create_notify_info)
- [Extended callback creation and exit contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nc-ntddk-pcreate_process_notify_routine_ex)
