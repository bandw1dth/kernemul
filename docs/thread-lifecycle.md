# Live thread notifications

The next fidelity increment connects classic thread notification registrations to
actual guest thread operations. Registration success alone previously retained a
function pointer without delivering an event.

## Contract and acceptance criteria

- Store registrations per emulator instance. Snapshot registration records for
  delivery, retain their lifetime, and never execute guest code under a registry lock.
- On a successful `PsCreateSystemThread`, notify in the creator's context using the
  new thread's process/thread IDs before the child starts executing its entry routine.
- Notify exit exactly once in the exiting thread's context, before publishing
  completion to thread-object waiters. Cover normal return and explicit self-exit.
  Returning from a system-thread start routine is an existing emulator extension;
  Windows documents `PsTerminateSystemThread` as the supported self-exit path.
- Keep creation and termination events tied to lifecycle transitions. Do not replay
  boot inventory when a callback registers, or turn an emulator fault into a normal
  guest exit notification.
- Remove a registration from future delivery and drain in-flight invocations before
  successful removal returns. Self-removal is prohibited by the Windows contract.
- Fail explicitly if a guest callback blocks or cannot complete. Resumable callback
  continuations are a separate scheduler feature.
- Validate context, IDs, creation-before-entry, exit-before-wakeup, multiple
  registrations, removal, and absence of delivery after removal with guest fixtures.
  Exercise lifetime/rundown behavior with focused host tests where practical.

## Scope

This increment starts with classic kernel system-thread notifications. Process
creation and image mapping need their own lifecycle integration and remain separate.
`PsSetCreateThreadNotifyRoutineEx` is not interchangeable with the classic API:
`PsCreateThreadNotifyNonSystem` uses the new thread's context for creation delivery.
Remote termination likewise requires execution in the target context; the caller's
context must never be substituted just to generate an event.

The Windows callback contract permits PASSIVE_LEVEL or APC_LEVEL. Unlike process
callbacks, the classic thread callback documentation does not impose the same
explicit normal-APC-disabled critical-region requirement. Preserve the actual
supported execution context and document narrower emulator limits.

## Implemented boundaries and verification

Classic registrations now receive guest `PsCreateSystemThread` creation events and
supported current-thread exit events. The implementation uses a per-machine registry
with atomic admission under its lock, retained snapshots, in-flight ownership, and
removal rundown. No host registry lock is held during guest execution. Re-registering
the same address cannot revive a stale snapshot or bypass ongoing rundown.

Remote Nt/Zw thread termination returns `STATUS_NOT_SUPPORTED` while a registration
is live or draining. Process termination that would remove other threads has the
same restriction. No target status or lifetime is changed on that rejection.
Resumable callbacks, Ex registration modes, and live user-thread creation are not
implemented by this increment. Backing guest allocations still use the existing
monotonic allocator, so rollback removes runnable/handle state without reclaiming
all guest memory. Seeded threads do not receive synthetic creation events; supported
actual exits can still notify observers registered after their creation.

The WHP build and four host models pass. Guest verification covers 29 lifecycle
checks and six failed-creation checks, plus negative fixtures for blocking and
self-removal. Additional negative fixtures cover swallowed nested API faults and
self-suspension. Checked guest calls now retain failure state across nested calls,
so an inner redirect exception prevents later callback execution and lifecycle
publication; ordinary API calls outside a checked callback keep their existing
error behavior. The registry model exercises concurrent rundown, nested admission,
stale snapshots, deadlock rejection, and instance isolation. Existing timer,
executive-callback, object/registry registration, and failure-path tests also pass.
These are emulator tests, not a differential validation against a real Windows VM;
actual multiprocessor guest delivery and user-mode self-termination remain untested.

Final verification on 2026-09-26 passed all six positive fixtures (92 assertions),
all eight negative fixtures, and all four host model tests. Executable SHA-256:
`53665A9EFD79E587CEED89468B6EA9A4444F1058024B0DE1BC3149C95855195B`.
The local test manifest is
`build-conformance/verification-final-20260926-010457.json`; artifacts remain local.

Use PowerShell 7 for the process runners. Windows PowerShell 5 can lose the exit
code of a fast redirected process despite successful guest assertions; runners
reject that interpreter rather than misreport its missing exit code as a guest failure.

## Sources

- [Thread callback contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nc-ntddk-pcreate_thread_notify_routine)
- [Classic registration](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreatethreadnotifyroutine)
- [Removal and rundown](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psremovecreatethreadnotifyroutine)
- [Ex registration differences](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreatethreadnotifyroutineex)
