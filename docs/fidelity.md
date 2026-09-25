# Kernel fidelity work

The emulator executes guest instructions with WHP or Unicorn and supplies Windows
kernel semantics itself. A mapped Windows image is not a running Windows kernel.
An API returning success is therefore not evidence that its underlying subsystem
exists. This work replaces isolated return-value handlers with stateful services.

## Design rules

- Keep CPU execution separate from guest OS state and policy.
- Own subsystem state per emulator instance; avoid process-global registration tables.
- Distinguish guest wall time from monotonic elapsed time. Relative deadlines use
  monotonic time. Publish shared memory clocks from the same source as API queries.
- Deliver timers independently of polling the timer object.
- Represent queued work separately from running work. DPC delivery has an execution
  context and is not a new ordinary system thread.
- Preserve guest-visible state and host bookkeeping together. State seen through
  structure reads must agree with state returned by APIs.
- Do not hold a host registry mutex while executing guest callbacks.
- Preserve the distinction between documented semantics, build-specific observations,
  fixture data, and unsupported behavior. A successful target initialization is not
  the correctness criterion.

## Verification

`tests/scripts/build-drivers.ps1` builds small x64 conformance guest images using
the installed Visual C++ tools and WDK (SDK version can be passed explicitly).
It does not install a Windows driver. Run fixtures from PowerShell 7 (`pwsh`) with:

```powershell
.\tests\scripts\build-drivers.ps1
.\tests\scripts\run-conformance.ps1 -Driver timer_conformance
.\tests\scripts\run-conformance.ps1 -Driver callback_conformance
.\tests\scripts\run-conformance.ps1 -Driver registration_conformance
.\tests\scripts\run-conformance.ps1 -Driver thread_notify_conformance
.\tests\scripts\run-conformance.ps1 -Driver thread_notify_boundaries
.\tests\scripts\run-model-tests.ps1
.\tests\scripts\run-negative-tests.ps1
```

The runner uses the WHP Release executable by default, copies only the selected
fixture into `fs_x86_64`, bounds execution, and writes logs plus a JSON manifest to
`build-conformance`. It requires an explicit passing guest result and rejects a
timeout, a failed check, or an unhandled exception. Emulator process exit code alone
is insufficient: historically a failed DriverEntry still led to host exit code zero.

Timer checks cover notification/synchronization semantics, expiry waking an idle
guest, cancellation, rearming, DPC reuse/context, periodic delivery, and shared time.
Executive callback checks cover named opens, identity, registration order, duplicate
registration identity, removal, arguments, caller IRQL, and single-registration objects.

Reference runs on a matching real Windows VM are a separate validation step. Passing
inside this emulator does not establish conformance for untested races or Windows
versions. Do not load the unsigned fixture into the host as part of this workflow.

## Follow-on work

1. Extend the classic system-thread lifecycle delivery to process creation, image
   mapping, Ex thread modes, and target-context remote termination.
2. Object/registry pre/post operation delivery using the retained registrations.
3. Coherent process-local handles and guest EPROCESS.ObjectTable representation.
4. Memory invariants across MMU, PFN, MDL, allocations, and guest-visible metadata.
5. Build-pinned CI verification contracts, fixtures, and policy behavior.
6. Versioned firmware/storage machine profiles and explicit device/IRP completion.

Use Microsoft contracts and small differential tests first. Consult matching PDBs
and exact-build disassembly when an observed behavior is undocumented. ReactOS is
a design reference, not the specification for a modern Windows build. Never make
a target-specific successful response stand in for the missing subsystem.

## Current implementation boundaries

The clock is real-time paced. Shared clock updates and expiry are serviced from
the host timekeeper at approximately 1 ms requested intervals; host scheduling can
delay delivery. This is not deterministic replay, instruction-accurate time, or
complete TSC/QPC equivalence. Missed periodic expirations are coalesced.

DPC dispatch is serialized, with a guest kernel stack per CPU and explicit IRQL
restoration. Processor-targeted queues and concurrent multiprocessor DPC execution
are not implemented. WHP currently uses one vCPU. The generic backend still needs
separate multiprocessor validation.

Executive callback delivery rechecks active registration state before invoking each
record. Unregister prevents future dispatch, but does not drain an already in-flight
callback on another vCPU. Full callback rundown needs scheduler-aware completion.
Object and registry registration retention does not imply operation delivery.
Registrations copy caller-owned data, enforce altitude collisions, and invalidate
exact handles/cookies on removal. Executive callbacks have the Windows-owned
`PowerState` and `SetSystemTime` namespace objects available at startup. A callback
that blocks currently stops execution with a diagnostic; resumable callback
continuations are not implemented. This avoids silently running past a pending wait.

Kernel smoke runs can be captured with `tests/scripts/run-kernel-lab.ps1`. The script
freezes a WHP executable and DLL copy, records executable/target/kernel hashes, and
stops at its time limit. DriverEntry status, unsupported API paths, and subsystem
events must be inspected separately; elapsed run time is not a pass criterion.

## Recorded validation (2026-09-26)

The target captures below used a pre-existing local VGK-specific DEBUGCTL patch
in `src/main.cpp`. That patch is not part of the general fidelity changes. These
captures therefore do not establish that an unmodified target initializes on a
clean checkout. The conformance fixtures exercise the generic implementation.

The WHP Release build passed. Guest conformance passed 32 timer checks, 14
executive-callback checks, nine object/registry registration checks, and two
invalid-timer recovery checks. Three host model executables cover deadlines and
clock changes, nested guest-call completion, and registration ownership/rollback.
Negative fixtures separately check controlled shutdown for blocking callbacks and
unsupported exports reached from DPCs. Their runner rejects forbidden continuation
markers, repeated failures, and timeouts rather than treating host exit zero as proof.

The kernel-only 210-second run in
`build-conformance/kernel-20260926-003230-923` used guest Windows kernel
10.0.26100.9444. Initialization thread 168 returned status zero. The driver set its
180-second timer at 00:32:32.797; it expired at 00:35:32.804 and subsequent timer
reads returned true (19 reads before capture ended). The capture was stopped at
its requested limit. No unimplemented-export or unhandled-exception diagnostic
was found; handled debugger-probe exceptions and other subsystem fidelity warnings
remain. This is evidence for timer delivery, not full driver or Windows correctness.
The manifest pins the exact executable; a later nested-callback failure guard is
validated separately on the final executable.

Final executable SHA-256:
`39C3BA71BDCCAF6E558FFD6E83D88BC1D8933218FA20ABF8CB8B52F28BE8728F`.
Its nested DPC-to-executive-callback unsupported-export test passed in 0.881 seconds:
one failure, threadless dispatch, restored IRQL, no forbidden continuation, and no
timeout. All 14 executive-callback checks also passed on this executable.
The final executable's kernel-only 60-second smoke capture is in
`build-conformance/kernel-20260926-003644-426`; initialization again returned zero
and the capture was stopped at the requested limit.

## References

- [KeSetTimerEx](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kesettimerex)
- [Timer objects and DPCs](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/timer-objects-and-dpcs)
- [KeCancelTimer](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kecanceltimer)
- [ExNotifyCallback](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exnotifycallback)
- [ExCreateCallback](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-excreatecallback)
