# Process and thread handle filtering

This increment connects retained OB registrations to guest handle operations. A
callback's permitted access reductions become the stored grant, and user-mode
`ObReferenceObjectByHandle` checks that grant. Process objects acquire registered
host identities so process handles and process type checks work alongside threads.

## Contract

The delivery surface is `ObOpenObjectByPointer`, `Nt/ZwOpenThread`,
`Nt/ZwDuplicateObject`, `NtCreateThreadEx`, and `PsCreateSystemThread`.
Host setup and raw internal handle-table insertion do not synthesize events.
Registration descriptors are copied; object type and create/duplicate flags select
the matching callbacks. Pre and post receive a separate `CallContext` per filter.
Post-only registrations are supported.

Pre and post execute synchronously at PASSIVE_LEVEL with normal kernel APCs
disabled and special kernel APCs enabled. The initiating thread's prior context
is restored. Delivery explicitly enters kernel execution with a supervisor stack
and the per-CPU PCR; register restoration preserves the actual incoming privilege
mode, including callers originating in user-mode syscalls. Pre must return
`OB_PREOP_SUCCESS`; post returns void. Failures,
blocking, termination, suspension, unbalanced execution context, and unsupported
nested OB operations stop execution instead of continuing with a fabricated result.

Each pre callback may remove only the process/thread rights documented as
modifiable. It cannot add rights or restore a right removed by an earlier filter.
Nonmodifiable bits survive attempted removal. Original access stays immutable;
successful post records report the final granted mask. This is access filtering,
not a complete Windows security descriptor, token, or privilege check.

Numeric altitude comparison uses decimal strings without floating point rounding.
Higher altitudes run pre first; post unwinds in reverse. Registrations remain
admitted through the entire operation, including post delivery. Removal stops new
admission and drains admitted operations. Removal from a callback is rejected to
avoid a synchronous rundown deadlock. **Ordering, rundown policy, and rejection of
nested OB operations are explicit emulator choices**; the public OB documentation
does not establish all these implementation details.

## Boundaries

The existing shared system handle table remains. Kernel-handle attributes are
retained and checked for user-mode references, but this does not create Windows'
full per-process handle namespace. Cross-process duplication and `NtOpenProcess`
remain outside this increment. Desktop object callbacks, guest `_OBJECT_TYPE`
callback-list layout, security descriptor evaluation, callback image signature
verification, and complete object destruction are not implemented here.

`NtCreateThreadEx` now delays child publication until its handle operation
succeeds. Its separate process/thread lifecycle notification gap is unchanged;
`PsCreateSystemThread` retains its existing lifecycle delivery and rollback.
Generic access bits and `MAXIMUM_ALLOWED` are explicitly rejected for these
process/thread operations rather than stored as unresolved grants.

Duplication is deliberately limited to a non-null output in the current process,
with no grant expansion beyond the source handle. It does not reevaluate object
security to grant additional rights. The existing close-source path closes only
after a successful duplicate; close-only requests and failure-path close-source
semantics still need implementation. This is narrower than the complete
[ZwDuplicateObject contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwduplicateobject).

Handle access enforcement is scoped to known process/thread identities at
`ObReferenceObjectByHandle` and duplication. File/device producers do not yet
retain reliable access grants, so their legacy reference behavior is preserved.
Other NT handlers that directly consume the shared handle table
still require an access-control audit; do not treat this increment as complete
emulated security isolation. Guest pointer checks cover mapped storage, not full
Windows probing and access-mode semantics.

## Evidence

`ob_notify_conformance.c` exercises process and thread identity, numeric ordering,
per-filter contexts, create/duplicate payloads, original and granted access,
nonmodifiable rights, attempted rights additions, kernel-handle flags, and removal.
`ob_notify_boundaries.c` covers registration-output rollback, altitude equivalence,
copied descriptors, operation/type selection, bad outputs, wrong object types,
duplication limits, system-thread creation, post-only delivery, and preservation
of legacy file-reference behavior. Negative
fixtures cover blocking, callback removal, a failing kernel API, an invalid pre
return, and nested handle operations. All driver fixtures run only inside WHP.

The paired `ob_notify_user.sys` / `ob_user.exe` fixture uses real ntdll syscalls
for thread open, duplication, and suspended thread creation. It checks callback
identity and grants, then reads CS and TEB fields to verify return to the original
user-mode context after each operation. Build and run only through the emulator:

```powershell
.\tests\scripts\build-drivers.ps1
.\tests\scripts\build-ob-user.ps1
.\tests\scripts\run-ob-user.ps1
```

The paired runner requires all three ordered pre/post pairs and successful user
termination. Its JSON manifest pins the emulator, driver, and executable hashes;
timeouts, host crashes, unexpected faults, and guest failure markers fail the run.

The mapped kernel exports neither `NtCreateThreadEx` nor its Zw name. The paired
fixture reaches the existing handler through real ntdll syscall routing instead
of inventing an export. It validates suspended creation and cleanup, not child
user-code execution or every creation flag. WHP resynchronizes `EFER.SCE` after
syscall handlers return: nested kernel callbacks can change that state, and the
next user syscall must still enter the emulator's interception path.

Runtime validation targets x64 WHP. Callback-failure fixtures originate in kernel
mode; ring-3 failure restoration and ARM64 execution are not runtime-validated.

The native loader still encounters unsupported system-information classes 192
and 197, and hook setup reports three absent optional IRQL aliases. The runner
records these exact existing bootstrap diagnostics separately; it rejects other
error diagnostics and actual calls to unimplemented functions. This test does not
establish full native-loader fidelity or Windows security equivalence.

Validated on 2026-09-26: 12 positive driver fixtures, 22 expected-failure fixtures,
10 host models, and the paired ring-3 fixture passed. The final artifact audit
matched every guest manifest to its current executable and fixture hashes.
Local WHP Release executable SHA-256:
`CAA3147EA087D905494B6087E36E24DF72EE8BB2D2657FFB2B65FDA791085E98`.

## Primary references

- [OB registration](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obregistercallbacks)
- [Operation registration](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_ob_operation_registration)
- [Pre callback contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nc-wdm-pob_pre_operation_callback)
- [Pre operation information](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_ob_pre_operation_information)
- [Modifiable create access](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_ob_pre_create_handle_information)
- [Duplicate information](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_ob_pre_duplicate_handle_information)
- [Post operation information](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_ob_post_operation_information)
- [Removal](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obunregistercallbacks)

Microsoft's post information contract makes `Parameters` valid only on success.
Its pre contract has no general veto status. These differ from registry filtering
and must not be implemented by simply reusing the registry dispatch protocol.
