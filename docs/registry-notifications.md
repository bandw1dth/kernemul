# Registry value notifications

This increment connects retained registry filter registrations to guest
Nt/ZwSetValueKey, Nt/ZwQueryValueKey, and Nt/ZwDeleteValueKey operations. Host registry
seeding does not generate guest notifications. Open/create, enumeration, key
deletion, handle-close notifications, transactions, and persistent object contexts
remain separate work. Path-based RTL registry helper operations are also outside
this first notification path. The registry backing remains emulator-owned state.

## Acceptance contract

- Invoke pre callbacks synchronously at PASSIVE_LEVEL in the initiating thread,
  from higher to lower numeric altitude. Do not execute guest code under host
  registration or registry-data locks.
- A failing pre status prevents the underlying operation and lower callbacks.
  Pre STATUS_CALLBACK_BYPASS skips the operation and returns success. The stopping
  filter receives no post; higher filters whose pre succeeded still receive post.
- Unwind admitted filters in reverse order, preserving each filter's own
  PreInformation and CallContext. ReturnStatus overrides the operation result only
  when a post callback returns STATUS_CALLBACK_BYPASS. A post error does not roll
  back an already completed mutation.
- Nested registry calls enter below the invoking filter's altitude. They do not
  notify that filter or higher filters, and have independent operation contexts.
- Retain key and registration lifetimes throughout dispatch. Callback removal
  prevents new admission and drains admitted work; reject callback removal that
  would deadlock instead of hanging the emulator.
- Preserve guest-visible operation results and registry state together. Validate
  buffers before mutation and do not report success for an unsupported operation.
  Support query output edits and per-call context; input-structure redirection is
  outside this increment and must be rejected explicitly rather than ignored.
- Checked guest calls must stop cleanly on callback faults, blocking, suspension,
  or termination rather than continue past a callback that did not return.

Reverse post ordering and the host rundown mechanism are explicit model choices
consistent with layered filtering and unload safety, rather than claims about
Windows' internal implementation. The profile uses modern (Windows 7 and later)
callback behavior; it does not reproduce the Vista 1.0 layered post bug.

## Implementation boundaries

Registration admission covers an operation through its post unwind. Removal closes
admission and waits for that work to drain. Removal from callback execution stops
the emulator with a diagnostic rather than risking a host deadlock. Registration
altitudes are compared as decimal strings without floating-point rounding; this
model treats equivalent numeric spellings as the same altitude.

Each admitted filter receives its own guest payload and per-operation context.
The initiating key object stays referenced even if a callback closes its handle.
Value mutations are synchronized, and query results are copied from the store
after pre-callbacks finish. No registration or value-store lock crosses guest code.

Input and output buffers retain their original guest pointers. The Windows 8+
capture of user-mode inputs into system memory remains unimplemented. Validation
checks mapped ranges and arithmetic bounds, not complete guest access permissions.
The legacy pointer-returning registry helpers and the key namespace are not a
complete concurrent Windows configuration manager. Registry change-event watches,
persistent callback object contexts, transactions, and key deletion semantics are
also outside this increment.

The no-blocking callback rule is a limitation of the emulator's synchronous guest
call bridge, not a claim that Windows forbids every such wait. Resumable callback
continuations and multiprocessor interleavings still need separate work.

## Verification

`registry_notify_conformance` exercises three filters registered out of altitude
order. It checks normal and failed operations, pre veto/bypass, post status
override, query output replacement, per-filter context, nested calls from pre and
post, and visibility of a nested mutation to the outer query. The fixture is built
against the WDK, independently of the emulator's structure and status definitions.

`registry_notify_boundaries` checks invalid input, absence of unintended writes,
unsupported input redirection, invalid cookies, and key-object retention when a
callback closes the initiating handle. Four negative fixtures require a controlled
stop and restored IRQL/APC context for waits, self-unregister, nested API failures,
and termination; they reject continuation after the callback failure.

Host models exercise numeric altitude ordering, registration rollback, callback
rundown through post, nested dispatch, and copied value reads under concurrent
mutation. Their bypass status is independently anchored to the WDK's numeric value
so the model cannot simply repeat an incorrect implementation constant.

### Recorded validation (2026-09-26)

The WHP Release build passed. Independent verification passed all 10 positive
fixtures, 17 expected-failure fixtures, and nine host models. Every runner exited
zero; all 27 guest manifests matched the current fixture hashes with no timeouts
or stderr output. The executable hash was unchanged from start to finish:
`DDB2BBDE1307BCA525991E5ABB90EFD3F6B17469C0BAEF4350BAF9ECFA58DE9F`.

Local evidence is indexed by `build-conformance/registry-final-manifest-audit.json`,
with commands in `build-conformance/registry-final-report.txt`. The WDK guest
fixture exposed an incorrect bypass constant during development; the corrected
value, `0xC0000503`, is checked independently by both guest and host tests.

Independent review found no material introduced defects. Allocation-failure
injection and multiprocessor guest interleavings remain unverified. These results
cover the stated emulator contract, not full Windows registry conformance.

## Sources

- [Layered registry filtering](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/supporting-layered-registry-filtering-drivers)
- [Handling notifications](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/handling-notifications)
- [Per-operation context](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/specifying-context-information)
- [Post-operation information](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_reg_post_operation_information)
- [Callback execution contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nc-wdm-ex_callback_function)
- [Callback removal](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-cmunregistercallback)
- [Microsoft layered and nested-call sample](https://github.com/microsoft/Windows-driver-samples/blob/main/general/registry/regfltr/sys/multialt.c)
